// Package leaktest is the reusable leak-test harness required by the design's
// Security testing section: code under test runs with known canary secret
// values, and the test fails if any canary shows up in stdout, stderr, logs,
// temp files or files written under the test's HOME.
//
// Typical in-process use:
//
//	leaktest.RunFunc(t, func(h *leaktest.Harness) {
//		secret := h.Canary()
//		code := cli.Run(args, strings.NewReader(secret), h.Stdout, h.Stderr)
//		...
//	})
//
// Out-of-process use (a built binary):
//
//	h := leaktest.New(t)
//	cmd := h.Command(binPath, "set", "API_KEY")
//	cmd.Stdin = strings.NewReader(h.Canary())
//	_ = cmd.Run()
//	h.Check()
//
// New points HOME, TMPDIR and XDG_* at fresh test directories (with
// t.Setenv, so tests using it cannot call t.Parallel), so anything the code
// writes to disk lands where Check scans it. Each canary is also searched
// for in its hex and base64 encodings, which catches the common way of
// "accidentally" leaking a secret by encoding it.
//
// Findings name where a canary was found, never the canary itself.
package leaktest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// CanaryPrefix starts every string canary, so a leak is easy to spot by eye
// and gitleaks-style tools never mistake it for a real credential format.
const CanaryPrefix = "SVCANARY_"

// maxScanFile bounds how much of one file is scanned.
const maxScanFile = 64 << 20

// Harness collects every place a secret could leak to during one test.
type Harness struct {
	t testing.TB

	// Stdout and Stderr are passed to the code under test (or filled by
	// Command) in place of the real streams.
	Stdout *bytes.Buffer
	Stderr *bytes.Buffer
	// Logs receives everything written through Logger.
	Logs   *bytes.Buffer
	Logger *slog.Logger

	// HomeDir and TempDir are set as HOME and TMPDIR for the test.
	HomeDir string
	TempDir string

	dirs     []string
	canaries [][]byte
}

// New creates a harness and redirects HOME, TMPDIR and XDG directories to
// fresh per-test directories.
func New(t testing.TB) *Harness {
	t.Helper()
	root := t.TempDir()
	h := &Harness{
		t:       t,
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
		Logs:    &bytes.Buffer{},
		HomeDir: filepath.Join(root, "home"),
		TempDir: filepath.Join(root, "tmp"),
	}
	h.Logger = slog.New(slog.NewJSONHandler(h.Logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	for _, d := range []string{h.HomeDir, h.TempDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("leaktest: %v", err)
		}
	}
	h.dirs = []string{h.HomeDir, h.TempDir}
	t.Setenv("HOME", h.HomeDir)
	t.Setenv("TMPDIR", h.TempDir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(h.HomeDir, ".config"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(h.HomeDir, ".local", "state"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(h.HomeDir, ".cache"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(h.TempDir, "run"))
	return h
}

// RunFunc creates a harness, runs fn, then fails t if any canary leaked.
func RunFunc(t testing.TB, fn func(h *Harness)) {
	t.Helper()
	h := New(t)
	fn(h)
	h.Check()
}

// Canary returns a new random string canary and registers it.
func (h *Harness) Canary() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		h.t.Fatalf("leaktest: %v", err)
	}
	c := CanaryPrefix + strings.ToUpper(hex.EncodeToString(b))
	h.AddCanary([]byte(c))
	return c
}

// CanaryBytes returns n random bytes and registers them as a canary, for
// binary secrets such as keys. n must be at least 8 to avoid false matches.
func (h *Harness) CanaryBytes(n int) []byte {
	if n < 8 {
		h.t.Fatalf("leaktest: canary of %d bytes is too short", n)
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		h.t.Fatalf("leaktest: %v", err)
	}
	h.AddCanary(b)
	return b
}

// AddCanary registers an existing value as a canary.
func (h *Harness) AddCanary(b []byte) {
	h.canaries = append(h.canaries, bytes.Clone(b))
}

// WatchDir adds a directory (for example a test vault folder or config dir
// outside HOME) whose files Check scans.
// Directories inside one already scanned (such as t.TempDir(), which lives
// under the redirected TMPDIR) are not added twice.
func (h *Harness) WatchDir(dir string) {
	for _, d := range h.dirs {
		if rel, err := filepath.Rel(d, dir); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return
		}
	}
	h.dirs = append(h.dirs, dir)
}

// Command returns an exec.Cmd whose stdout and stderr are captured into the
// harness and whose environment uses the harness HOME and TMPDIR. The
// caller sets Stdin and runs it, then calls Check.
func (h *Harness) Command(name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(context.Background(), name, args...) // #nosec G204 -- test helper runs binaries chosen by the test
	cmd.Stdout = h.Stdout
	cmd.Stderr = h.Stderr
	cmd.Env = os.Environ() // already redirected by New via t.Setenv
	return cmd
}

// Finding is one place a canary was found.
type Finding struct {
	Source   string // "stdout", "stderr", "logs" or "file <path>"
	Encoding string // "raw", "hex", "HEX", "base64", ...
	Canary   int    // index of the canary, in registration order
}

func (f Finding) String() string {
	return fmt.Sprintf("canary #%d found in %s (%s encoding)", f.Canary, f.Source, f.Encoding)
}

// Findings scans every source and returns where canaries were found.
func (h *Harness) Findings() []Finding {
	var out []Finding
	out = append(out, scan("stdout", h.Stdout.Bytes(), h.canaries)...)
	out = append(out, scan("stderr", h.Stderr.Bytes(), h.canaries)...)
	out = append(out, scan("logs", h.Logs.Bytes(), h.canaries)...)
	for _, dir := range h.dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() {
				return nil
			}
			data, err := readCapped(path)
			if err != nil {
				return err
			}
			rel, relErr := filepath.Rel(dir, path)
			if relErr != nil {
				rel = path
			}
			out = append(out, scan("file "+filepath.Join(filepath.Base(dir), rel), data, h.canaries)...)
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			h.t.Errorf("leaktest: scanning %s: %v", dir, err)
		}
	}
	return out
}

// Check fails the test once for every finding.
func (h *Harness) Check() {
	h.t.Helper()
	if len(h.canaries) == 0 {
		h.t.Errorf("leaktest: no canaries registered; the test checks nothing")
		return
	}
	for _, f := range h.Findings() {
		h.t.Errorf("leaktest: secret leaked: %s", f)
	}
}

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- walking the test's own directories
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxScanFile))
}

// encodings are the forms each canary is searched for in.
var encodings = []struct {
	name string
	enc  func([]byte) string
}{
	{"raw", func(b []byte) string { return string(b) }},
	{"hex", hex.EncodeToString},
	{"HEX", func(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }},
	{"base64", base64.StdEncoding.EncodeToString},
	{"base64-raw", base64.RawStdEncoding.EncodeToString},
	{"base64url", base64.URLEncoding.EncodeToString},
	{"base64url-raw", base64.RawURLEncoding.EncodeToString},
}

func scan(source string, data []byte, canaries [][]byte) []Finding {
	var out []Finding
	for i, c := range canaries {
		for _, e := range encodings {
			needle := e.enc(c)
			if needle == "" {
				continue
			}
			if bytes.Contains(data, []byte(needle)) {
				out = append(out, Finding{Source: source, Encoding: e.name, Canary: i})
				break // one finding per canary per source is enough
			}
		}
	}
	return out
}
