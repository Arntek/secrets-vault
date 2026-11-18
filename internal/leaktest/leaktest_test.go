package leaktest

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// recorder wraps a real *testing.T but captures failures so the harness's
// own failure paths can be tested.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func (r *recorder) Helper() {}

func TestCleanCodePasses(t *testing.T) {
	RunFunc(t, func(h *Harness) {
		_ = h.Canary()
		fmt.Fprintln(h.Stdout, "ok")
		h.Logger.Info("did a thing", "key", "API_KEY")
	})
}

func TestDetectsEachSource(t *testing.T) {
	cases := map[string]func(h *Harness, c string){
		"stdout": func(h *Harness, c string) { fmt.Fprint(h.Stdout, "value="+c) },
		"stderr": func(h *Harness, c string) { fmt.Fprint(h.Stderr, "error: "+c) },
		"logs":   func(h *Harness, c string) { h.Logger.Error("failed", "v", c) },
		"file tmp": func(h *Harness, c string) {
			f, err := os.CreateTemp("", "debug-*.txt") // TMPDIR is redirected
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			fmt.Fprint(f, c)
		},
		"file home": func(h *Harness, c string) {
			p := filepath.Join(h.HomeDir, ".config", "vault", "audit.log")
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"file watched": func(h *Harness, c string) {
			dir := t.TempDir()
			h.WatchDir(dir)
			if err := os.WriteFile(filepath.Join(dir, "x"), []byte(c), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, leak := range cases {
		t.Run(name, func(t *testing.T) {
			r := &recorder{TB: t}
			h := New(r)
			leak(h, h.Canary())
			h.Check()
			if len(r.errs) != 1 {
				t.Fatalf("want exactly 1 leak finding for %s, got %d: %v", name, len(r.errs), r.errs)
			}
			if !strings.Contains(r.errs[0], strings.Fields(name)[0]) {
				t.Fatalf("finding does not name source %q: %s", name, r.errs[0])
			}
		})
	}
}

func TestDetectsEncodings(t *testing.T) {
	encs := map[string]func([]byte) string{
		"hex":       hex.EncodeToString,
		"HEX":       func(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) },
		"base64":    base64.StdEncoding.EncodeToString,
		"base64url": base64.RawURLEncoding.EncodeToString,
	}
	for name, enc := range encs {
		t.Run(name, func(t *testing.T) {
			r := &recorder{TB: t}
			h := New(r)
			key := h.CanaryBytes(32)
			fmt.Fprint(h.Stdout, "debug key: "+enc(key))
			h.Check()
			if len(r.errs) != 1 {
				t.Fatalf("encoded leak not detected: %v", r.errs)
			}
		})
	}
}

func TestFindingNeverContainsCanary(t *testing.T) {
	r := &recorder{TB: t}
	h := New(r)
	c := h.Canary()
	fmt.Fprint(h.Stderr, c)
	h.Check()
	for _, e := range r.errs {
		if strings.Contains(e, c) {
			t.Fatal("failure message repeats the canary")
		}
	}
}

func TestNoCanariesFails(t *testing.T) {
	r := &recorder{TB: t}
	h := New(r)
	h.Check()
	if len(r.errs) != 1 {
		t.Fatal("a harness with no canaries must fail: it checks nothing")
	}
}

func TestCommandCapturesSubprocess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	r := &recorder{TB: t}
	h := New(r)
	c := h.Canary()
	cmd := h.Command("sh", "-c", `read v; echo "$v" >&2; echo "$v" > "$TMPDIR/leak"`)
	cmd.Stdin = strings.NewReader(c + "\n")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	h.Check()
	if len(r.errs) != 2 { // stderr + temp file
		t.Fatalf("want 2 findings (stderr, temp file), got %v", r.errs)
	}
}
