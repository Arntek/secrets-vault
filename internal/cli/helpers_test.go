package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Arntek/secrets-vault/internal/agent"
	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/touchid"
)

const testPass = "test passphrase one"

// TestMain lets the test binary double as the unlock agent: the CLI starts
// "itself __agent", which here is this test binary.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == agent.AgentArg {
		if err := agent.Run(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	code := m.Run()
	if oldMainDir != "" {
		_ = os.RemoveAll(oldMainDir) // the format-2 build, see buildOldMain
	}
	os.Exit(code)
}

// --- fakes ---

type fakeTerm struct {
	stdinTTY, stdoutTTY bool
	passwords           [][]byte
	asked               int
}

func (f *fakeTerm) StdinTTY() bool  { return f.stdinTTY }
func (f *fakeTerm) StdoutTTY() bool { return f.stdoutTTY }
func (f *fakeTerm) ReadPassword() ([]byte, error) {
	if len(f.passwords) == 0 {
		return nil, errors.New("test: no scripted password left")
	}
	p := f.passwords[0]
	f.passwords = f.passwords[1:]
	f.asked++
	return p, nil
}
func (f *fakeTerm) queue(p ...string) {
	for _, s := range p {
		f.passwords = append(f.passwords, []byte(s))
	}
}

type fakeTouch struct {
	avail   bool
	cancel  bool
	unwraps int
}

func (f *fakeTouch) backend() touchBackend {
	return touchBackend{
		available: func() bool { return f.avail },
		enroll: func(label, path string) (*touchid.Device, error) {
			if !f.avail {
				return nil, touchid.ErrUnsupported
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return nil, err
			}
			fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return nil, touchid.ErrEnrolled
			}
			defer fh.Close()
			_, _ = fh.Write([]byte("fake-enclave-" + label + "-" + time.Now().String()))
			return &touchid.Device{Label: label, KeyPath: path}, nil
		},
		wrapper: func(d *touchid.Device, vault string) (crypto.KeyWrapper, error) {
			blob, err := os.ReadFile(d.KeyPath)
			if err != nil {
				return nil, err
			}
			sum := sha256.Sum256(blob)
			inner, err := crypto.NewPassphraseWrapperWithWorkFactor(sum[:], crypto.MinScryptWorkFactor)
			if err != nil {
				return nil, err
			}
			return &fakeWrapper{f: f, inner: inner, label: d.Label, rec: "touchid-p256:" + base64.RawStdEncoding.EncodeToString(sum[:])}, nil
		},
	}
}

// fakeWrapper is a software "Secure Enclave": a touchid-typed unlocker
// wrapped under a key derived from the fake device file.
type fakeWrapper struct {
	f     *fakeTouch
	inner crypto.KeyWrapper
	label string
	rec   string
}

func (w *fakeWrapper) Type() format.UnlockerType { return format.UnlockerTouchID }
func (w *fakeWrapper) Wrap(k *crypto.VaultKey) (format.Unlocker, error) {
	u, err := w.inner.Wrap(k)
	if err != nil {
		return u, err
	}
	u.Type, u.Label, u.Recipient = format.UnlockerTouchID, w.label, w.rec
	return u, nil
}
func (w *fakeWrapper) Unwrap(u format.Unlocker) (*crypto.VaultKey, error) {
	if u.Type != format.UnlockerTouchID || u.Recipient != w.rec {
		return nil, crypto.ErrWrongKey
	}
	w.f.unwraps++
	if w.f.cancel {
		return nil, touchid.ErrCancelled
	}
	u.Type, u.Label, u.Recipient = format.UnlockerPassphrase, "", ""
	return w.inner.Unwrap(u)
}

// fakeDialog stands in for the macOS password dialog: no test may open a
// real one. It hands out scripted answers; with none left it behaves like
// Cancel.
type fakeDialog struct {
	answers []string
	msgs    []string
}

func (d *fakeDialog) run(msg string) ([]byte, error) {
	d.msgs = append(d.msgs, msg)
	if len(d.answers) == 0 {
		return nil, errDialogCancelled
	}
	a := d.answers[0]
	d.answers = d.answers[1:]
	return []byte(a), nil
}

type fakeClip struct {
	value     []byte
	scheduled []time.Duration
	digests   [][32]byte
	failWrite bool
}

func (c *fakeClip) Write(v []byte) error {
	if c.failWrite {
		return errors.New("clipboard unavailable")
	}
	c.value = append([]byte(nil), v...)
	return nil
}
func (c *fakeClip) Read() ([]byte, error) { return append([]byte(nil), c.value...), nil }
func (c *fakeClip) ScheduleClear(d [32]byte, delay time.Duration) error {
	c.digests = append(c.digests, d)
	c.scheduled = append(c.scheduled, delay)
	return nil
}

// --- environment ---

type testEnv struct {
	t        *testing.T
	home     string
	cfg      string
	agentDir string
	term     *fakeTerm
	touch    *fakeTouch
	clip     *fakeClip
	dialog   *fakeDialog
	environ  []string
	path     string
	exe      string
}

var curEnv *testEnv

// newEnv builds an isolated user: own HOME, registry, agent and fakes.
func newEnv(t *testing.T) *testEnv {
	t.Helper()
	skipWindows(t)
	return newEnvAt(t, t.TempDir())
}

// newEnvNoAgent is newEnv for a system with no unlock agent (what Windows
// is): dialing the agent reports ErrUnsupported. It runs on every OS, so
// the Windows flow (a passphrase prompt per command) is tested everywhere.
func newEnvNoAgent(t *testing.T) *testEnv {
	t.Helper()
	e := newEnvAt(t, t.TempDir())
	prev := testHook
	testHook = func(a *app) {
		prev(a)
		a.dialAgent = func(bool) (agent.Client, error) { return nil, agent.ErrUnsupported }
	}
	t.Cleanup(func() { testHook = prev })
	return e
}

// newEnvAt is newEnv with a chosen HOME (the leak harness scans its own).
func newEnvAt(t *testing.T, home string) *testEnv {
	t.Helper()
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	// /tmp keeps the agent's socket path short enough on macOS and Linux.
	adBase := "/tmp"
	if runtime.GOOS == "windows" {
		adBase = ""
	}
	ad, err := os.MkdirTemp(adBase, "svt")
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{
		t: t, home: home, cfg: filepath.Join(home, "config", "config.toml"), agentDir: ad,
		term: &fakeTerm{}, touch: &fakeTouch{}, clip: &fakeClip{}, dialog: &fakeDialog{},
		environ: []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "SV_UNRELATED=visible"},
	}
	e.exe = filepath.Join(home, "bin", "secrets-vault")
	_ = os.MkdirAll(filepath.Dir(e.exe), 0o755)
	_ = os.WriteFile(e.exe, []byte("#!/bin/sh\n"), 0o755)
	oldLogN := passphraseLogN
	passphraseLogN = crypto.MinScryptWorkFactor
	prevHook := testHook
	testHook = func(a *app) {
		c := curEnv
		a.term = c.term
		a.touch = c.touch.backend()
		a.clip = c.clip
		a.dialog = c.dialog.run
		a.goos = "darwin"
		a.caller = func() (string, int) { return "testprog", 4242 }
		a.environ = func() []string { return c.environ }
		a.exePath = func() (string, error) { return c.exe, nil }
		if c.path != "" {
			prev := a.getenv
			a.getenv = func(k string) string {
				if k == "PATH" {
					return c.path
				}
				return prev(k)
			}
		}
	}
	t.Cleanup(func() {
		if cl, err := agent.DialWith(agent.DialOptions{Dir: ad, NoAutoStart: true}); err == nil {
			_ = agent.Stop(cl)
		}
		_ = os.RemoveAll(ad)
		passphraseLogN = oldLogN
		testHook = prevHook
		curEnv = nil
	})
	e.activate()
	return e
}

func (e *testEnv) activate() {
	curEnv = e
	e.t.Setenv("HOME", e.home)
	e.t.Setenv("USERPROFILE", e.home)
	e.t.Setenv("XDG_CONFIG_HOME", filepath.Join(e.home, "xdg"))
	e.t.Setenv(EnvConfig, e.cfg)
	e.t.Setenv("SECRETS_VAULT_AGENT_DIR", e.agentDir)
}

type result struct {
	code int
	out  string
	err  string
}

func (r result) String() string {
	return "exit " + itoa(r.code) + "\nstdout: " + r.out + "\nstderr: " + r.err
}

// run executes one command as program "sv" with empty stdin.
func (e *testEnv) run(args ...string) result { return e.runIn("", args...) }

func (e *testEnv) runIn(stdin string, args ...string) result {
	e.t.Helper()
	var out, errb bytes.Buffer
	code := e.runTo(&out, &errb, stdin, args...)
	return result{code, out.String(), errb.String()}
}

func (e *testEnv) runTo(out, errb io.Writer, stdin string, args ...string) int {
	e.t.Helper()
	e.activate()
	return Run(append([]string{"sv"}, args...), strings.NewReader(stdin), out, errb)
}

func (e *testEnv) mustRun(args ...string) result {
	e.t.Helper()
	r := e.run(args...)
	if r.code != 0 {
		e.t.Fatalf("%v: %s", args, r)
	}
	return r
}

func (e *testEnv) mustRunIn(stdin string, args ...string) result {
	e.t.Helper()
	r := e.runIn(stdin, args...)
	if r.code != 0 {
		e.t.Fatalf("%v: %s", args, r)
	}
	return r
}

// testUser is the identity name every test environment uses.
const testUser = "tester"

// initVault creates a vault with the test passphrase (non-interactive).
// The first vault also creates this user's identity, with the same
// passphrase; stdin carries it twice either way: identity (created or
// unlocked), then the vault's recovery passphrase.
func (e *testEnv) initVault(name string) string {
	e.t.Helper()
	dir := filepath.Join(e.home, "vaults", name)
	e.mustRunIn(testPass+"\n"+testPass+"\n", "init", name, "--path", dir, "--passphrase-stdin", "--as", testUser)
	return dir
}

func (e *testEnv) unlock(name string) {
	e.t.Helper()
	e.mustRunIn(testPass+"\n", "unlock", name, "--passphrase-stdin")
}

func (e *testEnv) set(name, vault, value string) {
	e.t.Helper()
	args := []string{"set", name, "--desc", "test key " + strings.ToLower(name)}
	if vault != "" {
		args = append(args, "--vault", vault)
	}
	e.mustRunIn(value, args...)
}

func expectCode(t *testing.T, r result, want int) {
	t.Helper()
	if r.code != want {
		t.Fatalf("want exit %d, got:\n%s", want, r)
	}
}

func notContains(t *testing.T, what string, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if n != "" && strings.Contains(haystack, n) {
			t.Fatalf("%s contains a value that must not appear", what)
		}
	}
}

func decodeJSON[T any](t *testing.T, s string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("bad JSON %q: %v", s, err)
	}
	return v
}
