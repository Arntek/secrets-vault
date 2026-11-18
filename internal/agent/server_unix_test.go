//go:build unix

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/leaktest"
)

// TestMain lets the test binary double as the agent process, to test
// auto-start without building the real CLI.
func TestMain(m *testing.M) {
	if os.Getenv("SV_AGENT_TEST_CHILD") == "1" {
		if err := Run(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// shortDir returns a private directory with a short path (unix socket paths
// are limited to ~104 bytes, and t.TempDir is too long on macOS).
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "sva")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return filepath.Join(d, "d")
}

type rig struct {
	dir  string
	clk  *fakeClock
	srv  *server
	cl   Client
	done chan error
}

func startRig(t *testing.T, mod func(*ServerOptions)) *rig {
	t.Helper()
	r := &rig{dir: shortDir(t), clk: newFakeClock(), done: make(chan error, 1)}
	opts := ServerOptions{Dir: r.dir, Now: r.clk.Now, ReapInterval: time.Hour} // ticks are driven by tests
	if mod != nil {
		mod(&opts)
	}
	srv, err := newServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	r.srv = srv
	ctx, cancel := context.WithCancel(context.Background())
	go func() { r.done <- srv.serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})
	cl, err := DialWith(DialOptions{Dir: r.dir, NoAutoStart: true})
	if err != nil {
		t.Fatal(err)
	}
	r.cl = cl
	return r
}

func TestUnlockKeyRoundTrip(t *testing.T) {
	r := startRig(t, nil)
	k := newKey(t)
	want := bytes.Clone(k.Bytes())
	if err := r.cl.Unlock("v1", k, DefaultTTL); err != nil {
		t.Fatal(err)
	}
	if !allZero(k.Bytes()) {
		t.Error("client kept the key it handed over")
	}
	got, err := r.cl.Key("v1")
	if err != nil {
		t.Fatal(err)
	}
	defer got.Destroy()
	if !bytes.Equal(got.Bytes(), want) {
		t.Error("key changed in transit")
	}
	if _, err := r.cl.Key("other"); !errors.Is(err, ErrLocked) {
		t.Errorf("unknown vault: %v, want ErrLocked", err)
	}
}

func TestTTLExpiryThroughAgent(t *testing.T) {
	r := startRig(t, nil)
	_ = r.cl.Unlock("v1", newKey(t), time.Hour)
	r.clk.Advance(time.Hour - time.Second)
	if k, err := r.cl.Key("v1"); err != nil {
		t.Fatalf("before expiry: %v", err)
	} else {
		k.Destroy()
	}
	r.clk.Advance(time.Second)
	if _, err := r.cl.Key("v1"); !errors.Is(err, ErrLocked) {
		t.Fatalf("at expiry: %v, want ErrLocked", err)
	}
	st, _ := r.cl.Status()
	if len(st) != 0 {
		t.Errorf("expired vault still in status: %+v", st)
	}
}

func TestTTLRangeEnforced(t *testing.T) {
	r := startRig(t, nil)
	for _, d := range []time.Duration{0, MinTTL - time.Second, MaxTTL + time.Second, -time.Hour} {
		if err := r.cl.Unlock("v", newKey(t), d); err == nil {
			t.Errorf("client accepted ttl %s", d)
		}
	}
	// The server enforces it too, even for a client that skips the check.
	body := mustEncode(t, OpUnlock, "v", time.Second, testKeyBytes())
	st := rawExchange(t, r.dir, body)
	if st[0] != statusBadTTL {
		t.Errorf("server status = %d, want bad ttl", st[0])
	}
	if got, _ := r.cl.Status(); len(got) != 0 {
		t.Error("out-of-range unlock stored a key")
	}
}

func TestLockAndLockAll(t *testing.T) {
	r := startRig(t, nil)
	for _, v := range []string{"a", "b", "c"} {
		_ = r.cl.Unlock(v, newKey(t), time.Hour)
	}
	if err := r.cl.Lock("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.cl.Key("a"); !errors.Is(err, ErrLocked) {
		t.Errorf("a still unlocked: %v", err)
	}
	if k, err := r.cl.Key("b"); err != nil {
		t.Errorf("b affected by locking a: %v", err)
	} else {
		k.Destroy()
	}
	if err := r.cl.Lock("never-unlocked"); err != nil {
		t.Errorf("locking an unknown vault: %v", err)
	}
	if err := r.cl.LockAll(); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"b", "c"} {
		if _, err := r.cl.Key(v); !errors.Is(err, ErrLocked) {
			t.Errorf("%s survived LockAll: %v", v, err)
		}
	}
}

func TestStatusListsVaultsNotKeys(t *testing.T) {
	r := startRig(t, nil)
	k := newKey(t)
	secret := bytes.Clone(k.Bytes())
	_ = r.cl.Unlock("b", k, 2*time.Hour)
	_ = r.cl.Unlock("a", newKey(t), time.Hour)
	st, err := r.cl.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st) != 2 || st[0].VaultID != "a" || st[1].VaultID != "b" {
		t.Fatalf("status = %+v", st)
	}
	if want := r.clk.Now().Add(2 * time.Hour); st[1].ExpiresAt.UnixMilli() != want.UnixMilli() || !st[1].Unlocked {
		t.Errorf("expiry = %v, want %v", st[1].ExpiresAt, want)
	}
	// The raw response must not contain the key either.
	raw := rawExchange(t, r.dir, mustEncode(t, OpStatus, "", 0, nil))
	if bytes.Contains(raw, secret) {
		t.Error("status response contains key bytes")
	}
}

func TestSocketAndDirPermissions(t *testing.T) {
	r := startRig(t, nil)
	di, err := os.Stat(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %o, want 700", di.Mode().Perm())
	}
	si, err := os.Lstat(filepath.Join(r.dir, sockName))
	if err != nil {
		t.Fatal(err)
	}
	if si.Mode().Perm() != 0o600 || si.Mode()&os.ModeSocket == 0 {
		t.Errorf("socket mode %v, want socket 0600", si.Mode())
	}
}

func TestRefusesUnsafeDir(t *testing.T) {
	loose := shortDir(t)
	if err := os.MkdirAll(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newServer(ServerOptions{Dir: loose}); !errors.Is(err, ErrUnsafeDir) {
		t.Errorf("0755 dir: %v, want ErrUnsafeDir", err)
	}
	if _, err := DialWith(DialOptions{Dir: loose, NoAutoStart: true}); !errors.Is(err, ErrUnsafeDir) {
		t.Errorf("client with 0755 dir: %v", err)
	}
	// Group-only and other-only bits are both refused.
	for _, mode := range []os.FileMode{0o750, 0o710, 0o701, 0o770} {
		_ = os.Chmod(loose, mode)
		if _, err := newServer(ServerOptions{Dir: loose}); !errors.Is(err, ErrUnsafeDir) {
			t.Errorf("mode %o accepted", mode)
		}
	}
	// A symlink in place of the directory is refused.
	base := filepath.Dir(loose)
	real := filepath.Join(base, "real")
	_ = os.Mkdir(real, 0o700)
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := newServer(ServerOptions{Dir: link}); !errors.Is(err, ErrUnsafeDir) {
		t.Errorf("symlinked dir: %v", err)
	}
	// Relative paths are refused.
	if _, err := newServer(ServerOptions{Dir: "relative/dir"}); !errors.Is(err, ErrUnsafeDir) {
		t.Errorf("relative dir: %v", err)
	}
}

func TestDirOwnerCheck(t *testing.T) {
	d := shortDir(t)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkDir(d, os.Geteuid()); err != nil {
		t.Errorf("own dir rejected: %v", err)
	}
	if err := checkDir(d, os.Geteuid()+1); !errors.Is(err, ErrUnsafeDir) {
		t.Errorf("dir owned by another uid accepted: %v", err)
	}
}

func TestPeerAuthorization(t *testing.T) {
	me := os.Geteuid()
	if err := authorize(me, nil, me); err != nil {
		t.Errorf("same uid rejected: %v", err)
	}
	if err := authorize(me+1, nil, me); !errors.Is(err, ErrWrongUser) {
		t.Errorf("other uid accepted: %v", err)
	}
	if err := authorize(me, errNoPeerCred, me); !errors.Is(err, ErrWrongUser) {
		t.Errorf("credential read failure must fail closed: %v", err)
	}
	if err := authorize(0, nil, me); me != 0 && !errors.Is(err, ErrWrongUser) {
		t.Errorf("root peer accepted for a non-root agent: %v", err)
	}
}

func TestRealPeerUIDMatches(t *testing.T) {
	r := startRig(t, nil)
	c, err := net.Dial("unix", filepath.Join(r.dir, sockName))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uid, err := peerUID(c)
	if err != nil || uid != os.Geteuid() {
		t.Fatalf("peerUID = %d, %v; want %d", uid, err, os.Geteuid())
	}
	if err := checkPeer(c); err != nil {
		t.Fatal(err)
	}
}

func TestOtherUIDConnectionRejected(t *testing.T) {
	r := startRig(t, nil)
	// Simulate a connection from another user by making the peer check
	// report one; the server must drop it without serving anything.
	r.srv.setPeerCheck(func(c net.Conn) error { return authorize(os.Geteuid()+1, nil, os.Geteuid()) })
	_ = r.cl.Unlock("v", newKey(t), time.Hour) // fails: connection dropped
	r.srv.setPeerCheck(checkPeer)
	if st, _ := r.cl.Status(); len(st) != 0 {
		t.Error("request from rejected peer was served")
	}
	r.srv.setPeerCheck(func(net.Conn) error { return ErrWrongUser })
	c, err := net.Dial("unix", filepath.Join(r.dir, sockName))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = WriteFrame(c, mustEncode(t, OpStatus, "", 0, nil))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if b, err := io.ReadAll(c); len(b) != 0 {
		t.Errorf("rejected peer got %d response bytes (err %v)", len(b), err)
	}
}

// rawExchange sends one frame and returns the response body.
func rawExchange(t *testing.T, dir string, body []byte) []byte {
	t.Helper()
	c, err := net.Dial("unix", filepath.Join(dir, sockName))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := WriteFrame(c, body); err != nil {
		t.Fatal(err)
	}
	resp, err := ReadFrame(c, MaxResponseSize)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestOversizeAndGarbageRejected(t *testing.T) {
	r := startRig(t, nil)
	cases := map[string][]byte{
		"oversize declared": binary.BigEndian.AppendUint32(nil, MaxRequestSize+1),
		"huge declared":     {0xff, 0xff, 0xff, 0xff},
		"zero length":       {0, 0, 0, 0},
		"garbage body":      append(binary.BigEndian.AppendUint32(nil, 12), bytes.Repeat([]byte{0xa5}, 12)...),
		"unknown op":        append(binary.BigEndian.AppendUint32(nil, 13), 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
	}
	for name, raw := range cases {
		c, err := net.Dial("unix", filepath.Join(r.dir, sockName))
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write(raw)
		resp, err := ReadFrame(c, MaxResponseSize)
		if err != nil || len(resp) != 1 || resp[0] != statusBadRequest {
			t.Errorf("%s: resp=%v err=%v, want bad-request", name, resp, err)
		}
		if _, err := ReadFrame(c, MaxResponseSize); err == nil {
			t.Errorf("%s: connection left open after bad message", name)
		}
		_ = c.Close()
	}
	// The agent is still healthy afterwards.
	if _, err := r.cl.Status(); err != nil {
		t.Fatalf("agent unhealthy after garbage: %v", err)
	}
}

func TestIdleExit(t *testing.T) {
	r := startRig(t, func(o *ServerOptions) { o.IdleExit = 3 * time.Minute })
	_ = r.cl.Unlock("v", newKey(t), MinTTL)
	r.clk.Advance(2 * time.Minute)
	r.srv.tick()
	select {
	case <-r.srv.stop:
		t.Fatal("exited while holding a key")
	default:
	}
	r.clk.Advance(4 * time.Minute) // key expired at 5m; reaped here
	r.srv.tick()
	select {
	case <-r.srv.stop:
		t.Fatal("exited the instant the last key expired")
	default:
	}
	r.clk.Advance(3 * time.Minute)
	r.srv.tick()
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not exit after being empty for IdleExit")
	}
	if _, err := os.Lstat(filepath.Join(r.dir, sockName)); !os.IsNotExist(err) {
		t.Errorf("socket left behind: %v", err)
	}
	r.done <- nil // let cleanup's receive succeed
}

func TestStopLocksAllAndExits(t *testing.T) {
	r := startRig(t, nil)
	k := newKey(t)
	_ = r.cl.Unlock("v", k, time.Hour)
	held, _ := r.srv.store.get("v")
	defer held.Destroy()
	if err := Stop(r.cl); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-r.done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not exit after shutdown")
	}
	r.done <- nil
	if _, err := DialWith(DialOptions{Dir: r.dir, NoAutoStart: true}); err == nil {
		t.Error("agent still answering after shutdown")
	}
	if st := r.srv.store.status(); len(st) != 0 {
		t.Error("keys survived shutdown")
	}
}

func TestSecondAgentRefused(t *testing.T) {
	r := startRig(t, nil)
	if _, err := newServer(ServerOptions{Dir: r.dir}); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second server: %v, want ErrAlreadyRunning", err)
	}
	if _, err := r.cl.Status(); err != nil {
		t.Fatalf("first agent damaged by second start: %v", err)
	}
}

func TestStaleSocketReplaced(t *testing.T) {
	dir := shortDir(t)
	if err := prepareDir(dir); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, sockName))
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close() // dead agent leaves its socket file behind
	srv, err := newServer(ServerOptions{Dir: dir})
	if err != nil {
		t.Fatalf("stale socket blocked startup: %v", err)
	}
	_ = srv.ln.Close()
}

func TestNonSocketAtSocketPathRefused(t *testing.T) {
	dir := shortDir(t)
	if err := prepareDir(dir); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, sockName)
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newServer(ServerOptions{Dir: dir}); err == nil {
		t.Fatal("regular file at socket path was replaced")
	}
	if _, err := os.Stat(p); err != nil {
		t.Error("file was deleted")
	}
}

func TestAutoStartSpawnsAgent(t *testing.T) {
	dir := shortDir(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	opts := DialOptions{
		Dir: dir, Exe: exe, Args: []string{"-test.run=^$"},
		Env:          append(os.Environ(), "SV_AGENT_TEST_CHILD=1", envDir+"="+dir),
		StartTimeout: 10 * time.Second,
	}
	cl, err := DialWith(opts)
	if err != nil {
		t.Fatalf("auto-start: %v", err)
	}
	t.Cleanup(func() { _ = Stop(cl) })
	if err := cl.Unlock("v", newKey(t), time.Hour); err != nil {
		t.Fatal(err)
	}
	// A second Dial finds the running agent and does not start another.
	cl2, err := DialWith(opts)
	if err != nil {
		t.Fatal(err)
	}
	k, err := cl2.Key("v")
	if err != nil {
		t.Fatalf("second client lost the key: %v", err)
	}
	k.Destroy()
	if err := Stop(cl); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Lstat(filepath.Join(dir, sockName)); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent process did not remove its socket")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNoAutoStart(t *testing.T) {
	if _, err := DialWith(DialOptions{Dir: shortDir(t), NoAutoStart: true}); err == nil {
		t.Fatal("DialWith started or found an agent that is not there")
	}
}

func TestDefaultDirChoices(t *testing.T) {
	t.Setenv(envDir, "")
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1234")
	d, err := DefaultDir()
	if err != nil || !filepath.IsAbs(d) {
		t.Fatalf("DefaultDir = %q, %v", d, err)
	}
	t.Setenv(envDir, "/custom")
	if d, _ := DefaultDir(); d != "/custom" {
		t.Errorf("override ignored: %q", d)
	}
}

// TestLeakCanaryKeyNeverEscapes drives the whole agent with a canary key and
// proves the key reaches the agent and back, yet never shows up in logs,
// output, error messages, or any file on disk.
func TestLeakCanaryKeyNeverEscapes(t *testing.T) {
	h := leaktest.New(t)
	dir := shortDir(t)
	h.WatchDir(filepath.Dir(dir))
	canary := h.CanaryBytes(crypto.KeySize)

	clk := newFakeClock()
	logger := slog.New(slog.NewJSONHandler(h.Logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := newServer(ServerOptions{Dir: dir, Now: clk.Now, ReapInterval: time.Hour, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- srv.serve(ctx) }()
	defer cancel()

	cl, err := DialWith(DialOptions{Dir: dir, NoAutoStart: true})
	if err != nil {
		t.Fatal(err)
	}
	record := func(err error) {
		if err != nil {
			h.Stderr.WriteString(err.Error() + "\n")
		}
	}
	key, _ := crypto.VaultKeyFromBytes(canary)
	record(cl.Unlock("vault-one", key, time.Hour))
	got, err := cl.Key("vault-one")
	if err != nil || !bytes.Equal(got.Bytes(), canary) {
		t.Fatalf("canary did not round trip: %v", err)
	}
	h.Stdout.WriteString(got.String() + "\n")
	h.Logger.Info("holding key", "key", got) // redacting LogValue must apply
	fmt.Fprintf(h.Stdout, "%v %+v %#v\n", got, got, got)
	got.Destroy()
	st, err := cl.Status()
	record(err)
	for _, s := range st {
		h.Stdout.WriteString(s.VaultID + " " + s.ExpiresAt.String() + "\n")
	}
	// Error paths: bad ttl, bad id, garbage, locked, expiry.
	k2, _ := crypto.VaultKeyFromBytes(canary)
	record(cl.Unlock("vault-two", k2, time.Second))
	_, err = cl.Key("missing")
	record(err)
	c, derr := net.Dial("unix", filepath.Join(dir, sockName))
	if derr == nil {
		_, _ = c.Write(bytes.Repeat([]byte{0xff}, 64))
		_ = c.Close()
	}
	clk.Advance(2 * time.Hour)
	srv.tick()
	_, err = cl.Key("vault-one")
	record(err)
	record(Stop(cl))
	select {
	case <-done: // agent fully stopped: no more writes to the log buffer
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop")
	}
	h.Check()
}

func TestCrashOnBadChildEnvIsNotSilent(t *testing.T) {
	// A child agent pointed at an unsafe dir must exit non-zero, so the
	// parent's start timeout reports a failure instead of hanging.
	loose := shortDir(t)
	if err := os.MkdirAll(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(loose, 0o755)
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "-test.run=^$") // #nosec G204 -- test re-exec
	cmd.Env = append(os.Environ(), "SV_AGENT_TEST_CHILD=1", envDir+"="+loose)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Run(); err == nil {
		t.Fatal("agent started in an unsafe directory")
	}
}

func TestDefaultDirFallsBackWhenPathTooLong(t *testing.T) {
	long := filepath.Join(t.TempDir(), strings.Repeat("h", 120))
	tmp, err := os.MkdirTemp("/tmp", "svtmp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })
	t.Setenv(envDir, "")
	t.Setenv("HOME", long)
	t.Setenv("XDG_RUNTIME_DIR", long)
	t.Setenv("TMPDIR", tmp)
	got, err := DefaultDir()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "secrets-vault-"+strconv.Itoa(os.Geteuid()))
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// The fallback is a usable, private directory.
	if err := prepareDir(got); err != nil {
		t.Fatalf("fallback dir rejected: %v", err)
	}
}

func TestDefaultDirExplicitOverrideIsNotReplaced(t *testing.T) {
	long := "/tmp/" + strings.Repeat("a", 120)
	t.Setenv(envDir, long)
	got, err := DefaultDir()
	if err != nil || got != long {
		t.Fatalf("got %q, %v", got, err)
	}
	if err := prepareDir(got); !errors.Is(err, ErrPathTooLong) {
		t.Fatalf("want ErrPathTooLong, got %v", err)
	}
}
