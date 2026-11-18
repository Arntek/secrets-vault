package touchid

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/leaktest"
)

// fakeEnclave is a software stand-in for the Swift bridge. Its "blob" is a
// marker plus the raw private key, so tests can run anywhere.
type fakeEnclave struct {
	checkErr  error
	createErr error
	pubErr    error
	agreeErr  error
	parent    string

	agreeCalls int
	lastReason string
}

var fakeMarker = []byte("FAKE-SE-v1:")

func (f *fakeEnclave) check() error { return f.checkErr }

func (f *fakeEnclave) create() ([]byte, []byte, error) {
	if f.createErr != nil {
		return nil, nil, f.createErr
	}
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return append(append([]byte{}, fakeMarker...), k.Bytes()...), k.PublicKey().Bytes(), nil
}

func (f *fakeEnclave) key(blob []byte) (*ecdh.PrivateKey, error) {
	if !bytes.HasPrefix(blob, fakeMarker) {
		return nil, errBadKey
	}
	k, err := ecdh.P256().NewPrivateKey(blob[len(fakeMarker):])
	if err != nil {
		return nil, errBadKey
	}
	return k, nil
}

func (f *fakeEnclave) publicKey(blob []byte) ([]byte, error) {
	if f.pubErr != nil {
		return nil, f.pubErr
	}
	k, err := f.key(blob)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

func (f *fakeEnclave) agree(blob, peer []byte, reason string) ([]byte, error) {
	f.agreeCalls++
	f.lastReason = reason
	if f.agreeErr != nil {
		return nil, f.agreeErr
	}
	k, err := f.key(blob)
	if err != nil {
		return nil, err
	}
	p, err := ecdh.P256().NewPublicKey(peer)
	if err != nil {
		return nil, errBadKey
	}
	return k.ECDH(p)
}

func (f *fakeEnclave) parentProgram() string { return f.parent }

func noEnv(string) string { return "" }

func sshEnv(k string) string {
	if k == "SSH_CONNECTION" {
		return "192.0.2.1 50000 192.0.2.2 22"
	}
	return ""
}

// setup enrolls a fake device in a temp dir and returns its wrapper.
func setup(t *testing.T, f *fakeEnclave, vault string) (*keyWrapper, *Device) {
	t.Helper()
	d, err := enrollWith(f, noEnv, "Test Mac", filepath.Join(t.TempDir(), "keys", "touchid.blob"))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	w, err := wrapperWith(f, noEnv, d, vault)
	if err != nil {
		t.Fatalf("wrapper: %v", err)
	}
	return w.(*keyWrapper), d
}

func newKey(t *testing.T) *crypto.VaultKey {
	t.Helper()
	k, err := crypto.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTrip(t *testing.T) {
	f := &fakeEnclave{parent: "zsh"}
	w, _ := setup(t, f, "test-vault")
	key := newKey(t)

	u, err := w.Wrap(key)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if f.agreeCalls != 0 {
		t.Fatal("Wrap must not need Touch ID")
	}
	if w.Type() != format.UnlockerTouchID || u.Type != format.UnlockerTouchID {
		t.Fatalf("type = %q / %q", w.Type(), u.Type)
	}
	if u.Label != "Test Mac" || !strings.HasPrefix(u.Recipient, recipientPrefix) || u.Created.IsZero() {
		t.Fatalf("unexpected unlocker fields: label=%q recipient=%q", u.Label, u.Recipient)
	}
	if len(u.WrappedKey) != wrappedLen {
		t.Fatalf("wrapped length %d, want %d", len(u.WrappedKey), wrappedLen)
	}
	if bytes.Contains(u.WrappedKey, key.Bytes()) {
		t.Fatal("wrapped key contains the plaintext key")
	}

	got, err := w.Unwrap(u)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	defer got.Destroy()
	if !bytes.Equal(got.Bytes(), key.Bytes()) {
		t.Fatal("unwrapped key differs")
	}
	if f.agreeCalls != 1 {
		t.Fatalf("agree called %d times, want 1", f.agreeCalls)
	}
	if want := "unlock the \u201ctest-vault\u201d vault for zsh"; f.lastReason != want {
		t.Fatalf("reason = %q, want %q", f.lastReason, want)
	}

	// Two wraps of the same key differ (fresh ephemeral key and nonce).
	u2, err := w.Wrap(key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(u.WrappedKey, u2.WrappedKey) {
		t.Fatal("wrapping is deterministic")
	}
}

func TestWrapNilKey(t *testing.T) {
	w, _ := setup(t, &fakeEnclave{}, "v")
	if _, err := w.Wrap(nil); err == nil {
		t.Fatal("Wrap(nil) succeeded")
	}
}

func TestUnwrapErrorMapping(t *testing.T) {
	cases := []struct {
		name     string
		agreeErr error
		want     error
	}{
		{"cancel", ErrCancelled, ErrCancelled},
		{"no biometry now", ErrUnsupported, ErrUnsupported},
		{"wrong finger / fingerprints changed", errAuthFailed, crypto.ErrWrongKey},
		{"bad blob", errBadKey, crypto.ErrWrongKey},
		{"other", errors.New("boom"), crypto.ErrWrongKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeEnclave{}
			w, _ := setup(t, f, "v")
			u, err := w.Wrap(newKey(t))
			if err != nil {
				t.Fatal(err)
			}
			f.agreeErr = tc.agreeErr
			k, err := w.Unwrap(u)
			if k != nil || err != tc.want {
				t.Fatalf("Unwrap = %v, %v; want nil, %v", k, err, tc.want)
			}
		})
	}
}

func TestStatusError(t *testing.T) {
	want := map[int]error{
		statusOK:         nil,
		statusNoEnclave:  ErrUnsupported,
		statusNoBiometry: ErrUnsupported,
		statusCancelled:  ErrCancelled,
		statusAuthFailed: errAuthFailed,
		statusBadKey:     errBadKey,
	}
	for code, w := range want {
		if got := statusError(code); got != w {
			t.Errorf("statusError(%d) = %v, want %v", code, got, w)
		}
	}
	for _, code := range []int{6, 7, -1, 99} {
		err := statusError(code)
		if err == nil || errors.Is(err, ErrCancelled) || errors.Is(err, ErrUnsupported) {
			t.Errorf("statusError(%d) = %v, want a generic failure", code, err)
		}
	}
}

func TestTamperedUnlockers(t *testing.T) {
	f := &fakeEnclave{}
	w, _ := setup(t, f, "v")
	u, err := w.Wrap(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, m format.Unlocker) {
		t.Helper()
		k, err := w.Unwrap(m)
		if k != nil || err != crypto.ErrWrongKey {
			t.Errorf("%s: Unwrap = %v, %v; want ErrWrongKey", name, k, err)
		}
	}
	// Every single-bit flip anywhere in the wrapped key is rejected.
	for i := range u.WrappedKey {
		m := u
		m.WrappedKey = bytes.Clone(u.WrappedKey)
		m.WrappedKey[i] ^= 0x01
		check("flip", m)
	}
	m := u
	m.WrappedKey = u.WrappedKey[:len(u.WrappedKey)-1]
	check("truncated", m)
	m.WrappedKey = append(bytes.Clone(u.WrappedKey), 0)
	check("extended", m)
	m.WrappedKey = nil
	check("empty", m)
	m = u
	m.Type = format.UnlockerPassphrase
	check("wrong type", m)

	// A recipient that isn't this Mac's key is rejected before Touch ID.
	before := f.agreeCalls
	m = u
	m.Recipient = recipientPrefix + "AAAA"
	check("other recipient", m)
	if f.agreeCalls != before {
		t.Error("Touch ID was requested for another device's unlocker")
	}
}

func TestOtherDevice(t *testing.T) {
	f := &fakeEnclave{}
	w1, _ := setup(t, f, "v")
	w2, _ := setup(t, f, "v")
	u, err := w1.Wrap(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if k, err := w2.Unwrap(u); k != nil || err != crypto.ErrWrongKey {
		t.Fatalf("other device Unwrap = %v, %v", k, err)
	}
	// Even if the recipient is forged to match, the ECDH secret differs.
	u.Recipient = w2.recipient()
	if k, err := w2.Unwrap(u); k != nil || err != crypto.ErrWrongKey {
		t.Fatalf("forged recipient Unwrap = %v, %v", k, err)
	}
}

func TestSSHSession(t *testing.T) {
	f := &fakeEnclave{}
	if err := availableWith(f, sshEnv); err != ErrUnsupported {
		t.Fatalf("availableWith(ssh) = %v", err)
	}
	for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		env := func(k string) string {
			if k == v {
				return "x"
			}
			return ""
		}
		if !sshSession(env) {
			t.Errorf("%s not detected", v)
		}
	}
	if sshSession(noEnv) {
		t.Error("ssh detected with empty environment")
	}
	if _, err := enrollWith(f, sshEnv, "m", filepath.Join(t.TempDir(), "k")); err != ErrUnsupported {
		t.Fatalf("enroll over ssh = %v", err)
	}

	w, _ := setup(t, f, "v")
	u, err := w.Wrap(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	w.getenv = sshEnv
	if k, err := w.Unwrap(u); k != nil || err != ErrUnsupported {
		t.Fatalf("unwrap over ssh = %v, %v", k, err)
	}
	if f.agreeCalls != 0 {
		t.Fatal("Touch ID requested over SSH")
	}
}

func TestAvailability(t *testing.T) {
	if err := availableWith(nil, noEnv); err != ErrUnsupported {
		t.Fatalf("nil enclave: %v", err)
	}
	if err := availableWith(&fakeEnclave{}, noEnv); err != nil {
		t.Fatalf("usable enclave: %v", err)
	}
	if err := availableWith(&fakeEnclave{checkErr: errors.New("no sensor")}, noEnv); err != ErrUnsupported {
		t.Fatalf("no biometrics: %v", err)
	}
}

// The public API must return ErrUnsupported when the bridge isn't built in
// (every non-darwin, CGO_ENABLED=0 or untagged build).
func TestPublicAPIWithoutBridge(t *testing.T) {
	if platform != nil {
		t.Skip("Secure Enclave bridge compiled in")
	}
	if Available() {
		t.Fatal("Available() = true without the bridge")
	}
	if _, err := Enroll("m", filepath.Join(t.TempDir(), "k")); err != ErrUnsupported {
		t.Fatalf("Enroll = %v", err)
	}
	if _, err := Wrapper(&Device{KeyPath: "x"}); err != ErrUnsupported {
		t.Fatalf("Wrapper = %v", err)
	}
	if _, err := WrapperForVault(&Device{KeyPath: "x"}, "v"); err != ErrUnsupported {
		t.Fatalf("WrapperForVault = %v", err)
	}
}

func TestEnrollFile(t *testing.T) {
	f := &fakeEnclave{}
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "touchid.blob")
	d, err := enrollWith(f, noEnv, "Test Mac", path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Label != "Test Mac" || d.KeyPath != path {
		t.Fatalf("device = %+v", d)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no Unix permission bits to check.
	if runtime.GOOS != "windows" {
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("key file mode %v, want 0600", fi.Mode().Perm())
		}
		if di.Mode().Perm() != 0o700 {
			t.Errorf("key folder mode %v, want 0700", di.Mode().Perm())
		}
	}
	orig, _ := os.ReadFile(path)

	// Never overwrite an existing key: that would orphan every vault
	// enrolled with it.
	if _, err := enrollWith(f, noEnv, "Test Mac", path); err != ErrEnrolled {
		t.Fatalf("second enroll = %v, want ErrEnrolled", err)
	}
	now, _ := os.ReadFile(path)
	if !bytes.Equal(orig, now) {
		t.Fatal("existing key file was changed")
	}

	if _, err := enrollWith(f, noEnv, "m", ""); err == nil {
		t.Fatal("empty key path accepted")
	}

	bad := filepath.Join(dir, "fail.blob")
	if _, err := enrollWith(&fakeEnclave{createErr: errors.New("boom")}, noEnv, "m", bad); err == nil {
		t.Fatal("create failure not reported")
	}
	if _, err := os.Stat(bad); !os.IsNotExist(err) {
		t.Fatal("key file written after create failure")
	}
	if _, err := enrollWith(&fakeEnclave{createErr: ErrUnsupported}, noEnv, "m", bad); err != ErrUnsupported {
		t.Fatalf("create unsupported = %v", err)
	}
}

func TestWrapperKeyFileProblems(t *testing.T) {
	dir := t.TempDir()
	f := &fakeEnclave{}
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := map[string]string{
		"missing":   filepath.Join(dir, "nope"),
		"empty":     write("empty", nil),
		"oversized": write("big", make([]byte, maxBlobSize+1)),
		"garbage":   write("garbage", []byte("not a key")),
		"directory": dir,
	}
	for name, p := range cases {
		_, err := wrapperWith(f, noEnv, &Device{KeyPath: p}, "v")
		if err == nil {
			t.Errorf("%s: wrapper accepted a bad key file", name)
			continue
		}
		if strings.Contains(err.Error(), dir) {
			t.Errorf("%s: error echoes the key path: %v", name, err)
		}
	}
	if _, err := wrapperWith(f, noEnv, nil, "v"); err == nil {
		t.Error("nil device accepted")
	}
	if _, err := wrapperWith(nil, noEnv, &Device{KeyPath: "x"}, "v"); err != ErrUnsupported {
		t.Errorf("nil enclave = %v", err)
	}

	// Enclave refuses the blob (e.g. copied from another Mac).
	_, d := setup(t, f, "v")
	if _, err := wrapperWith(&fakeEnclave{pubErr: errBadKey}, noEnv, d, "v"); err == nil {
		t.Error("unusable blob accepted")
	}
	if _, err := wrapperWith(&fakeEnclave{pubErr: ErrUnsupported}, noEnv, d, "v"); err != ErrUnsupported {
		t.Errorf("enclave gone = %v", err)
	}
}

func TestUnlockReason(t *testing.T) {
	cases := []struct{ vault, prog, want string }{
		{"personal", "zsh", "unlock the \u201cpersonal\u201d vault for zsh"},
		{"", "zsh", "unlock a vault for zsh"},
		{"work", "", "unlock the \u201cwork\u201d vault"},
		{"", "", "unlock a vault"},
		// Newlines, control and bidi characters can't add fake lines or
		// reorder the text on the sheet.
		{"a\nb\tc\x00d", "evil\u202eexe", "unlock the \u201ca b cd\u201d vault for evilexe"},
	}
	for _, tc := range cases {
		if got := unlockReason(tc.vault, tc.prog); got != tc.want {
			t.Errorf("unlockReason(%q, %q) = %q, want %q", tc.vault, tc.prog, got, tc.want)
		}
	}
	long := strings.Repeat("x", 200)
	got := unlockReason(long, long)
	if n := len([]rune(got)); n > 2*maxReasonPart+40 {
		t.Errorf("reason not bounded: %d runes", n)
	}
}

// The vault key must never show up in output, errors or files, even when
// unwrapping fails.
func TestNoKeyLeak(t *testing.T) {
	leaktest.RunFunc(t, func(h *leaktest.Harness) {
		raw := h.CanaryBytes(crypto.KeySize)
		key, err := crypto.VaultKeyFromBytes(raw)
		if err != nil {
			t.Fatal(err)
		}
		f := &fakeEnclave{}
		d, err := enrollWith(f, noEnv, "Test Mac", filepath.Join(os.Getenv("HOME"), "touchid.blob"))
		if err != nil {
			t.Fatal(err)
		}
		kw, err := wrapperWith(f, noEnv, d, "v")
		if err != nil {
			t.Fatal(err)
		}
		u, err := kw.Wrap(key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := kw.Unwrap(u)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = h.Stdout.Write([]byte(got.String() + "\n"))
		got.Destroy()
		for _, e := range []error{ErrCancelled, errAuthFailed, errBadKey} {
			f.agreeErr = e
			if _, err := kw.Unwrap(u); err != nil {
				_, _ = h.Stderr.Write([]byte(err.Error() + "\n"))
			}
		}
		u.WrappedKey[len(u.WrappedKey)-1] ^= 1
		f.agreeErr = nil
		if _, err := kw.Unwrap(u); err != nil {
			_, _ = h.Stderr.Write([]byte(err.Error() + "\n"))
		}
	})
}

// FuzzUnwrap feeds arbitrary wrapped-key bytes to the parser and Unwrap.
// Nothing but the genuine wrapped key may unwrap, and nothing may panic.
func FuzzUnwrap(f *testing.F) {
	fe := &fakeEnclave{}
	d, err := enrollWith(fe, noEnv, "m", filepath.Join(f.TempDir(), "k"))
	if err != nil {
		f.Fatal(err)
	}
	kw, err := wrapperWith(fe, noEnv, d, "v")
	if err != nil {
		f.Fatal(err)
	}
	k, err := crypto.NewVaultKey()
	if err != nil {
		f.Fatal(err)
	}
	u, err := kw.Wrap(k)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(u.WrappedKey)
	f.Add([]byte{})
	f.Add([]byte{wrapVersion})
	f.Add(make([]byte, wrappedLen))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _, perr := parseWrapped(b)
		m := u
		m.WrappedKey = b
		got, err := kw.Unwrap(m)
		if bytes.Equal(b, u.WrappedKey) {
			if err != nil {
				t.Fatalf("genuine key failed: %v", err)
			}
			return
		}
		if err == nil {
			// A different encoding of the same ciphertext must not exist.
			got.Destroy()
			t.Fatal("forged wrapped key unwrapped")
		}
		if err != crypto.ErrWrongKey {
			t.Fatalf("Unwrap error = %v, want ErrWrongKey", err)
		}
		if perr == nil && len(b) != wrappedLen {
			t.Fatal("parser accepted a wrong length")
		}
	})
}
