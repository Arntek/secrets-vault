package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

func TestIdentityCreateUnlock(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "cfg", "vault", "identity"))
	if s.Exists() {
		t.Fatal("exists before create")
	}
	if _, err := s.Public(); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("Public before create: %v", err)
	}
	pub, err := s.Create("alice", pass(t, "alice pass"))
	if err != nil {
		t.Fatal(err)
	}
	if pub.Name != "alice" || !strings.HasPrefix(pub.Recipient, "age1") || !fpRe.MatchString(pub.Fingerprint) {
		t.Fatalf("bad public identity %+v", pub)
	}
	if _, err := s.Create("alice", pass(t, "x")); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("second create: %v", err)
	}
	if got, err := s.Public(); err != nil || got != pub {
		t.Fatalf("Public = %+v, %v", got, err)
	}
	u, err := s.Unlock(pass(t, "alice pass"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Identity != pub {
		t.Fatal("unlocked identity differs")
	}
	if _, err := s.Unlock(pass(t, "wrong")); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	for _, f := range []string{u.String(), u.GoString()} {
		if strings.Contains(f, "AGE-SECRET") || strings.Contains(f, pub.Recipient) {
			t.Fatal("Unlocked printed key material")
		}
	}
	u.Destroy()
	if _, err := u.MemberWrapper(); err == nil {
		t.Fatal("destroyed identity still usable")
	}
}

func TestIdentityNeedsUnlockerAndValidName(t *testing.T) {
	s := NewStore(t.TempDir() + "/c")
	if _, err := s.Create("alice"); err == nil {
		t.Fatal("created an identity with no unlocker")
	}
	for _, bad := range []string{"", "Alice", "a b", "../x", "-x", strings.Repeat("a", 65)} {
		if _, err := s.Create(bad, pass(t, "p")); !errors.Is(err, ErrInvalidName) {
			t.Errorf("name %q: %v", bad, err)
		}
	}
	if s.Exists() {
		t.Fatal("failed creates left a file")
	}
}

func TestIdentityPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits")
	}
	dir := filepath.Join(t.TempDir(), "id")
	s := NewStore(dir)
	if _, err := s.Create("alice", pass(t, "p")); err != nil {
		t.Fatal(err)
	}
	di, _ := os.Stat(dir)
	fi, _ := os.Stat(filepath.Join(dir, identityFileName))
	if di.Mode().Perm() != 0o700 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("modes dir %v file %v", di.Mode().Perm(), fi.Mode().Perm())
	}
	if err := os.Chmod(filepath.Join(dir, identityFileName), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock(pass(t, "p")); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("0644 file: %v", err)
	}
	_ = os.Chmod(filepath.Join(dir, identityFileName), 0o600)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Public(); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("0755 dir: %v", err)
	}
}

func TestDefaultDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/cfg")
	if d, _ := DefaultDir(); d != filepath.Join("/cfg", "vault", "identity") {
		t.Fatal(d)
	}
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/x")
	if d, _ := DefaultDir(); d != filepath.Join("/home/x", ".config", "vault", "identity") {
		t.Fatal(d)
	}
}

// Tampering with the stored file must never reveal or accept a different
// identity.
func TestIdentityTamper(t *testing.T) {
	a := newPerson(t, "alice")
	b := newPerson(t, "bob")
	path := a.store.path()
	orig, _ := os.ReadFile(path)

	var f map[string]any
	_ = json.Unmarshal(orig, &f)

	// Swap in bob's public key (valid, canonical) while keeping alice's sealed key.
	f["recipient"] = b.pub.Recipient
	swapped, _ := json.Marshal(f)
	mustWrite(t, path, swapped)
	if _, err := a.store.Unlock(pass(t, a.pw)); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("swapped recipient accepted: %v", err)
	}

	// Truncated, trailing data, duplicate keys, unknown field, bad version.
	for name, bad := range map[string][]byte{
		"truncated": orig[:len(orig)/2],
		"trailing":  append(bytes.Clone(orig), []byte(`{}`)...),
		"duplicate": bytes.Replace(orig, []byte(`"version": 1,`), []byte(`"version": 1, "version": 1,`), 1),
		"unknown":   bytes.Replace(orig, []byte(`"version": 1,`), []byte(`"version": 1, "extra": 1,`), 1),
		"version":   bytes.Replace(orig, []byte(`"version": 1,`), []byte(`"version": 2,`), 1),
		"empty":     {},
	} {
		mustWrite(t, path, bad)
		if _, err := a.store.Unlock(pass(t, a.pw)); err == nil {
			t.Errorf("%s: tampered file accepted", name)
		}
	}

	// Flip a byte of the sealed key.
	var g identityFile
	_ = json.Unmarshal(orig, &g)
	g.Sealed[len(g.Sealed)/2] ^= 0x01
	flipped, _ := json.Marshal(g)
	mustWrite(t, path, flipped)
	if _, err := a.store.Unlock(pass(t, a.pw)); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("flipped sealed key: %v", err)
	}

	// Oversize.
	mustWrite(t, path, bytes.Repeat([]byte(" "), maxIdentityFile+1))
	if _, err := a.store.Public(); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize: %v", err)
	}

	// Symlinked identity file refused.
	_ = os.Remove(path)
	target := filepath.Join(t.TempDir(), "elsewhere")
	mustWrite(t, target, orig)
	if err := os.Symlink(target, path); err == nil {
		if _, err := a.store.Public(); err == nil {
			t.Fatal("symlinked identity accepted")
		}
	}
}

func mustWrite(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityAddUnlockerAndChangePassphrase(t *testing.T) {
	s := NewStore(t.TempDir() + "/c")
	pub, err := s.Create("alice", pass(t, "old"))
	if err != nil {
		t.Fatal(err)
	}
	// Rejects a wrong current unlocker.
	if err := s.AddUnlocker(pass(t, "nope"), pass(t, "new")); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("wrong current: %v", err)
	}
	// A stand-in for Touch ID: a second, differently-typed wrapper.
	tid := fakeTouchID{pass(t, "device secret")}
	if err := s.AddUnlocker(pass(t, "old"), tid); err != nil {
		t.Fatal(err)
	}
	if u, err := s.Unlock(tid); err != nil || u.Identity != pub {
		t.Fatalf("unlock with added unlocker: %v", err)
	}
	// Change the passphrase: new works, old no longer does, Touch ID still does.
	if err := s.AddUnlocker(pass(t, "old"), pass(t, "new")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock(pass(t, "new")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unlock(pass(t, "old")); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("old passphrase still works: %v", err)
	}
	if _, err := s.Unlock(tid); err != nil {
		t.Fatal(err)
	}
	// Member-type wrapper refused.
	mw, _ := crypto.NewMemberWrapper("x", pub.Recipient)
	if err := s.AddUnlocker(pass(t, "new"), mw); err == nil {
		t.Fatal("member wrapper accepted as identity unlocker")
	}
}

// fakeTouchID is a passphrase wrapper that claims to be a Touch ID one.
type fakeTouchID struct{ crypto.KeyWrapper }

func (fakeTouchID) Type() format.UnlockerType { return format.UnlockerTouchID }
func (f fakeTouchID) Wrap(k *crypto.VaultKey) (format.Unlocker, error) {
	u, err := f.KeyWrapper.Wrap(k)
	u.Type, u.Label = format.UnlockerTouchID, "test-mac"
	return u, err
}
func (f fakeTouchID) Unwrap(u format.Unlocker) (*crypto.VaultKey, error) {
	u.Type = format.UnlockerPassphrase
	return f.KeyWrapper.Unwrap(u)
}

func TestIdentityExportImport(t *testing.T) {
	a := newPerson(t, "alice")
	data, err := a.store.Export(pass(t, a.pw), pass(t, "transfer phrase"))
	if err != nil {
		t.Fatal(err)
	}
	// The export is protected by the transfer passphrase only.
	if err := ParseIdentityFile(data); err != nil {
		t.Fatal(err)
	}

	second := NewStore(filepath.Join(t.TempDir(), "mac2"))
	if _, err := second.Import(data, pass(t, "wrong"), pass(t, "mac2 pass")); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("wrong transfer passphrase: %v", err)
	}
	if second.Exists() {
		t.Fatal("failed import left an identity")
	}
	got, err := second.Import(data, pass(t, "transfer phrase"), pass(t, "mac2 pass"))
	if err != nil {
		t.Fatal(err)
	}
	if got != a.pub {
		t.Fatalf("imported %+v, want %+v", got, a.pub)
	}
	// The imported identity opens what the original opens, under the new passphrase only.
	u2, err := second.Unlock(pass(t, "mac2 pass"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Unlock(pass(t, "transfer phrase")); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatal("transfer passphrase unlocks the imported store")
	}
	w2, _ := u2.MemberWrapper()
	dir, key := newSharedVault(t, a)
	vf, _ := format.ReadVaultFile(dir)
	k2, err := crypto.Unlock(vf, w2)
	if err != nil || !bytes.Equal(k2.Bytes(), key.Bytes()) {
		t.Fatalf("imported identity cannot open the vault: %v", err)
	}
	// Import refuses to overwrite.
	if _, err := second.Import(data, pass(t, "transfer phrase"), pass(t, "x")); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("overwrite: %v", err)
	}
	// A stored identity file is not an export, and an export is not a stored identity.
	stored, _ := os.ReadFile(a.store.path())
	if _, err := NewStore(t.TempDir()+"/m3").Import(stored, pass(t, a.pw), pass(t, "x")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("stored file imported as export: %v", err)
	}
	third := NewStore(t.TempDir() + "/m4")
	mustMkdir(t, third.dir)
	mustWrite(t, third.path(), data)
	if _, err := third.Public(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("export used as stored identity: %v", err)
	}
	// A tampered export is rejected.
	var ef identityFile
	_ = json.Unmarshal(data, &ef)
	ef.Sealed[len(ef.Sealed)-1] ^= 1
	bad, _ := json.Marshal(ef)
	if _, err := NewStore(t.TempDir()+"/m5").Import(bad, pass(t, "transfer phrase"), pass(t, "x")); !errors.Is(err, crypto.ErrWrongKey) {
		t.Fatalf("tampered export: %v", err)
	}
}

func mustMkdir(t testing.TB, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

func FuzzParseIdentityFile(f *testing.F) {
	s := NewStore(f.TempDir() + "/c")
	if _, err := s.Create("alice", pass(f, "p")); err != nil {
		f.Fatal(err)
	}
	valid, _ := os.ReadFile(s.path())
	exp, _ := s.Export(pass(f, "p"), pass(f, "q"))
	f.Add(valid)
	f.Add(exp)
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		err := ParseIdentityFile(data)
		if err != nil && len(data) > 12 && bytes.Contains([]byte(err.Error()), data) {
			t.Fatal("error echoes input")
		}
	})
}
