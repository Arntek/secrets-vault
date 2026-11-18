package members

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

var t0 = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

// pass returns a cheap passphrase wrapper for tests.
func pass(t testing.TB, p string) crypto.KeyWrapper {
	t.Helper()
	w, err := crypto.NewPassphraseWrapperWithWorkFactor([]byte(p), crypto.MinScryptWorkFactor)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// person is a test user with their own identity store.
type person struct {
	store *Store
	pub   Identity
	un    *Unlocked
	pw    string
}

func newPerson(t testing.TB, name string) *person {
	t.Helper()
	p := &person{store: NewStore(t.TempDir() + "/" + name + "-config"), pw: name + " personal passphrase"}
	pub, err := p.store.Create(name, pass(t, p.pw))
	if err != nil {
		t.Fatal(err)
	}
	p.pub = pub
	p.un, err = p.store.Unlock(pass(t, p.pw))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *person) wrapper(t testing.TB) crypto.KeyWrapper {
	t.Helper()
	w, err := p.un.MemberWrapper()
	if err != nil {
		t.Fatal(err)
	}
	return w
}

const vaultPass = "vault recovery passphrase"

// testVault is a vault folder plus its current verified chain and key.
type testVault struct {
	dir string
	c   *Chain
	key *crypto.VaultKey
}

// newVault creates a vault owned by owner, with the recovery passphrase.
func newVault(t testing.TB, owner *person) *testVault {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	key, err := crypto.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewVault(dir, "team", key, owner.un, pass(t, vaultPass), t0)
	if err != nil {
		t.Fatal(err)
	}
	return &testVault{dir: dir, c: c, key: key}
}

// join files p's request and has approver approve it with the right
// fingerprint.
func (v *testVault) join(t testing.TB, approver, p *person) {
	t.Helper()
	if err := WriteRequest(v.dir, p.un, t0); err != nil {
		t.Fatal(err)
	}
	c, _, err := ApproveRequest(v.dir, v.c, v.key, approver.un, p.pub.Name, p.pub.Fingerprint, false, t0)
	if err != nil {
		t.Fatal(err)
	}
	v.c = c
}

// remove has signer remove name (passphrase dropped) and switches to the
// new key.
func (v *testVault) remove(t testing.TB, signer *person, name string) *RotateResult {
	t.Helper()
	res, err := Remove(v.dir, v.c, v.key, signer.un, name, RotateOptions{Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	v.c, v.key = res.Chain, res.NewKey
	return res
}

// openAs unlocks the vault in dir as p and returns the vault key.
func openAs(t testing.TB, dir string, p *person) (*crypto.VaultKey, error) {
	t.Helper()
	vf, err := format.ReadVaultFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	return crypto.Unlock(vf, p.wrapper(t))
}

func putSecret(t testing.TB, dir string, key *crypto.VaultKey, name, value string) {
	t.Helper()
	if err := crypto.WriteSecret(dir, name, key, []byte(value)); err != nil {
		t.Fatal(err)
	}
}

func mustReadFile(t testing.TB, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustWriteFile(t testing.TB, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// copyDir copies a vault folder (files only, recursively).
func copyDir(t testing.TB, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// pinOf returns the pin a machine would hold after verifying c, having
// written own itself.
func pinOf(c *Chain, own ...format.LogEntry) *Pin { return PinFor(c, own) }
