package members

import (
	"testing"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

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

// newSharedVault creates a vault in a fresh folder opened by owner, with
// the given extra unlockers, and returns the folder and vault key.
func newSharedVault(t testing.TB, owner *person, extra ...crypto.KeyWrapper) (string, *crypto.VaultKey) {
	t.Helper()
	dir := t.TempDir() + "/vault"
	key, err := crypto.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	vf, err := crypto.NewVaultFile("shared", key, append([]crypto.KeyWrapper{owner.wrapper(t)}, extra...))
	if err != nil {
		t.Fatal(err)
	}
	if err := format.CreateVault(dir, vf); err != nil {
		t.Fatal(err)
	}
	// What `vault init --shared` does: record the creator as owner.
	if err := upsertMeta(dir, metaEntry{Name: owner.pub.Name, Recipient: owner.pub.Recipient, Role: RoleOwner, Added: vf.Unlockers[0].Created}); err != nil {
		t.Fatal(err)
	}
	return dir, key
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
