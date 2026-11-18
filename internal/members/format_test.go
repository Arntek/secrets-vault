package members

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// newLegacyVault makes a format-2 vault (the format v0.1.0 ships) owned by
// owner, for the upgrade tests.
func newLegacyVault(t testing.TB, owner *person) *testVault {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	key, err := crypto.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	mw, err := owner.un.MemberWrapper()
	if err != nil {
		t.Fatal(err)
	}
	vf, err := crypto.NewVaultFile("team", key, []crypto.KeyWrapper{mw, pass(t, vaultPass)})
	if err != nil {
		t.Fatal(err)
	}
	if err := GenesisFormat(vf, owner.un, t0, format.LegacyVaultVersion); err != nil {
		t.Fatal(err)
	}
	if err := format.CreateVault(dir, vf); err != nil {
		t.Fatal(err)
	}
	c, _, err := Load(dir, vf.ID)
	if err != nil {
		t.Fatal(err)
	}
	return &testVault{dir: dir, c: c, key: key}
}

func TestNewVaultIsFormat3(t *testing.T) {
	v := newVault(t, newPerson(t, "alice"))
	if v.c.Head().Format != format.VaultVersion || v.c.File.Version != format.VaultVersion || v.c.Records[0].Format != format.VaultVersion {
		t.Fatalf("format %d, version %d", v.c.Head().Format, v.c.File.Version)
	}
}

func TestUpgradeFormat(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	v := newLegacyVault(t, alice)
	if v.c.Head().Format != 2 || v.c.File.Version != 2 {
		t.Fatalf("legacy vault: format %d version %d", v.c.Head().Format, v.c.File.Version)
	}
	// Only a member can sign it.
	if _, err := v.c.UpgradeFormat(bob.un, t0); !errors.Is(err, ErrNotMember) {
		t.Fatalf("a non-member upgraded the vault: %v", err)
	}
	next, err := v.c.UpgradeFormat(alice.un, t0)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := WriteUpgrade(v.dir, v.c, next)
	if err != nil {
		t.Fatal(err)
	}
	h := nc.Head()
	if h.Format != 3 || nc.File.Version != 3 || h.Op != format.OpUpgradeFormat || h.Seq != 1 || h.KeyID != v.c.Head().KeyID {
		t.Fatalf("head after upgrade: %+v (version %d)", h, nc.File.Version)
	}
	// It is part of the signed log: it can't be done twice.
	if _, err := nc.UpgradeFormat(alice.un, t0); err == nil {
		t.Fatal("upgraded a format-3 vault again")
	}
	if _, err := nc.Append(alice.un, Change{Op: format.OpUpgradeFormat, Format: 3, KeyID: nc.File.KeyID, Unlockers: nc.File.Unlockers, Time: t0}); !errors.Is(err, ErrNotAuthorised) {
		t.Fatalf("a second upgrade-format record = %v", err)
	}
	// Later changes keep the format.
	v.c = nc
	v.join(t, alice, bob)
	if v.c.Head().Format != 3 || v.c.File.Version != 3 {
		t.Fatalf("after a later change: %d %d", v.c.Head().Format, v.c.File.Version)
	}
}

// A vault.json whose version disagrees with the signed history is refused:
// no downgrade, and no upgrade nobody signed.
func TestVerifyRefusesFormatMismatch(t *testing.T) {
	alice := newPerson(t, "alice")
	v := newLegacyVault(t, alice)
	legacy := *v.c.File
	// A format-2 history presented as version 3.
	up := legacy
	up.Version = 3
	if _, err := Verify(&up, nil, legacy.ID); !errors.Is(err, ErrTampered) {
		t.Fatalf("version 3 over a format-2 chain = %v", err)
	}
	next, _ := v.c.UpgradeFormat(alice.un, t0)
	nc, err := WriteUpgrade(v.dir, v.c, next)
	if err != nil {
		t.Fatal(err)
	}
	// A format-3 history presented as version 2 (a downgrade by a folder
	// writer, with or without dropping the record).
	down := *nc.File
	down.Version = 2
	if _, err := Verify(&down, nil, down.ID); !errors.Is(err, ErrTampered) {
		t.Fatalf("version 2 over a format-3 chain = %v", err)
	}
	// And a genesis-3 vault (new vaults) the same way.
	fresh := newVault(t, newPerson(t, "carol"))
	d := *fresh.c.File
	d.Version = 2
	if _, err := Verify(&d, nil, d.ID); !errors.Is(err, ErrTampered) {
		t.Fatalf("version 2 over a genesis-3 chain = %v", err)
	}
}

func TestFormat2VaultStillVerifies(t *testing.T) {
	alice := newPerson(t, "alice")
	v := newLegacyVault(t, alice)
	// Version 2 vaults read as before; a rotation keeps them format 2.
	if _, err := Verify(v.c.File, v.c.Raw, v.c.File.ID); err != nil {
		t.Fatal(err)
	}
}

// ue1.15: nothing a folder writer can put in secrets/ blocks member rm.
func TestRemoveSkipsUnopenableFiles(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	v := newVault(t, alice)
	v.join(t, alice, bob)
	putSecret(t, v.dir, v.key, "REAL", "value")
	real := mustReadFile(t, filepath.Join(v.dir, "secrets", "REAL.age"))
	mustWriteFile(t, filepath.Join(v.dir, "secrets", "RENAMED_COPY.age"), real) // current key, wrong name
	mustWriteFile(t, filepath.Join(v.dir, "secrets", "TRUNCATED.age"), real[:len(real)/2])
	mustWriteFile(t, filepath.Join(v.dir, "secrets", "GARBAGE.age"), []byte("junk"))
	var skipped []string
	res, err := Remove(v.dir, v.c, v.key, alice.un, "bob", RotateOptions{Now: t0, SkippedFiles: &skipped})
	if err != nil {
		t.Fatalf("member rm blocked: %v", err)
	}
	if len(skipped) != 3 {
		t.Fatalf("skipped = %v", skipped)
	}
	if got, err := crypto.ReadSecret(v.dir, "REAL", res.NewKey); err != nil || string(got) != "value" {
		t.Fatalf("REAL after the removal: %q %v", got, err)
	}
	if _, ok := res.Chain.Head().Member("bob"); ok {
		t.Fatal("bob is still a member")
	}
}
