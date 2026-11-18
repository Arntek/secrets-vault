package crypto

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/leaktest"
)

type testVault struct {
	dir string
	key *VaultKey
	pw  KeyWrapper
}

func newVault(t *testing.T, wrappers ...KeyWrapper) *testVault {
	t.Helper()
	pw := passWrapper(t, "test passphrase")
	k := mustKey(t)
	vf, err := NewVaultFile("test", k, append([]KeyWrapper{pw}, wrappers...))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "vault")
	if err := format.CreateVault(dir, vf); err != nil {
		t.Fatal(err)
	}
	return &testVault{dir: dir, key: k, pw: pw}
}

func TestNewVaultAndUnlock(t *testing.T) {
	dan := memberIdentity(t)
	danPub, _ := NewMemberWrapper("dan", dan.Recipient().String())
	v := newVault(t, danPub)
	vf, err := format.ReadVaultFile(v.dir)
	if err != nil {
		t.Fatal(err)
	}
	if vf.KeyID != v.key.ID() || len(vf.Unlockers) != 2 {
		t.Fatalf("vault file: %+v", vf)
	}
	k, err := Unlock(vf, v.pw)
	if err != nil || !bytes.Equal(k.Bytes(), v.key.Bytes()) {
		t.Fatalf("passphrase unlock = %v", err)
	}
	danW, _ := NewMemberIdentityWrapper("dan", dan)
	if k, err := Unlock(vf, danW); err != nil || CheckKey(vf, k) != nil {
		t.Fatalf("member unlock = %v", err)
	}
	if _, err := Unlock(vf, passWrapper(t, "nope")); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong passphrase = %v", err)
	}
	if _, err := NewVaultFile("test", v.key, nil); err == nil {
		t.Fatal("vault with no unlockers created")
	}
	if _, err := NewVaultFile("Bad Name", v.key, []KeyWrapper{v.pw}); err == nil {
		t.Fatal("invalid vault name accepted")
	}
}

// Tamper: an unlocker copied in from another vault (that the victim can
// open) unwraps, but to the wrong key, so Unlock refuses it.
func TestUnlockRejectsForeignUnlocker(t *testing.T) {
	a := newVault(t)
	b := newVault(t)
	vfA, _ := format.ReadVaultFile(a.dir)
	vfB, _ := format.ReadVaultFile(b.dir)
	vfA.Unlockers = vfB.Unlockers // same passphrase, other vault's key
	if _, err := Unlock(vfA, a.pw); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("foreign unlocker accepted: %v", err)
	}
}

func TestReadWriteSecret(t *testing.T) {
	v := newVault(t)
	if err := WriteSecret(v.dir, "API_KEY", v.key, []byte("value-1")); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSecret(v.dir, "API_KEY", v.key)
	if err != nil || string(got) != "value-1" {
		t.Fatalf("ReadSecret = %q, %v", got, err)
	}
	if _, err := ReadSecret(v.dir, "MISSING", v.key); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing = %v", err)
	}
	if err := WriteSecret(v.dir, "../X", v.key, nil); !errors.Is(err, format.ErrInvalidKeyName) {
		t.Fatalf("bad name = %v", err)
	}
}

// Tamper: swapping two secret files on disk is detected.
func TestSwappedSecretFiles(t *testing.T) {
	v := newVault(t)
	_ = WriteSecret(v.dir, "A", v.key, []byte("value A"))
	_ = WriteSecret(v.dir, "B", v.key, []byte("value B"))
	pa, _ := format.SecretPath(v.dir, "A")
	pb, _ := format.SecretPath(v.dir, "B")
	tmp := pa + ".swap"
	for _, mv := range [][2]string{{pa, tmp}, {pb, pa}, {tmp, pb}} {
		if err := os.Rename(mv[0], mv[1]); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"A", "B"} {
		if got, err := ReadSecret(v.dir, n, v.key); !errors.Is(err, ErrDecrypt) || got != nil {
			t.Fatalf("swapped %s read: %q, %v", n, got, err)
		}
	}
}

func TestRotate(t *testing.T) {
	dan := memberIdentity(t)
	danPub, _ := NewMemberWrapper("dan", dan.Recipient().String())
	v := newVault(t, danPub)
	values := map[string]string{"A": "value A", "B": "value B", "GONE": "trashed value"}
	for n, val := range values {
		if err := WriteSecret(v.dir, n, v.key, []byte(val)); err != nil {
			t.Fatal(err)
		}
	}
	trashed, err := format.TrashSecret(v.dir, "GONE", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	oldVF, _ := format.ReadVaultFile(v.dir)

	// Remove Dan: rewrap for the passphrase only.
	newKey, err := Rotate(v.dir, v.key, []KeyWrapper{v.pw})
	if err != nil {
		t.Fatal(err)
	}
	vf, err := format.ReadVaultFile(v.dir)
	if err != nil {
		t.Fatal(err)
	}
	if vf.KeyID == oldVF.KeyID || vf.KeyID != newKey.ID() || vf.ID != oldVF.ID || vf.Name != oldVF.Name {
		t.Fatalf("vault file after rotation: %+v", vf)
	}
	if len(vf.Unlockers) != 1 || vf.Unlockers[0].Type != format.UnlockerPassphrase {
		t.Fatalf("unlockers after rotation: %+v", vf.Unlockers)
	}
	if k, err := Unlock(vf, v.pw); err != nil || !bytes.Equal(k.Bytes(), newKey.Bytes()) {
		t.Fatalf("unlock after rotation = %v", err)
	}
	danW, _ := NewMemberIdentityWrapper("dan", dan)
	if _, err := Unlock(vf, danW); !errors.Is(err, ErrWrongKey) {
		t.Fatal("removed member can still unlock")
	}
	for _, n := range []string{"A", "B"} {
		got, err := ReadSecret(v.dir, n, newKey)
		if err != nil || string(got) != values[n] {
			t.Fatalf("%s after rotation = %q, %v", n, got, err)
		}
		if _, err := ReadSecret(v.dir, n, v.key); !errors.Is(err, ErrOtherKey) {
			t.Fatalf("old key still opens %s: %v", n, err)
		}
	}
	ct, err := format.ReadTrashedFile(v.dir, trashed)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := mustSealer(t, "GONE").Open(newKey, ct); err != nil || string(got) != values["GONE"] {
		t.Fatalf("trashed after rotation = %q, %v", got, err)
	}
	if ids, _ := format.PendingRotations(v.dir); len(ids) != 0 {
		t.Fatalf("staging left: %v", ids)
	}
	// The old key is no longer accepted for a second rotation.
	if _, err := Rotate(v.dir, v.key, []KeyWrapper{v.pw}); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("rotate with stale key = %v", err)
	}
}

func TestRotateRefusesConflicts(t *testing.T) {
	v := newVault(t)
	_ = WriteSecret(v.dir, "A", v.key, []byte("a"))
	p := filepath.Join(format.SecretsPath(v.dir), "A (Dan's conflicted copy 2026-11-20).age")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(v.dir, v.key, []KeyWrapper{v.pw}); !errors.Is(err, ErrConflicts) {
		t.Fatalf("rotate with conflicts = %v", err)
	}
}

// A failure before vault.json is written leaves the vault exactly as it
// was: same key, readable secrets, no staging folder.
func TestRotateFailureChangesNothing(t *testing.T) {
	v := newVault(t)
	_ = WriteSecret(v.dir, "A", v.key, []byte("a"))
	_ = WriteSecret(v.dir, "B", v.key, []byte("b"))
	// Corrupt B so it cannot be re-encrypted.
	pb, _ := format.SecretPath(v.dir, "B")
	data, _ := os.ReadFile(pb)
	data[len(data)-1] ^= 1
	if err := os.WriteFile(pb, data, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(format.VaultFilePath(v.dir))
	if _, err := Rotate(v.dir, v.key, []KeyWrapper{v.pw}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("rotate over a corrupt file = %v", err)
	}
	after, _ := os.ReadFile(format.VaultFilePath(v.dir))
	if !bytes.Equal(before, after) {
		t.Fatal("vault.json changed by a failed rotation")
	}
	if got, err := ReadSecret(v.dir, "A", v.key); err != nil || string(got) != "a" {
		t.Fatalf("A after failed rotation = %q, %v", got, err)
	}
	if ids, _ := format.PendingRotations(v.dir); len(ids) != 0 {
		t.Fatalf("staging left: %v", ids)
	}
	if _, err := Rotate(v.dir, v.key, nil); err == nil {
		t.Fatal("rotation with no wrappers accepted")
	}
}

// Leak test for every vault-level path that touches a secret: create,
// write, read, wrong-key read, trash, rotate. Canaries must not appear in
// the vault folder, temp files, output or logs.
func TestVaultLeak(t *testing.T) {
	leaktest.RunFunc(t, func(h *leaktest.Harness) {
		pass := h.Canary()
		pw, err := NewPassphraseWrapperWithWorkFactor([]byte(pass), testWorkFactor)
		if err != nil {
			t.Fatal(err)
		}
		k, err := VaultKeyFromBytes(h.CanaryBytes(KeySize))
		if err != nil {
			t.Fatal(err)
		}
		vf, err := NewVaultFile("leak", k, []KeyWrapper{pw})
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(h.TempDir, "vault")
		h.WatchDir(dir)
		if err := format.CreateVault(dir, vf); err != nil {
			t.Fatal(err)
		}
		v1, v2 := h.Canary(), h.Canary()
		if err := WriteSecret(dir, "ONE", k, []byte(v1)); err != nil {
			t.Fatal(err)
		}
		if err := WriteSecret(dir, "TWO", k, []byte(v2)); err != nil {
			t.Fatal(err)
		}
		if _, err := format.TrashSecret(dir, "TWO", time.Now()); err != nil {
			t.Fatal(err)
		}
		idx, _, err := format.RebuildIndex(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := format.WriteIndex(dir, idx); err != nil {
			t.Fatal(err)
		}
		got, err := ReadSecret(dir, "ONE", k)
		if err != nil || string(got) != v1 {
			t.Fatalf("read = %v", err)
		}
		other := mustKey(t)
		_, err = ReadSecret(dir, "ONE", other)
		h.Stderr.WriteString(err.Error())
		_, err = Unlock(vf, passWrapper(t, pass+"!"))
		h.Stderr.WriteString(err.Error())

		newKey, err := Rotate(dir, k, []KeyWrapper{pw})
		if err != nil {
			t.Fatal(err)
		}
		h.AddCanary(newKey.Bytes())
		h.Logger.Info("rotated", "old", k, "new", newKey, "key_id", newKey.ID())
		_, err = Rotate(dir, k, []KeyWrapper{pw})
		h.Stderr.WriteString(err.Error())
		conflicts, _ := format.FindConflicts(dir)
		if len(conflicts) != 0 {
			t.Fatalf("leftover files: %+v", conflicts)
		}
	})
}
