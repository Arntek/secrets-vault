package crypto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/leaktest"
)

type testVault struct {
	dir   string
	key   *VaultKey
	pw    KeyWrapper
	owner KeyWrapper // every version-2 vault has an owner member
}

func newVault(t *testing.T, wrappers ...KeyWrapper) *testVault {
	t.Helper()
	pw := passWrapper(t, "test passphrase")
	owner, err := NewMemberWrapper("owner", memberIdentity(t).Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	k := mustKey(t)
	vf, err := NewVaultFile("test", k, append([]KeyWrapper{pw, owner}, wrappers...))
	if err != nil {
		t.Fatal(err)
	}
	complete(vf)
	dir := filepath.Join(t.TempDir(), "vault")
	if err := format.CreateVault(dir, vf); err != nil {
		t.Fatal(err)
	}
	return &testVault{dir: dir, key: k, pw: pw, owner: owner}
}

// complete makes vf structurally valid for format: one member entry per
// member unlocker (the first is the owner) and a placeholder log. The
// signed log itself is package members' business and is not checked here.
func complete(vf *format.VaultFile) {
	vf.Members = nil
	for i, u := range vf.Unlockers {
		if u.Type != format.UnlockerMember {
			continue
		}
		role := format.RoleMember
		if u.Label == "owner" {
			role = format.RoleOwner
		}
		sk := strings.Repeat(string("0123456789abcdef"[i%16]), format.SignKeyHexLen)
		vf.Members = append(vf.Members, format.Member{Name: u.Label, Recipient: u.Recipient, SignKey: sk, Role: role})
	}
	format.SortMembers(vf.Members)
	vf.Log = []format.LogEntry{{Body: []byte(`{}`), By: "owner", Sig: make([]byte, format.SignatureSize)}}
}

// rotateTo returns RotateOptions that wrap the new key for the owner and
// wrappers, keeping everything else of the current vault.json.
func (v *testVault) rotateTo(t *testing.T, wrappers ...KeyWrapper) RotateOptions {
	return RotateOptions{Next: func(newKey *VaultKey) (*format.VaultFile, error) {
		cur, err := format.ReadVaultFile(v.dir)
		if err != nil {
			return nil, err
		}
		us, err := WrapAll(newKey, append([]KeyWrapper{v.owner}, wrappers...))
		if err != nil {
			return nil, err
		}
		next := *cur
		next.KeyID = newKey.ID()
		next.Unlockers = us
		complete(&next)
		return &next, nil
	}}
}

func TestNewVaultAndUnlock(t *testing.T) {
	dan := memberIdentity(t)
	danPub, _ := NewMemberWrapper("dan", dan.Recipient().String())
	v := newVault(t, danPub)
	vf, err := format.ReadVaultFile(v.dir)
	if err != nil {
		t.Fatal(err)
	}
	if vf.KeyID != v.key.ID() || len(vf.Unlockers) != 3 {
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
	newKey, err := Rotate(v.dir, v.key, v.rotateTo(t, v.pw))
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
	if len(vf.Unlockers) != 2 || vf.Unlockers[1].Type != format.UnlockerPassphrase {
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
	if _, err := Rotate(v.dir, v.key, v.rotateTo(t, v.pw)); !errors.Is(err, ErrWrongKey) {
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
	if _, err := Rotate(v.dir, v.key, v.rotateTo(t, v.pw)); !errors.Is(err, ErrConflicts) {
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
	if _, err := Rotate(v.dir, v.key, v.rotateTo(t, v.pw)); !errors.Is(err, ErrDecrypt) {
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
	if _, err := Rotate(v.dir, v.key, RotateOptions{}); err == nil {
		t.Fatal("rotation without a new vault file accepted")
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
		owner, _ := NewMemberWrapper("owner", memberIdentity(t).Recipient().String())
		vf, err := NewVaultFile("leak", k, []KeyWrapper{pw, owner})
		if err != nil {
			t.Fatal(err)
		}
		complete(vf)
		dir := filepath.Join(h.TempDir, "vault")
		v := &testVault{dir: dir, key: k, pw: pw, owner: owner}
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
		for i := range idx.Entries {
			idx.Entries[i].Version, idx.Entries[i].Rev, idx.Entries[i].MAC = 1, 1, strings.Repeat("a", 64)
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

		newKey, err := Rotate(dir, k, v.rotateTo(t, pw))
		if err != nil {
			t.Fatal(err)
		}
		h.AddCanary(newKey.Bytes())
		h.Logger.Info("rotated", "old", k, "new", newKey, "key_id", newKey.ID())
		_, err = Rotate(dir, k, v.rotateTo(t, pw))
		h.Stderr.WriteString(err.Error())
		conflicts, _ := format.FindConflicts(dir)
		if len(conflicts) != 0 {
			t.Fatalf("leftover files: %+v", conflicts)
		}
	})
}

// ue1.4 / M4: recovery moves staged files only when each opens under the
// verified key; a planted staging folder for any other key is untouched.
func TestRecoverRotation(t *testing.T) {
	v := newVault(t)
	_ = WriteSecret(v.dir, "A", v.key, []byte("real"))
	before, _ := format.ReadSecretFile(v.dir, "A")

	// Planted: staging for v.key's id with junk content.
	s, err := format.BeginStaging(v.dir, v.key.ID())
	if err != nil {
		t.Fatal(err)
	}
	_ = s.AddSecret("A", []byte("attacker junk"))
	_ = s.Finish()
	if done, err := RecoverRotation(v.dir, v.key); done || err == nil {
		t.Fatalf("junk staging committed: %v %v", done, err)
	}
	if got, _ := format.ReadSecretFile(v.dir, "A"); !bytes.Equal(got, before) {
		t.Fatal("live file overwritten by planted staging")
	}
	_ = format.AbandonStaging(v.dir, v.key.ID())

	// Genuine: staged under the key, opens with its own name.
	s, _ = format.BeginStaging(v.dir, v.key.ID())
	ct, _ := mustSealer(t, "A").Seal(v.key, []byte("staged"))
	_ = s.AddSecret("A", ct)
	_ = s.Finish()
	// A file staged for another name does not open as A.
	other := mustKey(t)
	if done, _ := RecoverRotation(v.dir, other); done {
		t.Fatal("recovered a staging folder for another key")
	}
	if done, err := RecoverRotation(v.dir, v.key); !done || err != nil {
		t.Fatalf("RecoverRotation = %v, %v", done, err)
	}
	if got, err := ReadSecret(v.dir, "A", v.key); err != nil || string(got) != "staged" {
		t.Fatalf("after recovery = %q, %v", got, err)
	}
}

func TestKeyIDOf(t *testing.T) {
	k := mustKey(t)
	ct, _ := mustSealer(t, "A").Seal(k, []byte("x"))
	if id, err := KeyIDOf(ct); err != nil || id != k.ID() {
		t.Fatalf("KeyIDOf = %q, %v", id, err)
	}
	for _, bad := range [][]byte{nil, []byte("age-encryption.org/v1\n-> X25519 abc\n"), ct[:30]} {
		if _, err := KeyIDOf(bad); err == nil {
			t.Errorf("KeyIDOf(%q) accepted", bad)
		}
	}
}

// Files sealed under an extra key (a lost rotation's key) are re-sealed;
// a file under an unknown key fails the rotation.
func TestRotateExtraKeys(t *testing.T) {
	v := newVault(t)
	k3 := mustKey(t)
	_ = WriteSecret(v.dir, "A", v.key, []byte("a"))
	_ = WriteSecret(v.dir, "B", k3, []byte("b"))
	if _, err := Rotate(v.dir, v.key, v.rotateTo(t, v.pw)); !errors.Is(err, ErrOtherKey) {
		t.Fatalf("rotation over an unknown-key file = %v", err)
	}
	opt := v.rotateTo(t, v.pw)
	opt.ExtraKeys = []*VaultKey{k3}
	nk, err := Rotate(v.dir, v.key, opt)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ReadSecret(v.dir, "B", nk); err != nil || string(got) != "b" {
		t.Fatalf("B = %q, %v", got, err)
	}
}

// M4 CAS: Rotate refuses when vault.json is not the bytes the caller
// verified.
func TestRotateCAS(t *testing.T) {
	v := newVault(t)
	opt := v.rotateTo(t, v.pw)
	opt.Expect = []byte("{}")
	if _, err := Rotate(v.dir, v.key, opt); !errors.Is(err, format.ErrChanged) {
		t.Fatalf("Rotate with stale Expect = %v", err)
	}
}

// v1Seal seals like builds from before ue1.8 did (stanza sv-vaultkey,
// v1 HKDF label), for the compatibility and old-build tests.
type v1Recipient struct {
	key  *VaultKey
	name string
}

func (r *v1Recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	salt := bytes.Repeat([]byte{3}, saltSize)
	aead, err := fileKeyWrapper(r.key, salt, r.name, stanzaTypeV1)
	if err != nil {
		return nil, err
	}
	return []*age.Stanza{{Type: stanzaTypeV1, Args: []string{r.key.ID(), base64.RawStdEncoding.EncodeToString(salt)},
		Body: aead.Seal(nil, make([]byte, aead.NonceSize()), fileKey, nil)}}, nil
}

func v1Seal(t *testing.T, key *VaultKey, name, value string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, &v1Recipient{key: key, name: name})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(value))
	_ = w.Close()
	return buf.Bytes()
}

// oldBuildIdentity opens secret files the way builds from before ue1.8
// did: only the v1 stanza type and label.
type oldBuildIdentity struct{ v *vaultKeyIdentity }

func (o oldBuildIdentity) Unwrap(st []*age.Stanza) ([]byte, error) {
	if len(st) != 1 || st[0].Type != stanzaTypeV1 {
		return nil, age.ErrIncorrectIdentity
	}
	return o.v.Unwrap(st)
}

// ue1.8 B: what this build writes gives an old build nothing to work with.
func TestOldBuildsCannotUseV2Data(t *testing.T) {
	key := mustKey(t)
	// Secret files: an old build's identity finds no stanza it knows.
	ct, err := mustSealer(t, "A").Seal(key, []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(bytes.NewReader(ct), oldBuildIdentity{&vaultKeyIdentity{key: key, name: "A"}}); err == nil {
		t.Fatal("an old build could open a v2 secret file")
	}
	// Wrapped keys: an old build expects exactly 32 bytes and gets more.
	id := memberIdentity(t)
	w, _ := NewMemberIdentityWrapper("m", id)
	u, err := w.Wrap(key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := age.Decrypt(bytes.NewReader(u.WrappedKey), id)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(io.LimitReader(r, KeySize+1))
	if len(b) == KeySize {
		t.Fatal("an old build could unwrap a v2 member unlocker")
	}
	pw := passWrapper(t, "pass phrase")
	pu, _ := pw.Wrap(key)
	sid, _ := age.NewScryptIdentity("pass phrase")
	r, err = age.Decrypt(bytes.NewReader(pu.WrappedKey), sid)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(io.LimitReader(r, KeySize+1)); len(b) == KeySize {
		t.Fatal("an old build could unwrap a v2 passphrase unlocker")
	}
	// This build still reads both forms.
	if k, err := w.Unwrap(u); err != nil || k.ID() != key.ID() {
		t.Fatalf("v2 unwrap: %v", err)
	}
	var legacy bytes.Buffer
	enc, _ := age.Encrypt(&legacy, id.Recipient())
	_, _ = enc.Write(key.Bytes())
	_ = enc.Close()
	if k, err := w.Unwrap(format.Unlocker{Type: format.UnlockerMember, Recipient: u.Recipient, WrappedKey: legacy.Bytes()}); err != nil || k.ID() != key.ID() {
		t.Fatalf("legacy unwrap: %v", err)
	}
}

// Migration helper: v1-format files are read and upgraded in place.
func TestUpgradeSecrets(t *testing.T) {
	v := newVault(t)
	if err := format.WriteSecretFile(v.dir, "OLD", v1Seal(t, v.key, "OLD", "old value")); err != nil {
		t.Fatal(err)
	}
	_ = WriteSecret(v.dir, "NEW", v.key, []byte("new value"))
	if got, err := ReadSecret(v.dir, "OLD", v.key); err != nil || string(got) != "old value" {
		t.Fatalf("v1 file read: %q %v", got, err)
	}
	ct, _ := format.ReadSecretFile(v.dir, "OLD")
	if id, err := KeyIDOf(ct); err != nil || id != v.key.ID() {
		t.Fatalf("KeyIDOf v1: %v", err)
	}
	n, err := UpgradeSecrets(v.dir, v.key)
	if err != nil || n != 1 {
		t.Fatalf("UpgradeSecrets = %d, %v", n, err)
	}
	ct, _ = format.ReadSecretFile(v.dir, "OLD")
	if !bytes.Contains(ct[:64], []byte(stanzaType+" ")) {
		t.Fatal("not upgraded")
	}
	if got, err := ReadSecret(v.dir, "OLD", v.key); err != nil || string(got) != "old value" {
		t.Fatalf("after upgrade: %q %v", got, err)
	}
	if n, _ := UpgradeSecrets(v.dir, v.key); n != 0 {
		t.Fatal("not idempotent")
	}
}
