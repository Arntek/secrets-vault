package members

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/leaktest"
)

// TestMembersNeverLeak runs identity creation, export, import, request,
// approve and remove with canary passphrases, private keys and secret values,
// and fails if any shows up in output, logs, errors, the identity store, the
// export file or the vault folder. Failing operations are included: their
// errors are written to stderr like the CLI would.
func TestMembersNeverLeak(t *testing.T) {
	h := leaktest.New(t)
	logErr := func(err error) {
		if err != nil {
			fmt.Fprintln(h.Stderr, err)
			h.Logger.Error("failed", "err", err)
		}
	}

	alicePass := h.Canary()
	bobPass := h.Canary()
	transferPass := h.Canary()
	recoveryPass := h.Canary()
	secretValue := h.Canary()

	pw := func(s string) crypto.KeyWrapper {
		w, err := crypto.NewPassphraseWrapperWithWorkFactor([]byte(s), crypto.MinScryptWorkFactor)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}

	// Identities live in the default location under the harness HOME.
	dirA, _ := DefaultDir()
	alice := NewStore(dirA)
	bobDir := filepath.Join(h.HomeDir, "bob-config")
	bob := NewStore(bobDir)
	h.WatchDir(h.HomeDir)

	alicePub, err := alice.Create("alice", pw(alicePass))
	if err != nil {
		t.Fatal(err)
	}
	bobPub, err := bob.Create("bob", pw(bobPass))
	if err != nil {
		t.Fatal(err)
	}
	au, err := alice.Unlock(pw(alicePass))
	if err != nil {
		t.Fatal(err)
	}
	bu, err := bob.Unlock(pw(bobPass))
	if err != nil {
		t.Fatal(err)
	}
	h.AddCanary([]byte(au.id.String()))
	h.AddCanary([]byte(bu.id.String()))
	fmt.Fprintf(h.Stdout, "%v %+v %#v %s\n", au, au, au, au)
	h.Logger.Info("unlocked", "identity", au)
	// Wrong passphrase and bad inputs.
	_, err = alice.Unlock(pw("not-" + alicePass))
	logErr(err)
	_, err = alice.Create("alice", pw(alicePass))
	logErr(err)
	_, err = alice.Create("Bad Name "+alicePass, pw(alicePass))
	logErr(err)

	// Export and import to a second "Mac".
	data, err := alice.Export(pw(alicePass), pw(transferPass))
	if err != nil {
		t.Fatal(err)
	}
	exportPath := filepath.Join(h.HomeDir, "alice.export")
	if err := os.WriteFile(exportPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NewStore(filepath.Join(h.HomeDir, "mac2")).Import(data, pw("wrong-"+transferPass), pw(alicePass))
	logErr(err)
	if _, err := NewStore(filepath.Join(h.HomeDir, "mac2")).Import(data, pw(transferPass), pw(alicePass)); err != nil {
		t.Fatal(err)
	}

	// Shared vault with a canary secret.
	vaultDir := filepath.Join(h.HomeDir, "shared-vault")
	h.WatchDir(vaultDir)
	key, err := crypto.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	h.AddCanary(key.Bytes())
	aw, _ := au.MemberWrapper()
	vf, err := crypto.NewVaultFile("shared", key, []crypto.KeyWrapper{aw, pw(recoveryPass)})
	if err != nil {
		t.Fatal(err)
	}
	if err := format.CreateVault(vaultDir, vf); err != nil {
		t.Fatal(err)
	}
	if err := crypto.WriteSecret(vaultDir, "DB_PASSWORD", key, []byte(secretValue)); err != nil {
		t.Fatal(err)
	}

	// Request, refused approval, approval.
	if err := WriteRequest(vaultDir, bobPub, t0); err != nil {
		t.Fatal(err)
	}
	logErr(WriteRequest(vaultDir, bobPub, t0)) // duplicate
	_, err = ApproveRequest(vaultDir, key, "bob", alicePub.Fingerprint, "alice")
	logErr(err)
	m, err := ApproveRequest(vaultDir, key, "bob", bobPub.Fingerprint, "alice")
	if err != nil {
		t.Fatal(err)
	}
	ov, err := Inspect(vaultDir)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(h.Stdout, "%+v\n%#v\n", m, ov)

	// Bob opens the vault; then Alice removes him.
	bw, _ := bu.MemberWrapper()
	bobKey, err := crypto.Unlock(mustVault(t, vaultDir), bw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Remove(vaultDir, key, "bob") // missing passphrase wrapper
	logErr(err)
	res, err := Remove(vaultDir, key, "bob", pw(recoveryPass))
	if err != nil {
		t.Fatal(err)
	}
	h.AddCanary(res.NewKey.Bytes())
	fmt.Fprintf(h.Stdout, "%+v\n%#v\n%v\n", res, res, res.NewKey)
	h.Logger.Info("removed", "result", res, "key", res.NewKey, "old", bobKey)
	_, err = crypto.ReadSecret(vaultDir, "DB_PASSWORD", bobKey) // bob's old key
	logErr(err)
	if !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("old key read: %v", err)
	}
	// Tampered inputs produce errors that do not quote the file.
	mustWrite(t, filepath.Join(vaultDir, "requests", "mallory.json"), []byte(`{"name":"`+secretValue+`"}`))
	_, bad, _ := ListRequests(vaultDir)
	for _, b := range bad {
		logErr(b.Err)
	}
	mustWrite(t, alice.path(), []byte(`{"name":"`+alicePass+`"`))
	_, err = alice.Unlock(pw(alicePass))
	logErr(err)
	// The planted files hold canaries on purpose; they are not output.
	_ = os.Remove(alice.path())
	_ = os.Remove(filepath.Join(vaultDir, "requests", "mallory.json"))

	h.Check()
}

func mustVault(t testing.TB, dir string) *format.VaultFile {
	t.Helper()
	vf, err := format.ReadVaultFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	return vf
}
