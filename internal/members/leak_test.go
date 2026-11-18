package members

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/leaktest"
)

// TestMembersNeverLeak runs identity creation, export, import, a signed
// request, approve, remove (rotation), passwd, the write guard, pins,
// pending keys and a lost-race rebase with canary passphrases and secret
// values, and fails if any shows up in output, logs, errors, the identity
// and trust stores, the export file or the vault folder. Failing operations
// are included: their errors are written to stderr like the CLI would.
func TestMembersNeverLeak(t *testing.T) {
	h := leaktest.New(t)
	logErr := func(err error) {
		if err != nil {
			fmt.Fprintln(h.Stderr, err)
			h.Logger.Error("failed", "err", err)
		}
	}
	alicePass, bobPass, transferPass, vaultPassC, newVaultPass := h.Canary(), h.Canary(), h.Canary(), h.Canary(), h.Canary()
	secretValue := h.Canary()
	pw := func(s string) crypto.KeyWrapper {
		w, err := crypto.NewPassphraseWrapperWithWorkFactor([]byte(s), crypto.MinScryptWorkFactor)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	h.WatchDir(h.HomeDir)
	alice := NewStore(filepath.Join(h.HomeDir, "alice"))
	bob := NewStore(filepath.Join(h.HomeDir, "bob"))
	if _, err := alice.Create("alice", pw(alicePass)); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Create("bob", pw(bobPass)); err != nil {
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
	_, err = alice.Unlock(pw(bobPass)) // wrong passphrase
	logErr(err)
	h.Logger.Info("identities", "alice", au, "bob", bu)

	dir := filepath.Join(h.HomeDir, "vault")
	key, err := crypto.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	h.AddCanary(key.Bytes())
	c, err := NewVault(dir, "team", key, au, pw(vaultPassC), t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.WriteSecret(dir, "API_KEY", key, []byte(secretValue)); err != nil {
		t.Fatal(err)
	}
	logErr(WriteRequest(dir, bu, t0))
	logErr(WriteRequest(dir, bu, t0)) // duplicate
	_, _, err = ApproveRequest(dir, c, key, au, "bob", "WRONG-WRONG-WRONG-0000", false, t0)
	logErr(err)
	c, _, err = ApproveRequest(dir, c, key, au, "bob", bu.Fingerprint, false, t0)
	if err != nil {
		t.Fatal(err)
	}
	ts := NewTrustStore(filepath.Join(h.HomeDir, "trust"))
	logErr(ts.Save(PinFor(c, []format.LogEntry{c.LastEntry()})))
	pending := NewPendingStore(filepath.Join(h.HomeDir, "pending"))
	res, err := Remove(dir, c, key, au, "bob", RotateOptions{Pending: pending, Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	h.AddCanary(res.NewKey.Bytes())
	keys, err := pending.Load(c.File.ID, au)
	logErr(err)
	for _, k := range keys {
		h.Logger.Info("pending", "key", k)
	}
	_, err = Remove(dir, c, key, au, "bob", RotateOptions{Now: t0}) // stale chain
	logErr(err)
	r2, err := Passwd(dir, res.Chain, res.NewKey, au, pw(newVaultPass), true, RotateOptions{Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	h.AddCanary(r2.NewKey.Bytes())
	rep, err := CheckFolder(dir, r2.Chain)
	logErr(err)
	h.Logger.Info("guard", "report", rep)
	_, err = Verify(c.File, nil, "ffffffffffffffffffffffffffffffff")
	logErr(err)
	logErr(MatchStateCode(r2.Chain, "team@0 ABLE-ABLE-ABLE-ABLE-ABLE-ABLE"))

	exp, err := alice.Export(pw(alicePass), pw(transferPass))
	if err != nil {
		t.Fatal(err)
	}
	mac2 := NewStore(filepath.Join(h.HomeDir, "mac2"))
	_, err = mac2.Import(exp, pw(transferPass+"x"), pw(alicePass))
	logErr(err)
	if _, err := mac2.Import(exp, pw(transferPass), pw(alicePass)); err != nil {
		t.Fatal(err)
	}
	h.Check()
}
