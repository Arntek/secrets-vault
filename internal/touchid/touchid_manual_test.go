//go:build darwin && cgo && touchid && manual

package touchid

// Manual Touch ID test against the real Secure Enclave. A person has to be
// at the Mac to touch the sensor, so it only builds with the "manual" tag:
//
//	make touchid-manual
//
// It enrolls a throwaway enclave key in a temp folder (deleted afterwards),
// wraps a random test key and asks for Touch ID twice: touch the sensor the
// first time, press "Use passphrase" (cancel) the second time.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

func say(format string, a ...any) { fmt.Fprintf(os.Stderr, "\n>>> "+format+"\n", a...) }

func TestManualTouchID(t *testing.T) {
	if !Available() {
		t.Fatal("Touch ID not available here (no sensor, no fingerprint enrolled, lid closed, or SSH session)")
	}
	d, err := Enroll("manual-test", filepath.Join(t.TempDir(), "touchid.blob"))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	kw, err := WrapperForVault(d, "manual-test")
	if err != nil {
		t.Fatalf("wrapper: %v", err)
	}
	key, err := crypto.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	u, err := kw.Wrap(key)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}

	say("1/2: a Touch ID sheet will appear naming the \u201cmanual-test\u201d vault. TOUCH THE SENSOR.")
	got, err := kw.Unwrap(u)
	if err != nil {
		t.Fatalf("unwrap with fingerprint: %v", err)
	}
	if !bytes.Equal(got.Bytes(), key.Bytes()) {
		t.Fatal("unwrapped key differs from the wrapped one")
	}
	got.Destroy()
	say("1/2 passed: test key unwrapped after Touch ID.")

	say("2/2: the sheet will appear again. Press \u201cUse passphrase\u201d (or Cancel) - do NOT touch.")
	if _, err := kw.Unwrap(u); err != ErrCancelled {
		t.Fatalf("cancel: got %v, want ErrCancelled", err)
	}
	say("2/2 passed: cancel reported as ErrCancelled.")

	// Another Mac's unlocker must fail without showing the sheet.
	u.Recipient = recipientPrefix + "AAAA"
	if _, err := kw.Unwrap(u); err != crypto.ErrWrongKey {
		t.Fatalf("other Mac: got %v, want ErrWrongKey", err)
	}
	say("done: no sheet should have appeared after 2/2.")
}
