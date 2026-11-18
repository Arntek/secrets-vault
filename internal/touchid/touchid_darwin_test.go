//go:build darwin && cgo && touchid

package touchid

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

// Exercises the real Swift bridge without needing a finger: creating an
// enclave key, reading its public key and wrapping never show the sheet.
// Skipped where there is no Secure Enclave or biometrics (CI VMs).
func TestBridgeEnrollAndWrap(t *testing.T) {
	if platform == nil {
		t.Fatal("bridge not registered in a touchid build")
	}
	if !Available() {
		t.Skip("Touch ID not available on this machine")
	}
	d, err := Enroll("bridge-test", filepath.Join(t.TempDir(), "touchid.blob"))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	kw, err := WrapperForVault(d, "bridge-test")
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
	if len(u.WrappedKey) != wrappedLen {
		t.Fatalf("wrapped length %d", len(u.WrappedKey))
	}
	// Re-reading the blob yields the same public key.
	kw2, err := WrapperForVault(d, "bridge-test")
	if err != nil {
		t.Fatal(err)
	}
	if kw.(*keyWrapper).recipient() != kw2.(*keyWrapper).recipient() {
		t.Fatal("public key changed between loads")
	}
}

func TestBridgeRejectsGarbage(t *testing.T) {
	if !Available() {
		t.Skip("Touch ID not available on this machine")
	}
	if _, err := platform.publicKey([]byte("not an enclave key")); !errors.Is(err, errBadKey) {
		t.Fatalf("publicKey(garbage) = %v, want errBadKey", err)
	}
}

func TestParentProgram(t *testing.T) {
	if platform.parentProgram() == "" {
		t.Error("parent program name is empty")
	}
}
