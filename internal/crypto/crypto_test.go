package crypto

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/Arntek/secrets-vault/internal/leaktest"
)

func TestNewVaultKeyIsRandom(t *testing.T) {
	a, err := NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("two vault keys are equal")
	}
	if bytes.Equal(a.Bytes(), make([]byte, KeySize)) {
		t.Fatal("vault key is all zero")
	}
}

func TestDestroyZeroes(t *testing.T) {
	k, err := NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	k.Destroy()
	if !bytes.Equal(k.Bytes(), make([]byte, KeySize)) {
		t.Fatal("Destroy did not zero the key")
	}
	k.Destroy()
	var nilKey *VaultKey
	nilKey.Destroy()
}

func TestVaultKeyFromBytesLength(t *testing.T) {
	if _, err := VaultKeyFromBytes(make([]byte, KeySize-1)); err == nil {
		t.Fatal("short key accepted")
	}
}

// A VaultKey formatted by mistake must never print its bytes.
func TestVaultKeyNeverFormats(t *testing.T) {
	leaktest.RunFunc(t, func(h *leaktest.Harness) {
		canary := h.CanaryBytes(KeySize)
		k, err := VaultKeyFromBytes(canary)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(h.Stdout, "%v %+v %#v %s\n", k, k, k, k)
		h.Logger.Info("unlocked", "key", k)
	})
}
