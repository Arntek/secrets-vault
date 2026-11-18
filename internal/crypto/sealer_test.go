package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/Arntek/secrets-vault/internal/leaktest"
)

func mustKey(t testing.TB) *VaultKey {
	t.Helper()
	k, err := NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustSealer(t testing.TB, name string) Sealer {
	t.Helper()
	s, err := NewSealer(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKeyID(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	if a.ID() == b.ID() || len(a.ID()) != 32 {
		t.Fatalf("key IDs: %q %q", a.ID(), b.ID())
	}
	if id1, id2 := a.ID(), a.ID(); id1 != id2 {
		t.Fatal("key ID not stable")
	}
	if strings.Contains(a.ID(), strings.ToLower(string(a.Bytes()[:4]))) {
		t.Fatal("key ID contains key bytes")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	k := mustKey(t)
	s := mustSealer(t, "API_KEY")
	for _, pt := range [][]byte{{}, []byte("v"), bytes.Repeat([]byte("x"), 64*1024+7), make([]byte, MaxSecretSize)} {
		ct, err := s.Seal(k, pt)
		if err != nil {
			t.Fatal(err)
		}
		if len(pt) > 8 && bytes.Contains(ct, pt[:8]) {
			t.Fatal("plaintext visible in ciphertext")
		}
		got, err := s.Open(k, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatal("round trip mismatch")
		}
	}
	if _, err := s.Seal(k, make([]byte, MaxSecretSize+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize seal = %v", err)
	}
	if _, err := NewSealer("bad name"); err == nil {
		t.Fatal("invalid key name accepted")
	}
}

func TestSealIsRandomized(t *testing.T) {
	k := mustKey(t)
	s := mustSealer(t, "A")
	c1, _ := s.Seal(k, []byte("same"))
	c2, _ := s.Seal(k, []byte("same"))
	if bytes.Equal(c1, c2) {
		t.Fatal("two seals of the same value are identical")
	}
}

func TestOpenWrongKeyAndOtherKey(t *testing.T) {
	k1, k2 := mustKey(t), mustKey(t)
	s := mustSealer(t, "A")
	ct, err := s.Seal(k1, []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(k2, ct); !errors.Is(err, ErrOtherKey) || !errors.Is(err, ErrDecrypt) {
		t.Fatalf("open with another key = %v, want ErrOtherKey", err)
	}
	if _, err := s.Open(nil, ct); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("open with nil key = %v", err)
	}
}

// Tamper: a file sealed for one name never opens as another, so swapping
// secrets/A.age and secrets/B.age is detected.
func TestOpenSwappedName(t *testing.T) {
	k := mustKey(t)
	ct, err := mustSealer(t, "A").Seal(k, []byte("value of A"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = mustSealer(t, "B").Open(k, ct)
	if !errors.Is(err, ErrDecrypt) || errors.Is(err, ErrOtherKey) {
		t.Fatalf("open under swapped name = %v, want ErrDecrypt", err)
	}
}

// Tamper: flipping any bit or truncating anywhere is rejected, and Open
// never returns partial plaintext.
func TestOpenTamper(t *testing.T) {
	k := mustKey(t)
	s := mustSealer(t, "A")
	pt := bytes.Repeat([]byte("p"), 70*1024) // spans two age chunks
	ct, err := s.Seal(k, pt)
	if err != nil {
		t.Fatal(err)
	}
	positions := []int{}
	for i := 0; i < 300 && i < len(ct); i++ {
		positions = append(positions, i)
	}
	for i := 300; i < len(ct); i += 997 {
		positions = append(positions, i)
	}
	positions = append(positions, len(ct)-1)
	for _, i := range positions {
		bad := bytes.Clone(ct)
		bad[i] ^= 0x01
		if got, err := s.Open(k, bad); err == nil || got != nil {
			t.Fatalf("bit flip at %d accepted", i)
		}
	}
	for _, n := range []int{0, 1, 20, 100, len(ct) / 2, 64*1024 + 50, len(ct) - 17, len(ct) - 1} {
		if got, err := s.Open(k, ct[:n]); err == nil || got != nil {
			t.Fatalf("truncation to %d accepted", n)
		}
	}
	if _, err := s.Open(k, append(bytes.Clone(ct), 0)); err == nil {
		t.Fatal("appended byte accepted")
	}
}

// A secret file must not carry a second recipient (for example an X25519
// stanza an attacker could add). age's header MAC stops that without the
// file key; the identity also insists on exactly one stanza.
func TestOpenRejectsExtraStanzas(t *testing.T) {
	k := mustKey(t)
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("v"))
	_ = w.Close()
	if _, err := mustSealer(t, "A").Open(k, buf.Bytes()); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("X25519 file opened: %v", err)
	}
	if _, err := age.Encrypt(&bytes.Buffer{}, &vaultKeyRecipient{key: k, name: "A"}, id.Recipient()); err == nil {
		t.Fatal("age mixed the vault-key recipient with another")
	}
}

func TestSealerLeak(t *testing.T) {
	leaktest.RunFunc(t, func(h *leaktest.Harness) {
		k, err := VaultKeyFromBytes(h.CanaryBytes(KeySize))
		if err != nil {
			t.Fatal(err)
		}
		value := []byte(h.Canary())
		s := mustSealer(t, "API_KEY")
		ct, err := s.Seal(k, value)
		if err != nil {
			t.Fatal(err)
		}
		// The ciphertext goes to stdout to prove it hides both canaries.
		h.Stdout.Write(ct)
		h.Logger.Info("sealed", "key", k, "ciphertext_len", len(ct))
		bad := bytes.Clone(ct)
		bad[len(bad)-1] ^= 1
		_, err = s.Open(k, bad)
		h.Stderr.WriteString(err.Error())
		_, err = mustSealer(t, "OTHER").Open(k, ct)
		h.Stderr.WriteString(err.Error())
		got, err := s.Open(k, ct)
		if err != nil || !bytes.Equal(got, value) {
			t.Fatalf("open failed: %v", err)
		}
	})
}

func FuzzOpen(f *testing.F) {
	k, err := VaultKeyFromBytes(bytes.Repeat([]byte{7}, KeySize))
	if err != nil {
		f.Fatal(err)
	}
	s := mustSealer(f, "FUZZ")
	for _, pt := range []string{"", "value", strings.Repeat("x", 300)} {
		ct, err := s.Seal(k, []byte(pt))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(ct)
	}
	f.Add([]byte("age-encryption.org/v1\n-> sv-vaultkey a b\n\n--- x\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		pt, err := s.Open(k, data)
		if err != nil {
			if pt != nil || !errors.Is(err, ErrDecrypt) {
				t.Fatalf("bad error contract: %v", err)
			}
			return
		}
		if len(pt) > MaxSecretSize {
			t.Fatal("oversize plaintext returned")
		}
	})
}
