package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/leaktest"
)

// testWorkFactor keeps scrypt fast in tests; production uses
// DefaultScryptWorkFactor.
const testWorkFactor = MinScryptWorkFactor

func passWrapper(t testing.TB, pass string) KeyWrapper {
	t.Helper()
	w, err := NewPassphraseWrapperWithWorkFactor([]byte(pass), testWorkFactor)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func memberIdentity(t testing.TB) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestPassphraseWrapper(t *testing.T) {
	k := mustKey(t)
	w := passWrapper(t, "correct horse")
	if w.Type() != format.UnlockerPassphrase {
		t.Fatal("wrong type")
	}
	u, err := w.Wrap(k)
	if err != nil {
		t.Fatal(err)
	}
	if u.Type != format.UnlockerPassphrase || u.Created.IsZero() || len(u.WrappedKey) == 0 {
		t.Fatalf("bad unlocker: %+v", u)
	}
	if err := u.Validate(); err != nil {
		t.Fatal(err)
	}
	got, err := w.Unwrap(u)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), k.Bytes()) {
		t.Fatal("unwrapped key differs")
	}
	if _, err := passWrapper(t, "wrong horse").Unwrap(u); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong passphrase = %v", err)
	}
	u.Type = format.UnlockerMember
	if _, err := w.Unwrap(u); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("wrong type = %v", err)
	}
}

func TestPassphraseWrapperArgs(t *testing.T) {
	if _, err := NewPassphraseWrapper(nil); err == nil {
		t.Fatal("empty passphrase accepted")
	}
	if _, err := NewPassphraseWrapperWithWorkFactor([]byte("x"), MinScryptWorkFactor-1); err == nil {
		t.Fatal("tiny work factor accepted")
	}
	if _, err := NewPassphraseWrapperWithWorkFactor([]byte("x"), MaxScryptWorkFactor+1); err == nil {
		t.Fatal("huge work factor accepted")
	}
	pass := []byte("secret")
	w, err := NewPassphraseWrapper(pass)
	if err != nil {
		t.Fatal(err)
	}
	pass[0] = 'X' // the wrapper keeps its own copy
	if w.(*passphraseWrapper).pass[0] != 's' {
		t.Fatal("wrapper aliases the caller's slice")
	}
	w.(interface{ Destroy() }).Destroy()
	if !bytes.Equal(w.(*passphraseWrapper).pass, make([]byte, 6)) {
		t.Fatal("Destroy did not zero the passphrase")
	}
}

// A vault.json edited to demand a huge scrypt work factor is refused
// quickly rather than computed.
func TestPassphraseUnwrapCapsWorkFactor(t *testing.T) {
	w := passWrapper(t, "pw")
	u, err := w.Wrap(mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the stanza's work factor ("-> scrypt <salt> 10") to 30.
	old := []byte(" 10\n")
	if !bytes.Contains(u.WrappedKey, old) {
		t.Fatalf("unexpected scrypt stanza: %q", u.WrappedKey)
	}
	u.WrappedKey = bytes.Replace(u.WrappedKey, old, []byte(" 30\n"), 1)
	start := time.Now()
	if _, err := w.Unwrap(u); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("over-cap work factor = %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("over-cap work factor was computed (%v)", d)
	}
}

func TestMemberWrapper(t *testing.T) {
	k := mustKey(t)
	dan := memberIdentity(t)
	pub, err := NewMemberWrapper("dan", dan.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	u, err := pub.Wrap(k)
	if err != nil {
		t.Fatal(err)
	}
	if u.Type != format.UnlockerMember || u.Label != "dan" || u.Recipient != dan.Recipient().String() {
		t.Fatalf("bad unlocker: %+v", u)
	}
	if err := u.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := pub.Unwrap(u); !errors.Is(err, ErrWrongKey) {
		t.Fatal("wrap-only wrapper unwrapped")
	}
	priv, err := NewMemberIdentityWrapper("dan", dan)
	if err != nil {
		t.Fatal(err)
	}
	got, err := priv.Unwrap(u)
	if err != nil || !bytes.Equal(got.Bytes(), k.Bytes()) {
		t.Fatalf("member unwrap = %v", err)
	}
	eve, err := NewMemberIdentityWrapper("eve", memberIdentity(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eve.Unwrap(u); !errors.Is(err, ErrWrongKey) {
		t.Fatal("other member unwrapped")
	}
	// Eve relabelling Dan's unlocker with her recipient still cannot open it.
	u.Recipient = eve.(*memberWrapper).recipient.String()
	if _, err := eve.Unwrap(u); !errors.Is(err, ErrWrongKey) {
		t.Fatal("relabelled unlocker opened")
	}
	if _, err := NewMemberWrapper("dan", "not-a-recipient"); err == nil {
		t.Fatal("bad recipient accepted")
	}
	if _, err := NewMemberWrapper("", dan.Recipient().String()); err == nil {
		t.Fatal("empty label accepted")
	}
	if _, err := NewMemberIdentityWrapper("x", nil); err == nil {
		t.Fatal("nil identity accepted")
	}
}

// Tamper: corrupted, truncated or extended wrapped keys never unwrap.
func TestUnwrapTamper(t *testing.T) {
	k := mustKey(t)
	dan := memberIdentity(t)
	w, err := NewMemberIdentityWrapper("dan", dan)
	if err != nil {
		t.Fatal(err)
	}
	u, err := w.Wrap(k)
	if err != nil {
		t.Fatal(err)
	}
	good := u.WrappedKey
	for i := range good {
		bad := u
		bad.WrappedKey = bytes.Clone(good)
		bad.WrappedKey[i] ^= 0x04
		if got, err := w.Unwrap(bad); err == nil {
			got.Destroy()
			t.Fatalf("flip at %d unwrapped", i)
		}
	}
	for n := 0; n < len(good); n++ {
		bad := u
		bad.WrappedKey = good[:n]
		if _, err := w.Unwrap(bad); err == nil {
			t.Fatalf("truncation to %d unwrapped", n)
		}
	}
	// A wrapped value of the wrong length (a valid age file) is refused.
	var buf bytes.Buffer
	enc, _ := age.Encrypt(&buf, dan.Recipient())
	_, _ = enc.Write(make([]byte, KeySize+1))
	_ = enc.Close()
	u.WrappedKey = buf.Bytes()
	if _, err := w.Unwrap(u); !errors.Is(err, ErrWrongKey) {
		t.Fatal("wrong-length key accepted")
	}
}

func TestWrappersLeak(t *testing.T) {
	leaktest.RunFunc(t, func(h *leaktest.Harness) {
		k, err := VaultKeyFromBytes(h.CanaryBytes(KeySize))
		if err != nil {
			t.Fatal(err)
		}
		pass := h.Canary()
		pw, err := NewPassphraseWrapperWithWorkFactor([]byte(pass), testWorkFactor)
		if err != nil {
			t.Fatal(err)
		}
		dan := memberIdentity(t)
		mw, err := NewMemberIdentityWrapper("dan", dan)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range []KeyWrapper{pw, mw} {
			u, err := w.Wrap(k)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(&format.VaultFile{
				Version: 1, ID: "0123456789abcdef0123456789abcdef", Name: "v",
				KeyID: k.ID(), Unlockers: []format.Unlocker{u},
			})
			if err != nil {
				t.Fatal(err)
			}
			h.Stdout.Write(data)
			h.Logger.Info("wrapped", "wrapper", w, "unlocker", u)
			if _, err := w.Unwrap(u); err != nil {
				t.Fatal(err)
			}
		}
		wrong, _ := NewPassphraseWrapperWithWorkFactor([]byte(pass+"x"), testWorkFactor)
		u, _ := pw.Wrap(k)
		_, err = wrong.Unwrap(u)
		h.Stderr.WriteString(err.Error())
	})
}

func FuzzMemberUnwrap(f *testing.F) {
	// A fresh identity per run: parsing paths do not depend on it, and no
	// key material (even a fake one) is committed for gitleaks to trip on.
	id := memberIdentity(f)
	w, err := NewMemberIdentityWrapper("fuzz", id)
	if err != nil {
		f.Fatal(err)
	}
	k, _ := VaultKeyFromBytes(bytes.Repeat([]byte{9}, KeySize))
	u, err := w.Wrap(k)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(u.WrappedKey)
	f.Add([]byte("age-encryption.org/v1\n-> X25519 x\n\n--- y\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := w.Unwrap(format.Unlocker{Type: format.UnlockerMember, Recipient: u.Recipient, WrappedKey: data})
		if err != nil {
			if got != nil || !errors.Is(err, ErrWrongKey) {
				t.Fatalf("bad error contract: %v", err)
			}
			return
		}
		got.Destroy()
	})
}
