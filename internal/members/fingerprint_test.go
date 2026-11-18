package members

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"
)

// wordlistSHA256 pins the committed list: changing it would change every
// fingerprint ever shown.
const wordlistSHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

func TestWordList(t *testing.T) {
	sum := sha256.Sum256([]byte(wordlistRaw))
	if hex.EncodeToString(sum[:]) != wordlistSHA256 {
		t.Fatal("wordlist.txt changed; fingerprints would change for everyone")
	}
	if len(words) != WordListSize || WordListSize < 2048 {
		t.Fatalf("have %d words", len(words))
	}
	seen := map[string]bool{}
	for _, w := range words {
		if !regexp.MustCompile(`^[a-z]{3,8}$`).MatchString(w) {
			t.Fatalf("bad word %q", w)
		}
		if seen[w] {
			t.Fatalf("duplicate %q", w)
		}
		seen[w] = true
	}
}

func TestFingerprintBits(t *testing.T) {
	want := 3*math.Log2(WordListSize) + math.Log2(10000)
	if math.Abs(FingerprintBits-want) > 0.01 {
		t.Fatalf("FingerprintBits %v, computed %v", FingerprintBits, want)
	}
}

func newRecipient(t testing.TB) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.Recipient().String()
}

var fpRe = regexp.MustCompile(`^[A-Z]{3,8}-[A-Z]{3,8}-[A-Z]{3,8}-[0-9]{4}$`)

// newSignKey returns a fresh Ed25519 public key in hex.
func newSignKey(t testing.TB) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub)
}

func TestFingerprint(t *testing.T) {
	r1, r2 := newRecipient(t), newRecipient(t)
	sk := newSignKey(t)
	a, err := Fingerprint(r1, sk)
	if err != nil {
		t.Fatal(err)
	}
	if !fpRe.MatchString(a) {
		t.Fatalf("unexpected format %q", a)
	}
	again, _ := Fingerprint(r1, sk)
	if a != again {
		t.Fatal("not deterministic")
	}
	b, _ := Fingerprint(r2, sk)
	if a == b {
		t.Fatalf("two random keys share %q (1 in 3e10; rerun)", a)
	}
	// The fingerprint covers the signing key too: pairing someone's age key
	// with another signing key changes it.
	c, _ := Fingerprint(r1, newSignKey(t))
	if a == c {
		t.Fatalf("signing key not covered by %q", a)
	}
}

// Public test vector (the matching private key was discarded). Pins the
// derivation: scrypt parameters, bit split, upper-casing. The signing key
// is the Ed25519 public key of a fixed, published seed (all bytes 7), so no
// key-like constant sits in the repository.
const (
	knownRecipient   = "age1kcxhuxclcv3a27xa5planrvg5444lzwcchw4d5xeu4zzvj86ts7qsp93hz"
	knownFingerprint = "OBTAIN-MORNING-AMUSED-7560"
)

var knownSignKey = hex.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize)).Public().(ed25519.PublicKey))

func TestFingerprintKnownAnswer(t *testing.T) {
	got, err := Fingerprint(knownRecipient, knownSignKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != knownFingerprint {
		t.Fatalf("fingerprint derivation changed: got %q", got)
	}
}

func TestFingerprintRejectsBadRecipients(t *testing.T) {
	good := newRecipient(t)
	for name, in := range map[string]string{
		"empty":     "",
		"garbage":   "hello",
		"upper":     strings.ToUpper(good),
		"truncated": good[:len(good)-3],
		"plugin":    "age1yubikey1qfakefakefake",
		"space":     good + " ",
	} {
		if _, err := Fingerprint(in, knownSignKey); !errors.Is(err, ErrInvalidRecipient) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for _, bad := range []string{"", "xyz", strings.ToUpper(knownSignKey), knownSignKey[:62]} {
		if _, err := Fingerprint(good, bad); !errors.Is(err, ErrInvalidRecipient) {
			t.Errorf("sign key %q: err = %v", bad, err)
		}
	}
}

func TestFingerprintComparison(t *testing.T) {
	for _, typed := range []string{"  maple-river-otter-4417\n", "maple river otter 4417", "Maple.River.Otter.4417", "MAPLE--RIVER  OTTER-4417"} {
		if NormalizeFingerprint(typed) != "MAPLE-RIVER-OTTER-4417" {
			t.Fatalf("normalize %q = %q", typed, NormalizeFingerprint(typed))
		}
	}
	if !FingerprintsEqual("MAPLE-RIVER-OTTER-4417", "MAPLE-RIVER-OTTER-4417") {
		t.Fatal("equal")
	}
	for _, other := range []string{"", "MAPLE-RIVER-OTTER-4418", "MAPLE-RIVER-4417", "MAPLE-RIVER-OTTER", "MAPLE-RIVER-OTTER-4417 ", "maple-river-otter-4417", "MAPLE-RIVER-OTTER-44171"} {
		if FingerprintsEqual("MAPLE-RIVER-OTTER-4417", other) {
			t.Errorf("%q equal", other)
		}
	}
	if FingerprintsEqual("", "") {
		t.Fatal("two empty fingerprints must not match")
	}
}

func FuzzFingerprint(f *testing.F) {
	f.Add(newRecipient(f), newSignKey(f))
	f.Add("age1", "")
	f.Add("", "00")
	f.Fuzz(func(t *testing.T, s, k string) {
		fp, err := Fingerprint(s, k)
		if err == nil && !fpRe.MatchString(fp) {
			t.Fatalf("bad fingerprint %q", fp)
		}
		if err != nil && len(s) > 12 && strings.Contains(err.Error(), s) {
			t.Fatal("error echoes input")
		}
	})
}

func TestCheckFingerprintFormat(t *testing.T) {
	good := "EMPLOY-WRITE-LOAD-4806"
	if err := CheckFingerprintFormat(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "MAPLE-RIVER-4417", "DUTCH-PREDICT-1767", "maple-river-otter-4417", "MAPLE-RIVER-OTTER-441", "MAPLE-RIVER-OTTER-44a7", "MAPLE-RIVER-ZZZZ-4417", "MAPLE-RIVER-OTTER-4417-1", " MAPLE-RIVER-OTTER-4417"} {
		if err := CheckFingerprintFormat(bad); !errors.Is(err, ErrFingerprintFormat) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// Real fingerprints always pass.
	fp, _ := Fingerprint(newRecipient(t), newSignKey(t))
	if err := CheckFingerprintFormat(fp); err != nil {
		t.Fatal(err)
	}
}
