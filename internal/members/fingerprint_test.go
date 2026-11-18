package members

import (
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
	want := 2*math.Log2(WordListSize) + math.Log2(10000)
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

var fpRe = regexp.MustCompile(`^[A-Z]{3,8}-[A-Z]{3,8}-[0-9]{4}$`)

func TestFingerprint(t *testing.T) {
	r1, r2 := newRecipient(t), newRecipient(t)
	a, err := Fingerprint(r1)
	if err != nil {
		t.Fatal(err)
	}
	if !fpRe.MatchString(a) {
		t.Fatalf("unexpected format %q", a)
	}
	again, _ := Fingerprint(r1)
	if a != again {
		t.Fatal("not deterministic")
	}
	b, _ := Fingerprint(r2)
	if a == b {
		t.Fatalf("two random keys share %q (1 in 3e10; rerun)", a)
	}
}

// Public test vector (the matching private key was discarded). Pins the
// derivation: scrypt parameters, bit split, upper-casing.
const (
	knownRecipient   = "age1kcxhuxclcv3a27xa5planrvg5444lzwcchw4d5xeu4zzvj86ts7qsp93hz"
	knownFingerprint = "DUTCH-PREDICT-1767"
)

func TestFingerprintKnownAnswer(t *testing.T) {
	got, err := Fingerprint(knownRecipient)
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
		if _, err := Fingerprint(in); !errors.Is(err, ErrInvalidRecipient) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestFingerprintComparison(t *testing.T) {
	if NormalizeFingerprint("  maple-river-4417\n") != "MAPLE-RIVER-4417" {
		t.Fatal("normalize")
	}
	if !FingerprintsEqual("MAPLE-RIVER-4417", "MAPLE-RIVER-4417") {
		t.Fatal("equal")
	}
	for _, other := range []string{"", "MAPLE-RIVER-4418", "MAPLE-RIVER", "MAPLE-RIVER-4417 ", "maple-river-4417", "MAPLE-RIVER-44171"} {
		if FingerprintsEqual("MAPLE-RIVER-4417", other) {
			t.Errorf("%q equal", other)
		}
	}
	if FingerprintsEqual("", "") {
		t.Fatal("two empty fingerprints must not match")
	}
}

func FuzzFingerprint(f *testing.F) {
	f.Add(newRecipient(f))
	f.Add("age1")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		fp, err := Fingerprint(s)
		if err == nil && !fpRe.MatchString(fp) {
			t.Fatalf("bad fingerprint %q", fp)
		}
		if err != nil && len(s) > 12 && strings.Contains(err.Error(), s) {
			t.Fatal("error echoes input")
		}
	})
}
