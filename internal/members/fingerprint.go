package members

import (
	_ "embed" // wordlist.txt
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"filippo.io/age"
	"golang.org/x/crypto/scrypt"
)

// wordlistRaw is the BIP-39 English word list: 2048 plain words, each
// unique in its first four letters, none a prefix of another. (Same list
// age uses for its suggested passphrases; MIT-licensed, public domain in
// practice.) It is committed so fingerprints never change under a
// dependency update; TestWordList pins its SHA-256.
//
//go:embed wordlist.txt
var wordlistRaw string

var words = func() []string {
	w := strings.Fields(wordlistRaw)
	if len(w) != WordListSize {
		panic("members: word list must have exactly 2048 words")
	}
	return w
}()

// Fingerprint parameters.
const (
	// WordListSize is the number of words: 11 bits each.
	WordListSize = 2048
	// FingerprintBits is the entropy of a fingerprint: two words (11 bits
	// each) and a four-digit number (log2(10000) = 13.29 bits).
	FingerprintBits = 22 + 13.29

	fpDomain = "secrets-vault/v1 member fingerprint\x00"
	fpSalt   = "secrets-vault/v1 fingerprint salt"
	// scrypt cost: ~16 MiB and ~30 ms per fingerprint. Only 35 bits long, so
	// we make each guess expensive: forging a second key with the same
	// fingerprint takes about 2^35 key generations *and* fingerprints,
	// which is decades of CPU time instead of days.
	fpN = 1 << 15
	fpR = 8
	fpP = 1
)

// Fingerprint derives the human-readable fingerprint of an age X25519
// recipient: WORD-WORD-NNNN, e.g. MAPLE-RIVER-4417.
//
// It is the scrypt hash of the canonical recipient string, split into 11
// bits (word), 11 bits (word) and a number below 10000, so it carries about
// 35 bits. That is enough to catch a swapped or mistyped key when two people
// read it to each other once, at the moment of approval. It is not a
// long-term identifier, and the scrypt cost is there so that an attacker who
// can write to the shared folder cannot grind a lookalike key before the
// approver has compared the words.
//
// The recipient must be a valid age X25519 recipient in canonical (lower
// case) form.
func Fingerprint(recipient string) (string, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil || r.String() != recipient {
		return "", ErrInvalidRecipient
	}
	if fp, ok := fpCache.get(recipient); ok {
		return fp, nil
	}
	fp, err := computeFingerprint(recipient)
	if err == nil {
		fpCache.put(recipient, fp)
	}
	return fp, err
}

// fpCache remembers recent fingerprints (public data) so listing members
// does not repeat the scrypt work. Bounded, so a flood of requests cannot
// grow it.
var fpCache = &fpMemo{m: map[string]string{}}

type fpMemo struct {
	mu sync.Mutex
	m  map[string]string
}

func (c *fpMemo) get(k string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[k]
	return v, ok
}

func (c *fpMemo) put(k, v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= 256 {
		clear(c.m)
	}
	c.m[k] = v
}

func computeFingerprint(recipient string) (string, error) {
	dk, err := scrypt.Key([]byte(fpDomain+recipient), []byte(fpSalt), fpN, fpR, fpP, 8)
	if err != nil {
		return "", fmt.Errorf("members: fingerprint: %w", err)
	}
	v := binary.BigEndian.Uint64(dk)
	w1 := words[v>>53]
	w2 := words[(v>>42)&0x7ff]
	n := (v & 0xffffffff) % 10000
	return fmt.Sprintf("%s-%s-%04d", strings.ToUpper(w1), strings.ToUpper(w2), n), nil
}

// NormalizeFingerprint trims space and upper-cases what a person typed, so
// "maple-river-4417 " compares equal to the real fingerprint. Nothing else
// is forgiven: every word and digit must match.
func NormalizeFingerprint(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// FingerprintsEqual compares two fingerprints exactly.
func FingerprintsEqual(a, b string) bool { return a != "" && a == b }
