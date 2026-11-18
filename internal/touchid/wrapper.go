package touchid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// Wrapped key layout (format.Unlocker.WrappedKey), version 1:
//
//	version (1 byte, 0x01)
//	ephemeral P-256 public key, uncompressed (65 bytes)
//	AES-256-GCM nonce (12 bytes)
//	AES-256-GCM ciphertext of the 32-byte vault key + tag (48 bytes)
//
// The wrapping key is HKDF-SHA256 over the ECDH secret of the ephemeral key
// and the enclave key, salt = ephemeral pub || enclave pub, info = wrapInfo.
// The same label is the GCM additional data. Recipient in vault.json is
// recipientPrefix + base64 (no padding) of the enclave public key.
const (
	wrapVersion     = 0x01
	pubKeyLen       = 65
	nonceLen        = 12
	tagLen          = 16
	wrappedLen      = 1 + pubKeyLen + nonceLen + crypto.KeySize + tagLen
	wrapInfo        = "secrets-vault/touchid/v1"
	recipientPrefix = "touchid-p256:"
)

// keyWrapper implements crypto.KeyWrapper for one enrolled device.
type keyWrapper struct {
	e      enclave
	getenv func(string) string
	label  string
	blob   []byte
	pub    []byte
	vault  string
}

var _ crypto.KeyWrapper = (*keyWrapper)(nil)

func (w *keyWrapper) Type() format.UnlockerType { return format.UnlockerTouchID }

// Recipient returns the public identifier stored in vault.json.
func (w *keyWrapper) recipient() string {
	return recipientPrefix + base64.RawStdEncoding.EncodeToString(w.pub)
}

// Wrap encrypts key to the enclave public key. It needs no Touch ID.
func (w *keyWrapper) Wrap(key *crypto.VaultKey) (format.Unlocker, error) {
	if key == nil {
		return format.Unlocker{}, errors.New("touchid: no vault key to wrap")
	}
	sePub, err := parsePublicKey(w.pub)
	if err != nil {
		return format.Unlocker{}, errors.New("touchid: enclave public key is invalid")
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return format.Unlocker{}, errors.New("touchid: could not generate ephemeral key")
	}
	shared, err := eph.ECDH(sePub)
	if err != nil {
		return format.Unlocker{}, errors.New("touchid: key agreement failed")
	}
	defer clear(shared)
	ephPub := eph.PublicKey().Bytes()
	aead, err := wrapAEAD(shared, ephPub, w.pub)
	if err != nil {
		return format.Unlocker{}, err
	}
	out := make([]byte, 1+pubKeyLen+nonceLen, wrappedLen)
	out[0] = wrapVersion
	copy(out[1:], ephPub)
	nonce := out[1+pubKeyLen:]
	if _, err := rand.Read(nonce); err != nil {
		return format.Unlocker{}, errors.New("touchid: could not generate nonce")
	}
	out = aead.Seal(out, nonce, key.Bytes(), []byte(wrapInfo))
	return format.Unlocker{
		Type:       format.UnlockerTouchID,
		Label:      w.label,
		Recipient:  w.recipient(),
		WrappedKey: out,
		Created:    time.Now().UTC(),
	}, nil
}

// Unwrap shows the Touch ID sheet and opens u. A cancelled sheet returns
// ErrCancelled; Touch ID becoming unusable (SSH, sensor gone) returns
// ErrUnsupported; every other failure returns crypto.ErrWrongKey.
func (w *keyWrapper) Unwrap(u format.Unlocker) (*crypto.VaultKey, error) {
	if u.Type != format.UnlockerTouchID {
		return nil, crypto.ErrWrongKey
	}
	// A different Mac's (or a re-enrolled) key: don't bother the user.
	if subtle.ConstantTimeCompare([]byte(u.Recipient), []byte(w.recipient())) != 1 {
		return nil, crypto.ErrWrongKey
	}
	ephPub, nonce, sealed, err := parseWrapped(u.WrappedKey)
	if err != nil {
		return nil, crypto.ErrWrongKey
	}
	if sshSession(w.getenv) {
		return nil, ErrUnsupported
	}
	shared, err := w.e.agree(w.blob, ephPub, unlockReason(w.vault, w.e.parentProgram()))
	switch {
	case err == nil:
	case errors.Is(err, ErrCancelled):
		return nil, ErrCancelled
	case errors.Is(err, ErrUnsupported):
		return nil, ErrUnsupported
	default:
		return nil, crypto.ErrWrongKey
	}
	defer clear(shared)
	aead, err := wrapAEAD(shared, ephPub, w.pub)
	if err != nil {
		return nil, crypto.ErrWrongKey
	}
	plain, err := aead.Open(nil, nonce, sealed, []byte(wrapInfo))
	if err != nil {
		return nil, crypto.ErrWrongKey
	}
	defer clear(plain)
	key, err := crypto.VaultKeyFromBytes(plain)
	if err != nil {
		return nil, crypto.ErrWrongKey
	}
	return key, nil
}

// parseWrapped splits a version-1 wrapped key. It accepts exactly one
// layout and length, and checks the ephemeral key is a valid curve point.
func parseWrapped(b []byte) (ephPub, nonce, sealed []byte, err error) {
	if len(b) != wrappedLen || b[0] != wrapVersion {
		return nil, nil, nil, errors.New("touchid: malformed wrapped key")
	}
	ephPub = b[1 : 1+pubKeyLen]
	if _, err := parsePublicKey(ephPub); err != nil {
		return nil, nil, nil, errors.New("touchid: malformed wrapped key")
	}
	nonce = b[1+pubKeyLen : 1+pubKeyLen+nonceLen]
	sealed = b[1+pubKeyLen+nonceLen:]
	return ephPub, nonce, sealed, nil
}

func parsePublicKey(b []byte) (*ecdh.PublicKey, error) {
	if len(b) != pubKeyLen || b[0] != 0x04 {
		return nil, errors.New("touchid: not an uncompressed P-256 point")
	}
	return ecdh.P256().NewPublicKey(b)
}

func wrapAEAD(shared, ephPub, sePub []byte) (cipher.AEAD, error) {
	salt := make([]byte, 0, 2*pubKeyLen)
	salt = append(append(salt, ephPub...), sePub...)
	k, err := hkdf.Key(sha256.New, shared, salt, wrapInfo, 32)
	if err != nil {
		return nil, errors.New("touchid: key derivation failed")
	}
	defer clear(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, errors.New("touchid: cipher setup failed")
	}
	return cipher.NewGCM(block)
}

// maxReasonPart bounds each name shown on the Touch ID sheet.
const maxReasonPart = 48

// unlockReason is the text on the Touch ID sheet. macOS shows it as
// "<this program> is trying to <reason>." Names come from local config and
// the process table; they are cleaned so they can't spoof extra lines.
func unlockReason(vault, program string) string {
	vault, program = cleanName(vault), cleanName(program)
	var b strings.Builder
	b.WriteString("unlock ")
	if vault != "" {
		b.WriteString("the \u201c" + vault + "\u201d vault")
	} else {
		b.WriteString("a vault")
	}
	if program != "" {
		b.WriteString(" for " + program)
	}
	return b.String()
}

func cleanName(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxReasonPart {
			b.WriteRune('\u2026')
			break
		}
		switch {
		case unicode.IsSpace(r):
			r = ' ' // newlines and tabs become plain spaces
		case r == unicode.ReplacementChar, unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			continue // control, bidi and other invisible formatting runes
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}
