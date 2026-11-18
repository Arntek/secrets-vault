package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"

	"filippo.io/age"

	"github.com/Arntek/secrets-vault/internal/format"
)

// HKDF info strings. Changing any of them breaks every existing vault.
const (
	infoKeyID   = "secrets-vault/v1 key id"
	infoFileKey = "secrets-vault/v1 secret file key\x00"
)

// stanzaType is the age recipient stanza type of secret files:
//
//	-> sv-vaultkey <key id hex> <salt, 16 bytes, base64 raw std>
//	<AES-256-GCM(file key), zero nonce, under HKDF(vault key, salt, info||name)>
//
// Each file has its own random salt, so each wrapping key is used once and
// the fixed nonce is safe (the same construction age uses for scrypt).
const stanzaType = "sv-vaultkey"

const (
	saltSize    = 16
	fileKeySize = 16 // age file keys
)

// NewSealer returns a Sealer for the secret called name. The name is bound
// into the encryption: a file sealed for one name fails to open as another,
// so swapping secrets/A.age and secrets/B.age is detected.
func NewSealer(name string) (Sealer, error) {
	if err := format.ValidateKeyName(name); err != nil {
		return nil, err
	}
	return &sealer{name: name}, nil
}

type sealer struct{ name string }

// Seal encrypts plaintext as an age file for key.
func (s *sealer) Seal(key *VaultKey, plaintext []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("crypto: no vault key")
	}
	if len(plaintext) > MaxSecretSize {
		return nil, ErrTooLarge
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, &vaultKeyRecipient{key: key, name: s.name})
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Open decrypts an age file sealed by Seal for the same key and name. The
// whole file is authenticated before any plaintext is returned. Every
// failure returns ErrDecrypt (or ErrOtherKey, which wraps it).
func (s *sealer) Open(key *VaultKey, ciphertext []byte) ([]byte, error) {
	if key == nil {
		return nil, ErrDecrypt
	}
	if len(ciphertext) > format.MaxSecretFileSize {
		return nil, ErrDecrypt
	}
	id := &vaultKeyIdentity{key: key, name: s.name}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		if id.otherKey {
			return nil, ErrOtherKey
		}
		return nil, ErrDecrypt
	}
	pt, err := io.ReadAll(io.LimitReader(r, MaxSecretSize+1))
	if err != nil || len(pt) > MaxSecretSize {
		clear(pt)
		return nil, ErrDecrypt
	}
	return pt, nil
}

// fileKeyWrapper derives the AES-GCM that wraps one file key.
func fileKeyWrapper(key *VaultKey, salt []byte, name string) (cipher.AEAD, error) {
	kek, err := hkdf.Key(sha256.New, key.b[:], salt, infoFileKey+name, 32)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type vaultKeyRecipient struct {
	key  *VaultKey
	name string
}

func (r *vaultKeyRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aead, err := fileKeyWrapper(r.key, salt, r.name)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return []*age.Stanza{{
		Type: stanzaType,
		Args: []string{r.key.ID(), base64.RawStdEncoding.EncodeToString(salt)},
		Body: aead.Seal(nil, nonce, fileKey, nil), // #nosec G407 -- the key is derived from a fresh random salt and used for this one seal only

	}}, nil
}

// WrapWithLabels makes age refuse to mix this recipient with any other in
// one file, so a secret file never carries a second, weaker way in.
func (r *vaultKeyRecipient) WrapWithLabels(fileKey []byte) ([]*age.Stanza, []string, error) {
	s, err := r.Wrap(fileKey)
	return s, []string{stanzaType + "-" + r.key.ID()}, err
}

type vaultKeyIdentity struct {
	key      *VaultKey
	name     string
	otherKey bool // set when the only stanza names a different key ID
}

var errBadStanza = errors.New("crypto: malformed secret file header")

func (i *vaultKeyIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(stanzas) != 1 {
		return nil, errBadStanza
	}
	s := stanzas[0]
	if s.Type != stanzaType {
		return nil, age.ErrIncorrectIdentity
	}
	if len(s.Args) != 2 {
		return nil, errBadStanza
	}
	if subtle.ConstantTimeCompare([]byte(s.Args[0]), []byte(i.key.ID())) != 1 {
		i.otherKey = true
		return nil, age.ErrIncorrectIdentity
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[1])
	if err != nil || len(salt) != saltSize {
		return nil, errBadStanza
	}
	aead, err := fileKeyWrapper(i.key, salt, i.name)
	if err != nil {
		return nil, err
	}
	if len(s.Body) != fileKeySize+aead.Overhead() {
		return nil, errBadStanza
	}
	fileKey, err := aead.Open(nil, make([]byte, aead.NonceSize()), s.Body, nil)
	if err != nil {
		return nil, age.ErrIncorrectIdentity
	}
	return fileKey, nil
}
