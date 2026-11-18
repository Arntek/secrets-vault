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
	"encoding/binary"
	"errors"
	"io"
	"strconv"

	"filippo.io/age"

	"github.com/Arntek/secrets-vault/internal/format"
)

// HKDF info strings. Changing any of them breaks every existing vault.
// Secret files written by this build use the v2 file-key label and stanza
// type (ue1.8): builds from before the membership log can't open them, so
// they can't rotate a version-2 vault even if its vault.json is rewritten
// as version 1. v1 files are still read (migration).
const (
	infoKeyID     = "secrets-vault/v1 key id"
	infoFileKeyV1 = "secrets-vault/v1 secret file key\x00"
	infoFileKey   = "secrets-vault/v2 secret file key\x00"
	infoFileKeyV3 = "secrets-vault/v3 secret file key\x00"
)

// stanzaType is the age recipient stanza type of secret files:
//
//	-> sv-vaultkey2 <key id hex> <salt, 16 bytes, base64 raw std>
//	<AES-256-GCM(file key), zero nonce, under HKDF(vault key, salt, info||name)>
//
// Each file has its own random salt, so each wrapping key is used once and
// the fixed nonce is safe (the same construction age uses for scrypt).
// stanzaTypeV1 ("sv-vaultkey", with infoFileKeyV1) is only read.
//
// Version 3 (docs/design/index-auth.md) adds the file's version number:
//
//	-> sv-vaultkey3 <key id hex> <salt> <version, decimal>
//
// The version is bound into the file key's AES-GCM as associated data and
// covered by age's header MAC. Builds before it can't open these files.
const (
	stanzaType   = "sv-vaultkey2"
	stanzaTypeV1 = "sv-vaultkey"
	stanzaTypeV3 = "sv-vaultkey3"
)

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

// Seal encrypts plaintext as an unversioned age file for key.
func (s *sealer) Seal(key *VaultKey, plaintext []byte) ([]byte, error) {
	return s.seal(key, plaintext, 0)
}

// SealVersion encrypts plaintext as a version-stamped age file for key.
func (s *sealer) SealVersion(key *VaultKey, plaintext []byte, version uint32) ([]byte, error) {
	if version < 1 || version > format.MaxCounter {
		return nil, ErrVersionRange
	}
	return s.seal(key, plaintext, version)
}

func (s *sealer) seal(key *VaultKey, plaintext []byte, version uint32) ([]byte, error) {
	if key == nil {
		return nil, errors.New("crypto: no vault key")
	}
	if len(plaintext) > MaxSecretSize {
		return nil, ErrTooLarge
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, &vaultKeyRecipient{key: key, name: s.name, version: version})
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
	pt, _, err := s.OpenVersion(key, ciphertext)
	return pt, err
}

// OpenVersion is Open that also returns the version in the file's header.
func (s *sealer) OpenVersion(key *VaultKey, ciphertext []byte) ([]byte, uint32, error) {
	if key == nil {
		return nil, 0, ErrDecrypt
	}
	if len(ciphertext) > format.MaxSecretFileSize {
		return nil, 0, ErrDecrypt
	}
	id := &vaultKeyIdentity{key: key, name: s.name}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), id)
	if err != nil {
		if id.otherKey {
			return nil, 0, ErrOtherKey
		}
		return nil, 0, ErrDecrypt
	}
	pt, err := io.ReadAll(io.LimitReader(r, MaxSecretSize+1))
	if err != nil || len(pt) > MaxSecretSize {
		clear(pt)
		return nil, 0, ErrDecrypt
	}
	return pt, id.version, nil
}

// fileKeyWrapper derives the AES-GCM that wraps one file key, with the
// HKDF label of the given stanza type.
func fileKeyWrapper(key *VaultKey, salt []byte, name, typ string) (cipher.AEAD, error) {
	info := infoFileKey
	switch typ {
	case stanzaTypeV1:
		info = infoFileKeyV1
	case stanzaTypeV3:
		info = infoFileKeyV3
	}
	kek, err := hkdf.Key(sha256.New, key.b[:], salt, info+name, 32)
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
	key     *VaultKey
	name    string
	version uint32 // 0: unversioned (stanza v2)
}

func versionAAD(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func (r *vaultKeyRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	typ := stanzaType
	args := []string{r.key.ID(), base64.RawStdEncoding.EncodeToString(salt)}
	var aad []byte
	if r.version != 0 {
		typ = stanzaTypeV3
		args = append(args, strconv.FormatUint(uint64(r.version), 10))
		aad = versionAAD(r.version)
	}
	aead, err := fileKeyWrapper(r.key, salt, r.name, typ)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return []*age.Stanza{{
		Type: typ,
		Args: args,
		Body: aead.Seal(nil, nonce, fileKey, aad), // #nosec G407 -- the key is derived from a fresh random salt and used for this one seal only
	}}, nil
}

// WrapWithLabels makes age refuse to mix this recipient with any other in
// one file, so a secret file never carries a second, weaker way in.
func (r *vaultKeyRecipient) WrapWithLabels(fileKey []byte) ([]*age.Stanza, []string, error) {
	s, err := r.Wrap(fileKey)
	typ := stanzaType
	if r.version != 0 {
		typ = stanzaTypeV3
	}
	return s, []string{typ + "-" + r.key.ID()}, err
}

type vaultKeyIdentity struct {
	key      *VaultKey
	name     string
	otherKey bool // set when the only stanza names a different key ID
	version  uint32
}

var errBadStanza = errors.New("crypto: malformed secret file header")

func (i *vaultKeyIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(stanzas) != 1 {
		return nil, errBadStanza
	}
	s := stanzas[0]
	if s.Type != stanzaType && s.Type != stanzaTypeV1 && s.Type != stanzaTypeV3 {
		return nil, age.ErrIncorrectIdentity
	}
	want := 2
	if s.Type == stanzaTypeV3 {
		want = 3
	}
	if len(s.Args) != want {
		return nil, errBadStanza
	}
	var aad []byte
	var version uint32
	if s.Type == stanzaTypeV3 {
		v, err := parseVersionArg(s.Args[2])
		if err != nil {
			return nil, errBadStanza
		}
		version, aad = v, versionAAD(v)
	}
	if subtle.ConstantTimeCompare([]byte(s.Args[0]), []byte(i.key.ID())) != 1 {
		i.otherKey = true
		return nil, age.ErrIncorrectIdentity
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[1])
	if err != nil || len(salt) != saltSize {
		return nil, errBadStanza
	}
	aead, err := fileKeyWrapper(i.key, salt, i.name, s.Type)
	if err != nil {
		return nil, err
	}
	if len(s.Body) != fileKeySize+aead.Overhead() {
		return nil, errBadStanza
	}
	fileKey, err := aead.Open(nil, make([]byte, aead.NonceSize()), s.Body, aad)
	if err != nil {
		return nil, age.ErrIncorrectIdentity
	}
	i.version = version
	return fileKey, nil
}

// ErrVersionRange is returned for a secret-file version outside
// 1..format.MaxCounter.
var ErrVersionRange = errors.New("crypto: secret version out of range")

// parseVersionArg parses the canonical decimal version of a v3 stanza.
func parseVersionArg(a string) (uint32, error) {
	if a == "" || (len(a) > 1 && a[0] == '0') || len(a) > 10 {
		return 0, errBadStanza
	}
	n, err := strconv.ParseUint(a, 10, 32)
	if err != nil || n < 1 || n > format.MaxCounter {
		return 0, errBadStanza
	}
	return uint32(n), nil
}
