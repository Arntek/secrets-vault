package crypto

import (
	"bytes"
	"errors"
	"io"
	"time"

	"filippo.io/age"

	"github.com/Arntek/secrets-vault/internal/format"
)

// scrypt work factors (log2 of N) for the passphrase unlocker.
const (
	// DefaultScryptWorkFactor is used for every passphrase in production
	// (about a second on a current Mac).
	DefaultScryptWorkFactor = 18
	// MinScryptWorkFactor is the lowest accepted; only tests should go
	// below DefaultScryptWorkFactor.
	MinScryptWorkFactor = 10
	// MaxScryptWorkFactor bounds what Unwrap will compute, so a tampered
	// vault.json cannot make an unlock attempt run for minutes.
	MaxScryptWorkFactor = 20
)

// NewPassphraseWrapper returns the scrypt passphrase KeyWrapper. The
// passphrase is copied; the caller should zero its slice. The returned
// wrapper also has a Destroy method that zeroes its copy.
//
// age takes the passphrase as a Go string, which cannot be zeroed, so a
// copy lives in memory until the garbage collector reuses it.
func NewPassphraseWrapper(passphrase []byte) (KeyWrapper, error) {
	return NewPassphraseWrapperWithWorkFactor(passphrase, DefaultScryptWorkFactor)
}

// NewPassphraseWrapperWithWorkFactor is NewPassphraseWrapper with an
// explicit scrypt work factor for Wrap, for tests that cannot afford the
// default. Unwrap honours whatever factor the stored unlocker used, up to
// MaxScryptWorkFactor.
func NewPassphraseWrapperWithWorkFactor(passphrase []byte, logN int) (KeyWrapper, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("crypto: empty passphrase")
	}
	if logN < MinScryptWorkFactor || logN > MaxScryptWorkFactor {
		return nil, errors.New("crypto: scrypt work factor out of range")
	}
	return &passphraseWrapper{pass: bytes.Clone(passphrase), logN: logN}, nil
}

type passphraseWrapper struct {
	pass []byte
	logN int
}

func (w *passphraseWrapper) Type() format.UnlockerType { return format.UnlockerPassphrase }

// Destroy zeroes the wrapper's copy of the passphrase.
func (w *passphraseWrapper) Destroy() { clear(w.pass) }

func (w *passphraseWrapper) Wrap(key *VaultKey) (format.Unlocker, error) {
	r, err := age.NewScryptRecipient(string(w.pass))
	if err != nil {
		return format.Unlocker{}, errors.New("crypto: cannot use passphrase")
	}
	r.SetWorkFactor(w.logN)
	wrapped, err := wrapAge(r, key)
	if err != nil {
		return format.Unlocker{}, err
	}
	return format.Unlocker{Type: format.UnlockerPassphrase, WrappedKey: wrapped, Created: now()}, nil
}

func (w *passphraseWrapper) Unwrap(u format.Unlocker) (*VaultKey, error) {
	if u.Type != format.UnlockerPassphrase {
		return nil, ErrWrongKey
	}
	id, err := age.NewScryptIdentity(string(w.pass))
	if err != nil {
		return nil, ErrWrongKey
	}
	id.SetMaxWorkFactor(MaxScryptWorkFactor)
	return unwrapAge(id, u.WrappedKey)
}

// NewMemberWrapper returns a wrap-only KeyWrapper for a member's age X25519
// recipient ("age1..."), used when adding or rewrapping for a member whose
// private identity is not on this machine. Its Unwrap always fails.
func NewMemberWrapper(label, recipient string) (KeyWrapper, error) {
	if label == "" {
		return nil, errors.New("crypto: member wrapper needs a label")
	}
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, errors.New("crypto: invalid member recipient")
	}
	return &memberWrapper{label: label, recipient: r}, nil
}

// NewMemberIdentityWrapper returns a member KeyWrapper that can also unwrap,
// from this member's own age X25519 identity.
func NewMemberIdentityWrapper(label string, identity *age.X25519Identity) (KeyWrapper, error) {
	if label == "" {
		return nil, errors.New("crypto: member wrapper needs a label")
	}
	if identity == nil {
		return nil, errors.New("crypto: no member identity")
	}
	return &memberWrapper{label: label, recipient: identity.Recipient(), identity: identity}, nil
}

type memberWrapper struct {
	label     string
	recipient *age.X25519Recipient
	identity  *age.X25519Identity
}

func (w *memberWrapper) Type() format.UnlockerType { return format.UnlockerMember }

func (w *memberWrapper) Wrap(key *VaultKey) (format.Unlocker, error) {
	wrapped, err := wrapAge(w.recipient, key)
	if err != nil {
		return format.Unlocker{}, err
	}
	return format.Unlocker{
		Type:       format.UnlockerMember,
		Label:      w.label,
		Recipient:  w.recipient.String(),
		WrappedKey: wrapped,
		Created:    now(),
	}, nil
}

func (w *memberWrapper) Unwrap(u format.Unlocker) (*VaultKey, error) {
	// Skip unlockers for other members without doing any work.
	if w.identity == nil || u.Type != format.UnlockerMember || u.Recipient != w.recipient.String() {
		return nil, ErrWrongKey
	}
	return unwrapAge(w.identity, u.WrappedKey)
}

// wrappedKeyMarker starts the plaintext of every wrapped key this build
// writes (ue1.8). Builds from before the membership log expect exactly the
// 32 key bytes, so they can't unwrap a key from a version-2 vault even if a
// folder writer rewrites its vault.json as version 1: an old build gets
// nothing to unlock, and so nothing to re-wrap for a planted unlocker.
const wrappedKeyMarker = "secrets-vault/v2 wrapped key\x00"

// wrapAge encrypts the marked vault key as an age file to r.
func wrapAge(r age.Recipient, key *VaultKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("crypto: no vault key")
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	pt := append([]byte(wrappedKeyMarker), key.b[:]...)
	defer clear(pt)
	if _, err := w.Write(pt); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// unwrapAge opens a wrapped vault key: the marked form, or the bare 32
// bytes of earlier versions (version-1 vaults being migrated, identity
// files from before). Every failure is ErrWrongKey.
func unwrapAge(id age.Identity, wrapped []byte) (*VaultKey, error) {
	if len(wrapped) == 0 || len(wrapped) > format.MaxWrappedKeyLen {
		return nil, ErrWrongKey
	}
	r, err := age.Decrypt(bytes.NewReader(wrapped), id)
	if err != nil {
		return nil, ErrWrongKey
	}
	// ReadAll returns a nil error only at a clean, authenticated EOF.
	b, err := io.ReadAll(io.LimitReader(r, int64(len(wrappedKeyMarker)+KeySize+1)))
	defer clear(b)
	if err != nil {
		return nil, ErrWrongKey
	}
	switch {
	case len(b) == len(wrappedKeyMarker)+KeySize && string(b[:len(wrappedKeyMarker)]) == wrappedKeyMarker:
		b = b[len(wrappedKeyMarker):]
	case len(b) == KeySize:
	default:
		return nil, ErrWrongKey
	}
	k := &VaultKey{}
	copy(k.b[:], b)
	return k, nil
}

func now() time.Time { return time.Now().UTC().Round(0) }
