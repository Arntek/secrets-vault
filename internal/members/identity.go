package members

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
)

// Identity file layout. The private key is sealed (crypto.Sealer, name
// IDENTITY) under a random identity key, and that key is wrapped once per
// unlocker in Unlockers, the same shape as vault.json. Adding Touch ID later
// is AddUnlocker with a touchid wrapper; the sealed key is never rewritten.
const (
	identityFileName = "identity.json"
	identityVersion  = 1
	kindIdentity     = "identity"
	kindExport       = "identity-export"
	identitySealName = "IDENTITY"
	maxIdentityFile  = 64 << 10
	maxIdentityLocks = 8
	maxSealedLen     = 4096
)

type identityFile struct {
	Version   int               `json:"version"`
	Kind      string            `json:"kind"`
	Name      string            `json:"name"`
	Recipient string            `json:"recipient"`
	Created   time.Time         `json:"created"`
	KeyID     string            `json:"key_id"`
	Sealed    []byte            `json:"sealed"`
	Unlockers []format.Unlocker `json:"unlockers"`
}

// ParseIdentityFile strictly parses a stored identity or an export file
// (it checks structure only; unlocking is separate). Exposed for fuzzing.
func ParseIdentityFile(data []byte) error {
	_, err := parseIdentityFile(data, "")
	return err
}

// parseIdentityFile parses data; wantKind "" accepts either kind.
func parseIdentityFile(data []byte, wantKind string) (*identityFile, error) {
	var f identityFile
	if err := decodeStrict(data, maxIdentityFile, &f); err != nil {
		return nil, err
	}
	if f.Version != identityVersion {
		return nil, fmt.Errorf("%w: unsupported version", ErrMalformed)
	}
	if f.Kind != kindIdentity && f.Kind != kindExport {
		return nil, fmt.Errorf("%w: unknown kind", ErrMalformed)
	}
	if wantKind != "" && f.Kind != wantKind {
		return nil, fmt.Errorf("%w: wrong kind of identity file", ErrMalformed)
	}
	if err := ValidateMemberName(f.Name); err != nil {
		return nil, fmt.Errorf("%w: bad name", ErrMalformed)
	}
	if err := checkRecipient(f.Recipient); err != nil {
		return nil, fmt.Errorf("%w: bad public key", ErrMalformed)
	}
	if f.Created.IsZero() {
		return nil, fmt.Errorf("%w: no created time", ErrMalformed)
	}
	if err := format.ValidateKeyID(f.KeyID); err != nil {
		return nil, fmt.Errorf("%w: bad key id", ErrMalformed)
	}
	if len(f.Sealed) == 0 || len(f.Sealed) > maxSealedLen {
		return nil, fmt.Errorf("%w: bad sealed key", ErrMalformed)
	}
	if len(f.Unlockers) == 0 || len(f.Unlockers) > maxIdentityLocks {
		return nil, fmt.Errorf("%w: bad unlocker list", ErrMalformed)
	}
	for i := range f.Unlockers {
		if f.Unlockers[i].Type == format.UnlockerMember {
			return nil, fmt.Errorf("%w: unlocker type not allowed", ErrMalformed)
		}
		if err := f.Unlockers[i].Validate(); err != nil {
			return nil, fmt.Errorf("%w: bad unlocker", ErrMalformed)
		}
	}
	return &f, nil
}

// checkRecipient requires a valid age X25519 recipient in canonical form.
func checkRecipient(s string) error {
	r, err := age.ParseX25519Recipient(s)
	if err != nil || r.String() != s {
		return ErrInvalidRecipient
	}
	return nil
}

// Store is a directory holding this user's identity.
type Store struct{ dir string }

// DefaultDir returns ~/.config/vault/identity (honouring XDG_CONFIG_HOME).
func DefaultDir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "vault", "identity"), nil
}

// NewStore returns the store in dir. Tests pass a temp folder; the CLI
// passes DefaultDir().
func NewStore(dir string) *Store { return &Store{dir: dir} }

func (s *Store) path() string { return filepath.Join(s.dir, identityFileName) }

// Exists reports whether an identity file is present.
func (s *Store) Exists() bool {
	_, err := os.Lstat(s.path())
	return err == nil
}

// checkPerms refuses a store other users can read (not enforced on Windows,
// where mode bits mean nothing).
func (s *Store) checkPerms() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	di, err := os.Stat(s.dir)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(s.path())
	if err != nil {
		return err
	}
	if di.Mode().Perm()&0o077 != 0 || fi.Mode().Perm()&0o077 != 0 {
		return ErrInsecurePermissions
	}
	return nil
}

func (s *Store) load(kind string) (*identityFile, error) {
	data, err := readSmallFile(s.path(), maxIdentityFile)
	if err != nil {
		if isNotExist(err) {
			return nil, ErrNoIdentity
		}
		return nil, err
	}
	if err := s.checkPerms(); err != nil {
		return nil, err
	}
	return parseIdentityFile(data, kind)
}

func (s *Store) save(f *identityFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, format.DirMode); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(s.dir, format.DirMode); err != nil { // #nosec G302 -- a directory needs the execute bit; 0700 is owner-only
			return err
		}
	}
	return format.WriteFileAtomic(s.path(), append(data, '\n'), format.FileMode)
}

// Public returns the public identity without unlocking anything.
func (s *Store) Public() (Identity, error) {
	f, err := s.load(kindIdentity)
	if err != nil {
		return Identity{}, err
	}
	return publicOf(f)
}

func publicOf(f *identityFile) (Identity, error) {
	fp, err := Fingerprint(f.Recipient)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Name: f.Name, Recipient: f.Recipient, Fingerprint: fp}, nil
}

// Unlocked is an identity whose private key is in memory. It never prints
// its key. Destroy it when done (the underlying age key cannot be zeroed
// but the reference is dropped).
type Unlocked struct {
	Identity
	id *age.X25519Identity
}

// String, GoString and LogValue keep the private key out of logs.
func (u *Unlocked) String() string   { return "Unlocked(redacted)" }
func (u *Unlocked) GoString() string { return u.String() }

// LogValue implements slog.LogValuer.
func (u *Unlocked) LogValue() slog.Value { return slog.StringValue(u.String()) }

// Destroy drops the private key reference.
func (u *Unlocked) Destroy() {
	if u != nil {
		u.id = nil
	}
}

// MemberWrapper returns a crypto.KeyWrapper that can wrap and unwrap vault
// keys as this person (the vault's member unlocker for them).
func (u *Unlocked) MemberWrapper() (crypto.KeyWrapper, error) {
	if u == nil || u.id == nil {
		return nil, errors.New("members: identity is not unlocked")
	}
	return crypto.NewMemberIdentityWrapper(u.Name, u.id)
}

// sealIdentity builds an identity file for id protected by wrappers.
func sealIdentity(kind, name string, created time.Time, id *age.X25519Identity, wrappers []crypto.KeyWrapper) (*identityFile, error) {
	if len(wrappers) == 0 {
		return nil, errors.New("members: at least one unlocker is required to protect the identity")
	}
	if len(wrappers) > maxIdentityLocks {
		return nil, errors.New("members: too many unlockers")
	}
	for _, w := range wrappers {
		if w.Type() == format.UnlockerMember {
			return nil, errors.New("members: an identity cannot be protected by a member unlocker")
		}
	}
	key, err := crypto.NewVaultKey()
	if err != nil {
		return nil, err
	}
	defer key.Destroy()
	sealer, err := crypto.NewSealer(identitySealName)
	if err != nil {
		return nil, err
	}
	secret := []byte(id.String())
	defer clear(secret)
	sealed, err := sealer.Seal(key, secret)
	if err != nil {
		return nil, err
	}
	unlockers, err := crypto.WrapAll(key, wrappers)
	if err != nil {
		return nil, err
	}
	return &identityFile{
		Version:   identityVersion,
		Kind:      kind,
		Name:      name,
		Recipient: id.Recipient().String(),
		Created:   created,
		KeyID:     key.ID(),
		Sealed:    sealed,
		Unlockers: unlockers,
	}, nil
}

// identityKey unwraps the identity key of f with w.
func identityKey(f *identityFile, w crypto.KeyWrapper) (*crypto.VaultKey, error) {
	probe := &format.VaultFile{KeyID: f.KeyID}
	for _, u := range f.Unlockers {
		if u.Type != w.Type() {
			continue
		}
		k, err := w.Unwrap(u)
		if err != nil {
			continue
		}
		if crypto.CheckKey(probe, k) == nil {
			return k, nil
		}
		k.Destroy()
	}
	return nil, crypto.ErrWrongKey
}

// openIdentity unlocks f with w. Every failure is crypto.ErrWrongKey, so a
// wrong passphrase and a tampered file look the same.
func openIdentity(f *identityFile, w crypto.KeyWrapper) (*age.X25519Identity, error) {
	key, err := identityKey(f, w)
	if err != nil {
		return nil, err
	}
	defer key.Destroy()
	sealer, err := crypto.NewSealer(identitySealName)
	if err != nil {
		return nil, err
	}
	pt, err := sealer.Open(key, f.Sealed)
	if err != nil {
		return nil, crypto.ErrWrongKey
	}
	defer clear(pt)
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(pt)))
	if err != nil || id.Recipient().String() != f.Recipient {
		return nil, crypto.ErrWrongKey
	}
	return id, nil
}

// Create makes a new identity called name, protected by the given
// unlockers (the personal passphrase wrapper, plus Touch ID later). It fails
// with ErrIdentityExists if one is already stored here.
func (s *Store) Create(name string, wrappers ...crypto.KeyWrapper) (Identity, error) {
	if err := ValidateMemberName(name); err != nil {
		return Identity{}, err
	}
	if s.Exists() {
		return Identity{}, ErrIdentityExists
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return Identity{}, err
	}
	return s.store(kindIdentity, name, id, wrappers)
}

func (s *Store) store(kind, name string, id *age.X25519Identity, wrappers []crypto.KeyWrapper) (Identity, error) {
	f, err := sealIdentity(kind, name, time.Now().UTC().Round(0), id, wrappers)
	if err != nil {
		return Identity{}, err
	}
	pub, err := publicOf(f)
	if err != nil {
		return Identity{}, err
	}
	if err := s.save(f); err != nil {
		return Identity{}, err
	}
	return pub, nil
}

// Unlock opens the identity with w.
func (s *Store) Unlock(w crypto.KeyWrapper) (*Unlocked, error) {
	f, err := s.load(kindIdentity)
	if err != nil {
		return nil, err
	}
	id, err := openIdentity(f, w)
	if err != nil {
		return nil, err
	}
	pub, err := publicOf(f)
	if err != nil {
		return nil, err
	}
	return &Unlocked{Identity: pub, id: id}, nil
}

// AddUnlocker adds (or replaces, for the passphrase or the same device) an
// unlocker of the identity, authorised by current. Use it to add Touch ID or
// to change the personal passphrase. The sealed private key is untouched.
func (s *Store) AddUnlocker(current, add crypto.KeyWrapper) error {
	f, err := s.load(kindIdentity)
	if err != nil {
		return err
	}
	key, err := identityKey(f, current)
	if err != nil {
		return err
	}
	defer key.Destroy()
	if add.Type() == format.UnlockerMember {
		return errors.New("members: an identity cannot be protected by a member unlocker")
	}
	u, err := add.Wrap(key)
	if err != nil {
		return fmt.Errorf("members: wrapping the identity key: %w", err)
	}
	vf := &format.VaultFile{Unlockers: f.Unlockers}
	vf.SetUnlocker(u)
	if len(vf.Unlockers) > maxIdentityLocks {
		return errors.New("members: too many unlockers")
	}
	f.Unlockers = vf.Unlockers
	return s.save(f)
}

// Export returns the identity as a file protected only by protect (a
// passphrase wrapper chosen for the transfer), for moving to a second Mac.
// unlock opens the stored identity. The result holds the private key, so
// the caller writes it with mode 0600 and deletes it after importing.
func (s *Store) Export(unlock, protect crypto.KeyWrapper) ([]byte, error) {
	f, err := s.load(kindIdentity)
	if err != nil {
		return nil, err
	}
	id, err := openIdentity(f, unlock)
	if err != nil {
		return nil, err
	}
	ef, err := sealIdentity(kindExport, f.Name, f.Created, id, []crypto.KeyWrapper{protect})
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(ef, "", "  ")
}

// Import stores an identity from export data, opened with from and
// re-protected by wrappers on this machine. It fails with ErrIdentityExists
// if this machine already has one.
func (s *Store) Import(data []byte, from crypto.KeyWrapper, wrappers ...crypto.KeyWrapper) (Identity, error) {
	if s.Exists() {
		return Identity{}, ErrIdentityExists
	}
	ef, err := parseIdentityFile(data, kindExport)
	if err != nil {
		return Identity{}, err
	}
	id, err := openIdentity(ef, from)
	if err != nil {
		return Identity{}, err
	}
	f, err := sealIdentity(kindIdentity, ef.Name, ef.Created, id, wrappers)
	if err != nil {
		return Identity{}, err
	}
	pub, err := publicOf(f)
	if err != nil {
		return Identity{}, err
	}
	if err := s.save(f); err != nil {
		return Identity{}, err
	}
	return pub, nil
}
