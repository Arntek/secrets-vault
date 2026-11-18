package members

import (
	"crypto/ed25519"
	"encoding/hex"
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

// Identity file layout. The age private key and the Ed25519 signing seed
// are sealed (crypto.Sealer, names IDENTITY and SIGNING) under a random
// identity key, and that key is wrapped once per unlocker in Unlockers, the
// same shape as vault.json. Adding Touch ID later is AddUnlocker with a
// touchid wrapper; the sealed keys are never rewritten. Version 1 files
// have no signing key; one is added the first time they are unlocked.
const (
	identityFileName = "identity.json"
	identityVersion  = 2
	signSealName     = "SIGNING"
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
	SignKey   string            `json:"sign_key,omitempty"`
	SealedSig []byte            `json:"sealed_sign,omitempty"`
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
	switch f.Version {
	case 1:
		if f.SignKey != "" || f.SealedSig != nil {
			return nil, fmt.Errorf("%w: version 1 has no signing key", ErrMalformed)
		}
	case identityVersion:
		if checkSignKey(f.SignKey) != nil || len(f.SealedSig) == 0 || len(f.SealedSig) > maxSealedLen {
			return nil, fmt.Errorf("%w: bad signing key", ErrMalformed)
		}
	default:
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

// checkSignKey requires a 64-character lower-case hex Ed25519 public key.
func checkSignKey(s string) error {
	if len(s) != 2*ed25519.PublicKeySize {
		return ErrInvalidRecipient
	}
	b, err := hex.DecodeString(s)
	if err != nil || hex.EncodeToString(b) != s {
		return ErrInvalidRecipient
	}
	return nil
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

// DefaultDir returns ~/.config/vault/identity (honouring XDG_CONFIG_HOME;
// %LOCALAPPDATA%\vault\identity on Windows).
func DefaultDir() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" && runtime.GOOS == "windows" {
		base = os.Getenv("LOCALAPPDATA")
	}
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if runtime.GOOS == "windows" {
			base = filepath.Join(home, "AppData", "Local")
		} else {
			base = filepath.Join(home, ".config")
		}
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

// publicOf returns the public identity of a version-2 file.
func publicOf(f *identityFile) (Identity, error) {
	if f.Version != identityVersion {
		return Identity{}, ErrIdentityUpgrade
	}
	fp, err := Fingerprint(f.Recipient, f.SignKey)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Name: f.Name, Recipient: f.Recipient, SignKey: f.SignKey, Fingerprint: fp}, nil
}

// Unlocked is an identity whose private key is in memory. It never prints
// its key. Destroy it when done (the underlying age key cannot be zeroed
// but the reference is dropped).
type Unlocked struct {
	Identity
	id   *age.X25519Identity
	sign ed25519.PrivateKey
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
		clear(u.sign)
		u.sign = nil
	}
}

// Sign signs domain || msg with this person's Ed25519 key. domain
// separates the kinds of things signed (records, requests, leases).
func (u *Unlocked) Sign(domain string, msg []byte) ([]byte, error) {
	if u == nil || u.sign == nil {
		return nil, errors.New("members: identity is not unlocked")
	}
	return ed25519.Sign(u.sign, append([]byte(domain), msg...)), nil
}

// Member returns this person as a vault member entry with role.
func (u *Unlocked) Member(role string) format.Member {
	return format.Member{Name: u.Name, Recipient: u.Recipient, SignKey: u.SignKey, Role: role}
}

// verifySig checks an Ed25519 signature by the hex public key signKey.
func verifySig(signKey, domain string, msg, sig []byte) bool {
	pub, err := hex.DecodeString(signKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, append([]byte(domain), msg...), sig)
}

// MemberWrapper returns a crypto.KeyWrapper that can wrap and unwrap vault
// keys as this person (the vault's member unlocker for them).
func (u *Unlocked) MemberWrapper() (crypto.KeyWrapper, error) {
	if u == nil || u.id == nil {
		return nil, errors.New("members: identity is not unlocked")
	}
	return crypto.NewMemberIdentityWrapper(u.Name, u.id)
}

// sealIdentity builds an identity file for id and the signing key sk,
// protected by wrappers.
func sealIdentity(kind, name string, created time.Time, id *age.X25519Identity, sk ed25519.PrivateKey, wrappers []crypto.KeyWrapper) (*identityFile, error) {
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
	sealedSign, err := sealSigning(key, sk)
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
		SignKey:   hex.EncodeToString(sk.Public().(ed25519.PublicKey)),
		SealedSig: sealedSign,
		Unlockers: unlockers,
	}, nil
}

// sealSigning seals the signing key's seed (hex) under the identity key.
func sealSigning(key *crypto.VaultKey, sk ed25519.PrivateKey) ([]byte, error) {
	s, err := crypto.NewSealer(signSealName)
	if err != nil {
		return nil, err
	}
	seed := []byte(hex.EncodeToString(sk.Seed()))
	defer clear(seed)
	return s.Seal(key, seed)
}

// openSigning opens the sealed signing key of a version-2 file.
func openSigning(f *identityFile, key *crypto.VaultKey) (ed25519.PrivateKey, error) {
	s, err := crypto.NewSealer(signSealName)
	if err != nil {
		return nil, err
	}
	pt, err := s.Open(key, f.SealedSig)
	if err != nil {
		return nil, crypto.ErrWrongKey
	}
	defer clear(pt)
	seed := make([]byte, ed25519.SeedSize)
	if n, err := hex.Decode(seed, pt); err != nil || n != ed25519.SeedSize || len(pt) != 2*ed25519.SeedSize {
		return nil, crypto.ErrWrongKey
	}
	sk := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	if hex.EncodeToString(sk.Public().(ed25519.PublicKey)) != f.SignKey {
		return nil, crypto.ErrWrongKey
	}
	return sk, nil
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
// wrong passphrase and a tampered file look the same. For a version-1 file
// the signing key is nil (see Store.Unlock, which upgrades it).
func openIdentity(f *identityFile, w crypto.KeyWrapper) (*age.X25519Identity, ed25519.PrivateKey, error) {
	key, err := identityKey(f, w)
	if err != nil {
		return nil, nil, err
	}
	defer key.Destroy()
	sealer, err := crypto.NewSealer(identitySealName)
	if err != nil {
		return nil, nil, err
	}
	pt, err := sealer.Open(key, f.Sealed)
	if err != nil {
		return nil, nil, crypto.ErrWrongKey
	}
	defer clear(pt)
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(pt)))
	if err != nil || id.Recipient().String() != f.Recipient {
		return nil, nil, crypto.ErrWrongKey
	}
	if f.Version == 1 {
		return id, nil, nil
	}
	sk, err := openSigning(f, key)
	if err != nil {
		return nil, nil, err
	}
	return id, sk, nil
}

// upgradeV1 adds a signing key to a version-1 file, unlocked with w, and
// returns the version-2 file (not yet saved).
func upgradeV1(f *identityFile, w crypto.KeyWrapper) (*identityFile, ed25519.PrivateKey, error) {
	key, err := identityKey(f, w)
	if err != nil {
		return nil, nil, err
	}
	defer key.Destroy()
	_, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	sealed, err := sealSigning(key, sk)
	if err != nil {
		return nil, nil, err
	}
	up := *f
	up.Version = identityVersion
	up.SignKey = hex.EncodeToString(sk.Public().(ed25519.PublicKey))
	up.SealedSig = sealed
	return &up, sk, nil
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
	_, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		return Identity{}, err
	}
	return s.store(kindIdentity, name, id, sk, wrappers)
}

func (s *Store) store(kind, name string, id *age.X25519Identity, sk ed25519.PrivateKey, wrappers []crypto.KeyWrapper) (Identity, error) {
	f, err := sealIdentity(kind, name, time.Now().UTC().Round(0), id, sk, wrappers)
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

// Unlock opens the identity with w. A version-1 identity (no signing key)
// is upgraded on the way: a signing key is generated and the file saved
// as version 2. Its fingerprint changes, since the fingerprint covers both
// keys.
func (s *Store) Unlock(w crypto.KeyWrapper) (*Unlocked, error) {
	f, err := s.load(kindIdentity)
	if err != nil {
		return nil, err
	}
	id, sk, err := openIdentity(f, w)
	if err != nil {
		return nil, err
	}
	if f.Version == 1 {
		up, nsk, err := upgradeV1(f, w)
		if err != nil {
			return nil, err
		}
		if err := s.save(up); err != nil {
			return nil, err
		}
		f, sk = up, nsk
	}
	pub, err := publicOf(f)
	if err != nil {
		return nil, err
	}
	return &Unlocked{Identity: pub, id: id, sign: sk}, nil
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
	if f.Version != identityVersion {
		return nil, ErrIdentityUpgrade
	}
	id, sk, err := openIdentity(f, unlock)
	if err != nil {
		return nil, err
	}
	ef, err := sealIdentity(kindExport, f.Name, f.Created, id, sk, []crypto.KeyWrapper{protect})
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
	if ef.Version != identityVersion {
		return Identity{}, ErrIdentityUpgrade
	}
	id, sk, err := openIdentity(ef, from)
	if err != nil {
		return Identity{}, err
	}
	f, err := sealIdentity(kindIdentity, ef.Name, ef.Created, id, sk, wrappers)
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

// UnlockerRecipients returns the recipients of the identity's unlockers of
// type t (for example this Mac's Touch ID key), without unlocking anything.
func (s *Store) UnlockerRecipients(t format.UnlockerType) ([]string, error) {
	f, err := s.load(kindIdentity)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, u := range f.Unlockers {
		if u.Type == t {
			out = append(out, u.Recipient)
		}
	}
	return out, nil
}

// RemoveUnlockers removes every unlocker of type t from the identity (for
// example Touch ID on this Mac). At least one unlocker must remain.
func (s *Store) RemoveUnlockers(t format.UnlockerType) error {
	f, err := s.load(kindIdentity)
	if err != nil {
		return err
	}
	vf := &format.VaultFile{Unlockers: f.Unlockers}
	if vf.RemoveUnlockers(func(u format.Unlocker) bool { return u.Type == t }) == 0 {
		return nil
	}
	if len(vf.Unlockers) == 0 {
		return errors.New("members: that would leave the identity with no way to open it")
	}
	f.Unlockers = vf.Unlockers
	return s.save(f)
}
