package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/Arntek/secrets-vault/internal/agent"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/members"
)

// EnvConfig overrides the registry file location (used by tests).
const EnvConfig = "SECRETS_VAULT_CONFIG"

const maxConfigSize = 1 << 20

// Config is ~/.config/vault/config.toml: which vaults exist and where, and
// a few settings. It holds no secrets.
type Config struct {
	DefaultTTL     string                 `toml:"default_ttl,omitempty"`
	DefaultVault   string                 `toml:"default_vault,omitempty"`
	TouchEveryRead bool                   `toml:"touch_every_read,omitempty"`
	Dialog         string                 `toml:"dialog,omitempty"`
	Aliases        []string               `toml:"aliases,omitempty"`
	Vaults         map[string]*VaultEntry `toml:"vaults,omitempty"`
}

// VaultEntry is one [vaults.NAME] table.
type VaultEntry struct {
	Path           string `toml:"path"`
	Description    string `toml:"description,omitempty"`
	TTL            string `toml:"ttl,omitempty"`
	TouchEveryRead *bool  `toml:"touch_every_read,omitempty"`
	Dialog         string `toml:"dialog,omitempty"`
	// ID is the vault ID recorded at init or attach. vault.json is only
	// accepted if it holds this vault (design M1); the trust pin for it is
	// kept outside the registry, under trust/<ID>.json.
	ID string `toml:"id,omitempty"`
	// KeyID is the legacy key pin from before trust pins. It is read once,
	// by the migration and first-use checks, then dropped.
	KeyID string `toml:"key_id,omitempty"`
}

func (a *app) loadConfig() (*Config, error) {
	if a.cfg != nil {
		return a.cfg, nil
	}
	path, err := a.configFile()
	if err != nil {
		return nil, err
	}
	c := &Config{}
	f, err := os.Open(path) // #nosec G304 -- the user's own registry path
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, failf("cannot read the vault registry: %v", pathless(err))
	default:
		defer func() { _ = f.Close() }()
		data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
		if err != nil {
			return nil, failf("cannot read the vault registry: %v", pathless(err))
		}
		if c, err = parseConfig(data); err != nil {
			return nil, err
		}
	}
	if c.Vaults == nil {
		c.Vaults = map[string]*VaultEntry{}
	}
	a.cfg = c
	return c, nil
}

// parseConfig parses registry bytes. Errors describe the problem and never
// quote the file (toml's own errors do).
func parseConfig(data []byte) (*Config, error) {
	if len(data) > maxConfigSize {
		return nil, failf("the vault registry is too large")
	}
	c := &Config{}
	if _, err := toml.Decode(string(data), c); err != nil {
		return nil, failf("the vault registry is not valid TOML; fix or remove it")
	}
	if c.Vaults == nil {
		c.Vaults = map[string]*VaultEntry{}
	}
	for name, e := range c.Vaults {
		if e == nil || format.ValidateVaultName(name) != nil {
			return nil, failf("the vault registry has an invalid vault entry; fix or remove it")
		}
	}
	return c, nil
}

func (a *app) saveConfig(c *Config) error {
	path, err := a.configFile()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return failf("cannot create the config folder: %v", pathless(err))
	}
	var sb strings.Builder
	if err := toml.NewEncoder(&sb).Encode(c); err != nil {
		return failf("cannot write the vault registry")
	}
	if err := format.WriteFileAtomic(path, []byte(sb.String()), 0o600); err != nil {
		return failf("cannot write the vault registry: %v", pathless(err))
	}
	a.cfg = c
	return nil
}

func pathless(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// --- vault handles ---

// vaultRef is a registered vault. After app.open, chain is its verified
// vault.json (or v1 a version-1 file awaiting migration), pin this
// machine's trust pin and class how the two relate.
type vaultRef struct {
	name  string
	entry *VaultEntry
	dir   string

	chain *members.Chain
	v1    *format.VaultFile
	pin   *members.Pin
	class members.Classification
}

func (a *app) expandEntry(e *VaultEntry) (string, error) { return a.expandPath(e.Path) }

// vault looks up a registered vault by name. An unknown name is not echoed.
func (a *app) vault(name string) (*vaultRef, error) {
	c, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	e, ok := c.Vaults[name]
	if !ok {
		return nil, notFoundErrVault(a.prog)
	}
	dir, err := a.expandEntry(e)
	if err != nil {
		return nil, err
	}
	return &vaultRef{name: name, entry: e, dir: dir}, nil
}

func notFoundErrVault(prog string) error {
	return &exitErr{code: ExitError, msg: fmt.Sprintf("no such vault. Run '%s vaults' to see the registered ones", prog)}
}

// defaultVault picks the vault to use when none is named.
func (a *app) defaultVault(arg string) (*vaultRef, error) {
	if arg != "" {
		return a.vault(arg)
	}
	c, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	if c.DefaultVault != "" {
		if _, ok := c.Vaults[c.DefaultVault]; ok {
			return a.vault(c.DefaultVault)
		}
	}
	if len(c.Vaults) == 1 {
		for n := range c.Vaults {
			return a.vault(n)
		}
	}
	if len(c.Vaults) == 0 {
		return nil, failf("no vaults yet. Create one with: %s init NAME --path DIR", a.prog)
	}
	return nil, usageErrf("which vault? Name one, or set a default: %s config set default-vault NAME", a.prog)
}

func (a *app) vaultNames() ([]string, error) {
	c, err := a.loadConfig()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(c.Vaults))
	for n := range c.Vaults {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

func vaultErr(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("the folder or vault.json is missing (not synced yet, or moved?)")
	}
	return pathless(err)
}

// index returns the vault's index, rebuilt in memory from secrets/ if it
// is missing, broken or has drifted. Reading never writes to the vault
// folder (design section 6); the next write stores the rebuilt index.
func (v *vaultRef) index() (*format.Index, error) {
	old, rerr := format.ReadIndex(v.dir)
	if rerr != nil {
		old = nil
	}
	idx, _, err := format.RebuildIndex(v.dir, old)
	if err != nil {
		return nil, failf("cannot read the index of vault '%s': %v", v.name, vaultErr(err))
	}
	return idx, nil
}

// --- time to live ---

func (a *app) ttlFor(v *vaultRef) time.Duration {
	c, _ := a.loadConfig()
	for _, s := range []string{v.entry.TTL, c.DefaultTTL} {
		if s == "" {
			continue
		}
		if d, err := time.ParseDuration(s); err == nil && agent.ValidateTTL(d) == nil {
			return d
		}
	}
	return agent.DefaultTTL
}

func (a *app) touchEveryRead(v *vaultRef) bool {
	if v.entry.TouchEveryRead != nil {
		return *v.entry.TouchEveryRead
	}
	c, _ := a.loadConfig()
	return c.TouchEveryRead
}

// --- agent status helpers ---

type lockState struct {
	Unlocked bool
	Expires  time.Time
}

// lockStates asks a running agent which vaults are unlocked. It never
// starts the agent: no agent means everything is locked.
func (a *app) lockStates() map[string]lockState {
	out := map[string]lockState{}
	cl := a.client(false)
	if cl == nil {
		return out
	}
	list, err := cl.Status()
	if err != nil {
		return out
	}
	for _, s := range list {
		if s.Unlocked {
			out[s.VaultID] = lockState{Unlocked: true, Expires: s.ExpiresAt}
		}
	}
	return out
}

// --- key lookup across vaults ---

type keyRef struct {
	v     *vaultRef
	vf    *format.VaultFile
	entry format.IndexEntry
}

// findKey locates a key by name. With vaultName empty every registered vault
// is searched: not found is exit 4, and a name in several vaults needs
// --vault. Names that fail validation are not echoed.
func (a *app) findKey(name, vaultName string) (*keyRef, error) {
	if err := format.ValidateKeyName(name); err != nil {
		return nil, usageErrf("%v", err)
	}
	var names []string
	if vaultName != "" {
		if _, err := a.vault(vaultName); err != nil {
			return nil, err
		}
		names = []string{vaultName}
	} else {
		var err error
		if names, err = a.vaultNames(); err != nil {
			return nil, err
		}
	}
	var found []*keyRef
	for _, n := range names {
		v, err := a.vault(n)
		if err != nil {
			return nil, err
		}
		vf, err := format.ReadVaultFile(v.dir)
		if err != nil {
			a.warnf("vault '%s' is unavailable: %v", n, vaultErr(err))
			continue
		}
		idx, err := v.index()
		if err != nil {
			a.warnf("%v", err)
			continue
		}
		if e, ok := idx.Get(name); ok {
			found = append(found, &keyRef{v: v, vf: vf, entry: e})
		}
	}
	switch len(found) {
	case 0:
		return nil, notFoundErr("key not found. Try: %s search WORDS", a.prog)
	case 1:
		return found[0], nil
	}
	vs := make([]string, len(found))
	for i, k := range found {
		vs[i] = k.v.name
	}
	slices.Sort(vs)
	return nil, usageErrf("that key exists in more than one vault (%s). Use --vault", strings.Join(vs, ", "))
}
