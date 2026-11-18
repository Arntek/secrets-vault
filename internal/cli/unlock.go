package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Arntek/secrets-vault/internal/agent"
	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/members"
	"github.com/Arntek/secrets-vault/internal/touchid"
)

const (
	minPassphraseLen  = 8
	maxPassphraseLen  = 1024
	maxPassphraseTry  = 3
	maxStdinValueSize = 1 << 20
)

// --- prompts ---

// interactive reports whether we can ask the user for a passphrase.
func (a *app) interactive() bool { return a.term.StdinTTY() || a.passStdin }

func (a *app) readLine() (string, error) {
	line, err := a.in.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// askHidden reads a secret without echo from the terminal, or one line from
// stdin when --passphrase-stdin is given. The prompt goes to stderr so
// stdout stays clean for pipes.
func (a *app) askHidden(prompt string) ([]byte, error) {
	switch {
	case a.term.StdinTTY():
		fmt.Fprint(a.errOut, prompt)
		b, err := a.term.ReadPassword()
		fmt.Fprint(a.errOut, "\n")
		if err != nil {
			return nil, failf("could not read from the terminal")
		}
		return b, nil
	case a.passStdin:
		line, err := a.readLine()
		if err != nil {
			return nil, failf("no passphrase on stdin")
		}
		return []byte(line), nil
	}
	return nil, failf("no terminal to ask on; use --passphrase-stdin or run in a terminal")
}

// askNewPassphrase asks for a new passphrase (twice on a terminal).
func (a *app) askNewPassphrase(what string) ([]byte, error) {
	p, err := a.askHidden(what + ": ")
	if err != nil {
		return nil, err
	}
	if len(p) < minPassphraseLen {
		clear(p)
		return nil, failf("the passphrase must be at least %d characters", minPassphraseLen)
	}
	if len(p) > maxPassphraseLen {
		clear(p)
		return nil, failf("the passphrase is too long")
	}
	if a.term.StdinTTY() {
		p2, err := a.askHidden("Repeat it: ")
		if err != nil {
			clear(p)
			return nil, err
		}
		same := bytes.Equal(p, p2)
		clear(p2)
		if !same {
			clear(p)
			return nil, failf("the two passphrases do not match")
		}
	}
	return p, nil
}

// confirm asks a yes/no question; the default is no.
func (a *app) confirm(question string) (bool, error) {
	if !a.term.StdinTTY() {
		return false, nil
	}
	fmt.Fprint(a.errOut, question+" [y/N] ")
	line, err := a.readLine()
	if err != nil {
		return false, nil
	}
	l := strings.ToLower(strings.TrimSpace(line))
	return l == "y" || l == "yes", nil
}

// confirmDefaultYes asks a yes/no question where Enter means yes.
func (a *app) confirmDefaultYes(question string) bool {
	if !a.term.StdinTTY() {
		return false
	}
	fmt.Fprint(a.errOut, question+" [Y/n] ")
	line, err := a.readLine()
	if err != nil {
		return false
	}
	l := strings.ToLower(strings.TrimSpace(line))
	return l == "" || l == "y" || l == "yes"
}

func (a *app) ask(prompt string) (string, error) {
	fmt.Fprint(a.errOut, prompt)
	return a.readLine()
}

// --- wrappers ---

func (a *app) passphraseWrapper(pass []byte) (crypto.KeyWrapper, error) {
	if passphraseLogN > 0 {
		return crypto.NewPassphraseWrapperWithWorkFactor(pass, passphraseLogN)
	}
	return crypto.NewPassphraseWrapper(pass)
}

func destroyWrapper(w crypto.KeyWrapper) {
	if d, ok := w.(interface{ Destroy() }); ok {
		d.Destroy()
	}
}

// --- Touch ID on this Mac ---

func (a *app) touchKeyPath() (string, error) {
	d, err := a.configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "touchid.key"), nil
}

func (a *app) deviceLabel() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "this Mac"
	}
	h = strings.TrimSuffix(h, ".local")
	if len(h) > 64 {
		h = h[:64]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, h)
}

// enrolledDevice returns this Mac's Touch ID device when its key file exists
// and Touch ID is usable now.
func (a *app) enrolledDevice() *touchid.Device {
	if !a.touch.available() {
		return nil
	}
	p, err := a.touchKeyPath()
	if err != nil {
		return nil
	}
	if _, err := os.Stat(p); err != nil {
		return nil
	}
	return &touchid.Device{Label: a.deviceLabel(), KeyPath: p}
}

// ensureDevice enrols this Mac's Secure Enclave key if needed.
func (a *app) ensureDevice() (*touchid.Device, error) {
	if !a.touch.available() {
		return nil, failf("Touch ID is not available here (no sensor, an SSH session, or this build lacks it)")
	}
	if d := a.enrolledDevice(); d != nil {
		return d, nil
	}
	p, err := a.touchKeyPath()
	if err != nil {
		return nil, err
	}
	d, err := a.touch.enroll(a.deviceLabel(), p)
	if err != nil {
		if errors.Is(err, touchid.ErrEnrolled) {
			return &touchid.Device{Label: a.deviceLabel(), KeyPath: p}, nil
		}
		return nil, failf("could not set up Touch ID: %v", err)
	}
	return d, nil
}

// touchWrapper returns the Touch ID wrapper for this Mac, or nil.
func (a *app) touchWrapper(vaultName string) crypto.KeyWrapper {
	d := a.enrolledDevice()
	if d == nil {
		return nil
	}
	w, err := a.touch.wrapper(d, vaultName)
	if err != nil {
		return nil
	}
	return w
}

// thisMacRecipient returns the public identifier of this Mac's enclave key.
func (a *app) thisMacRecipient() string {
	w := a.touchWrapper("")
	if w == nil {
		return ""
	}
	probe, err := crypto.NewVaultKey()
	if err != nil {
		return ""
	}
	defer probe.Destroy()
	u, err := w.Wrap(probe)
	if err != nil {
		return ""
	}
	return u.Recipient
}

// --- identity ---

func (a *app) identityStore() (*members.Store, error) {
	d, err := a.configDir()
	if err != nil {
		return nil, err
	}
	return members.NewStore(filepath.Join(d, "identity")), nil
}

// myIdentity returns the public part of this person's identity, if any.
func (a *app) myIdentity() (members.Identity, bool) {
	s, err := a.identityStore()
	if err != nil || !s.Exists() {
		return members.Identity{}, false
	}
	id, err := s.Public()
	if err != nil {
		return members.Identity{}, false
	}
	return id, true
}

func (a *app) myName() string {
	if id, ok := a.myIdentity(); ok {
		return id.Name
	}
	return ""
}

// unlockIdentity opens the personal identity: Touch ID first (when this Mac
// is enrolled), then the personal passphrase.
func (a *app) unlockIdentity() (*members.Unlocked, error) {
	s, err := a.identityStore()
	if err != nil {
		return nil, err
	}
	if !s.Exists() {
		return nil, failf("you have no identity yet. Run: %s attach NAME DIR", a.prog)
	}
	if tw := a.touchWrapper(""); tw != nil {
		if un, err := s.Unlock(tw); err == nil {
			return un, nil
		}
	}
	if !a.interactive() {
		return nil, failf("your identity is locked and there is no terminal to ask on")
	}
	for try := 0; try < maxPassphraseTry; try++ {
		p, err := a.askHidden("Your personal passphrase: ")
		if err != nil {
			return nil, err
		}
		w, err := a.passphraseWrapper(p)
		clear(p)
		if err != nil {
			return nil, failf("that passphrase cannot be used")
		}
		un, uerr := s.Unlock(w)
		destroyWrapper(w)
		if uerr == nil {
			return un, nil
		}
		if a.passStdin && !a.term.StdinTTY() {
			break
		}
		a.infof("Wrong passphrase.")
	}
	return nil, failf("could not unlock your identity: wrong passphrase")
}

// createIdentity makes this person's identity: a name, a personal
// passphrase, and Touch ID when offered and available.
func (a *app) createIdentity(name string) (members.Identity, error) {
	s, err := a.identityStore()
	if err != nil {
		return members.Identity{}, err
	}
	if name == "" {
		if !a.term.StdinTTY() {
			return members.Identity{}, failf("this is your first time: choose a name with --as NAME (a-z, 0-9, - and _)")
		}
		if name, err = a.ask("Your name for other members (a-z, 0-9, - and _): "); err != nil {
			return members.Identity{}, failf("no name given")
		}
	}
	if err := members.ValidateMemberName(name); err != nil {
		return members.Identity{}, failf("%v", err)
	}
	pass, err := a.askNewPassphrase("Choose a personal passphrase for your identity")
	if err != nil {
		return members.Identity{}, err
	}
	pw, err := a.passphraseWrapper(pass)
	clear(pass)
	if err != nil {
		return members.Identity{}, failf("that passphrase cannot be used")
	}
	defer destroyWrapper(pw)
	wrappers := []crypto.KeyWrapper{pw}
	if a.touch.available() && a.term.StdinTTY() && a.confirmDefaultYes("Use Touch ID to unlock your identity on this Mac?") {
		if d, err := a.ensureDevice(); err == nil {
			if tw, err := a.touch.wrapper(d, ""); err == nil {
				wrappers = append(wrappers, tw)
			}
		}
	}
	id, err := s.Create(name, wrappers...)
	if err != nil {
		return members.Identity{}, failf("could not create your identity: %v", err)
	}
	a.infof("Created your identity '%s'. Fingerprint: %s", id.Name, id.Fingerprint)
	return id, nil
}

// --- unlocking a vault ---

type purpose int

const (
	purposeRead purpose = iota
	purposeWrite
)

// authenticate runs the unlock chain for a vault: Touch ID if enrolled on
// this Mac, then the member identity, then the vault passphrase. It returns
// ErrLocked-style errors (exit 3) when nothing can be asked.
func (a *app) authenticate(v *vaultRef, vf *format.VaultFile) (*crypto.VaultKey, error) {
	// 1. Touch ID.
	if len(vf.UnlockersOf(format.UnlockerTouchID)) > 0 {
		if w := a.touchWrapper(v.name); w != nil {
		touch:
			for _, u := range vf.UnlockersOf(format.UnlockerTouchID) {
				k, err := w.Unwrap(u)
				switch {
				case err == nil:
					if crypto.CheckKey(vf, k) == nil {
						return k, nil
					}
					k.Destroy()
				case errors.Is(err, touchid.ErrCancelled), errors.Is(err, touchid.ErrUnsupported):
					break touch // fall back to the passphrase
				}
			}
		}
	}
	// 2. This person's member key.
	if id, ok := a.myIdentity(); ok {
		for _, u := range vf.UnlockersOf(format.UnlockerMember) {
			if u.Recipient != id.Recipient {
				continue
			}
			if !a.interactive() && a.touchWrapper("") == nil {
				break
			}
			un, err := a.unlockIdentity()
			if err != nil {
				var ee *exitErr
				if errors.As(err, &ee) && !a.interactive() {
					break
				}
				return nil, err
			}
			mw, err := un.MemberWrapper()
			un.Destroy()
			if err == nil {
				if k, err := crypto.Unlock(vf, mw); err == nil {
					return k, nil
				}
			}
			break
		}
	}
	// 3. The vault passphrase.
	if len(vf.UnlockersOf(format.UnlockerPassphrase)) > 0 {
		if k, err := a.promptVaultPassphrase(v, vf); k != nil || err != nil {
			return k, err
		}
	}
	return nil, a.lockedErr(v.name)
}

// promptVaultPassphrase asks for the vault passphrase. It returns (nil, nil)
// when there is no way to ask (the caller reports "locked").
func (a *app) promptVaultPassphrase(v *vaultRef, vf *format.VaultFile) (*crypto.VaultKey, error) {
	if !a.interactive() {
		if a.dialogPassphrase != nil {
			// Phase 2: native password dialog for agents.
			p, err := a.dialogPassphrase(v.name)
			if err != nil {
				return nil, nil
			}
			defer clear(p)
			return a.tryPassphrase(vf, p)
		}
		return nil, nil
	}
	for try := 0; try < maxPassphraseTry; try++ {
		p, err := a.askHidden("Passphrase for '" + v.name + "': ")
		if err != nil {
			return nil, err
		}
		k, err := a.tryPassphrase(vf, p)
		clear(p)
		if err != nil {
			return nil, err
		}
		if k != nil {
			return k, nil
		}
		if !a.term.StdinTTY() {
			break
		}
		a.infof("Wrong passphrase.")
	}
	return nil, failf("could not unlock '%s': wrong passphrase", v.name)
}

func (a *app) tryPassphrase(vf *format.VaultFile, p []byte) (*crypto.VaultKey, error) {
	w, err := a.passphraseWrapper(p)
	if err != nil {
		return nil, nil
	}
	defer destroyWrapper(w)
	k, err := crypto.Unlock(vf, w)
	if err != nil {
		return nil, nil
	}
	return k, nil
}

// checkPin compares the vault's key with the one this Mac pinned. A mismatch
// outside a rotation this Mac ran is refused unless the user accepts it.
func (a *app) checkPin(v *vaultRef, vf *format.VaultFile, accept bool) error {
	if v.entry.KeyID == "" || v.entry.KeyID == vf.KeyID || accept {
		return nil
	}
	return failf("the encryption key of vault '%s' changed since this Mac last used it. "+
		"That is expected if a member was removed; otherwise someone with access to the folder may have replaced it. "+
		"If you trust the change, run: %s unlock %s --accept-key-change", v.name, a.prog, v.name)
}

type openOpts struct {
	purpose      purpose
	forceAuth    bool          // ignore a key held by the agent
	ttl          time.Duration // 0 = per-vault/default
	acceptKeyChg bool
	// requireAgent makes a missing agent an error (the unlock command).
	requireAgent bool
}

// openKey returns the vault key, unlocking the vault if needed: agent key,
// then Touch ID / member / passphrase. A successful unlock is cached in the
// agent for the vault's TTL. The caller must Destroy the key.
func (a *app) openKey(v *vaultRef, vf *format.VaultFile, o openOpts) (*crypto.VaultKey, error) {
	if err := a.checkPin(v, vf, o.acceptKeyChg); err != nil {
		return nil, err
	}
	cl := a.client(true)
	if o.requireAgent && cl == nil {
		return nil, a.agentUnavailableErr()
	}
	touchEvery := o.purpose == purposeRead && a.touchEveryRead(v)
	if cl != nil && !o.forceAuth && !touchEvery {
		k, err := cl.Key(vf.ID)
		switch {
		case err == nil:
			if crypto.CheckKey(vf, k) == nil {
				return k, nil
			}
			// The vault key was rotated elsewhere: forget the stale key.
			k.Destroy()
			_ = cl.Lock(vf.ID)
		case errors.Is(err, agent.ErrLocked):
		default:
			// An unreachable agent just means no cache; carry on.
		}
	}
	k, err := a.authenticate(v, vf)
	if err != nil {
		return nil, err
	}
	a.pinKey(v, vf.KeyID)
	if cl != nil {
		ttl := o.ttl
		if ttl == 0 {
			ttl = a.ttlFor(v)
		}
		if dup, err := crypto.VaultKeyFromBytes(k.Bytes()); err == nil {
			if err := cl.Unlock(vf.ID, dup, ttl); err != nil && o.requireAgent {
				k.Destroy()
				return nil, failf("could not hand the key to the unlock agent")
			}
		}
	}
	return k, nil
}
