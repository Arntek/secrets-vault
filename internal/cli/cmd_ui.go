package cli

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Arntek/secrets-vault/internal/format"
	"github.com/Arntek/secrets-vault/internal/tui"
)

// uiRun starts the terminal UI. Tests replace it so no real terminal is
// needed; production code leaves it alone.
var uiRun = tui.Run

// cmdUI: ui
//
// The UI is a second front end on the same operations as the commands
// (setKey, moveKey, ... in cmd_keys.go and unlockVault in cmd_lock.go), so
// the index, audit hook, membership verification and exit codes behave the
// same. Prompts (passphrases, first-use confirmation) are drawn inside the
// UI instead of on the terminal.
func cmdUI(a *app, p *parsed) error {
	if err := p.wantArgs(0, 0, a.prog+" ui"); err != nil {
		return err
	}
	if a.asJSON {
		return usageErrf("%s ui is interactive and has no --json output", a.prog)
	}
	in, inOK := a.rawStdin.(*os.File)
	out, outOK := a.out.(*os.File)
	if !a.term.StdinTTY() || !a.term.StdoutTTY() || !inOK || !outOK {
		return failf("%s ui needs a terminal (it is a full-screen interface)", a.prog)
	}
	b := newUIBackend(a)
	err := uiRun(b, tui.Options{NoColor: a.getenv("NO_COLOR") != ""}, in, out)
	if err != nil {
		return failf("%v", err)
	}
	return nil
}

// uiBackend implements tui.Backend on an app. The UI calls it from one
// goroutine at a time; mu makes that a rule rather than a hope.
type uiBackend struct {
	a      *app
	mu     sync.Mutex
	ask    tui.Prompter
	cap    *captureWriter
	cancel bool // the person dismissed a prompt during this call
}

// captureWriter collects what the commands would print to stderr, so the
// next prompt can show it (for example "Wrong passphrase.").
type captureWriter struct{ buf []byte }

func (c *captureWriter) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	if len(c.buf) > 4096 {
		c.buf = c.buf[len(c.buf)-4096:]
	}
	return len(p), nil
}

func (c *captureWriter) take() string {
	s := string(c.buf)
	c.buf = c.buf[:0]
	return s
}

// uiTerm makes the app believe it has a terminal whose questions are asked
// inside the UI.
type uiTerm struct{ b *uiBackend }

func (uiTerm) StdinTTY() bool  { return true }
func (uiTerm) StdoutTTY() bool { return true }
func (t uiTerm) ReadPassword() ([]byte, error) {
	return t.b.question(true)
}

// uiLineReader feeds visible one-line answers (a state code, y/n) to the
// app's buffered stdin reader.
type uiLineReader struct {
	b    *uiBackend
	rest []byte
}

func (r *uiLineReader) Read(p []byte) (int, error) {
	if len(r.rest) == 0 {
		line, err := r.b.question(false)
		if err != nil {
			return 0, io.EOF
		}
		r.rest = append(line, '\n')
	}
	n := copy(p, r.rest)
	clear(r.rest[:n])
	r.rest = r.rest[n:]
	return n, nil
}

func newUIBackend(a *app) *uiBackend {
	b := &uiBackend{a: a, cap: &captureWriter{}}
	a.term = uiTerm{b: b}
	a.in = bufio.NewReaderSize(&uiLineReader{b: b}, 16)
	a.out = io.Discard
	a.errOut = b.cap
	a.passStdin = false
	a.asJSON = false
	return b
}

func (b *uiBackend) SetPrompter(p tui.Prompter) { b.ask = p }

// question asks inside the UI, showing whatever the app printed since the
// last question (the prompt text and any notes).
func (b *uiBackend) question(hidden bool) ([]byte, error) {
	text := strings.TrimRight(b.cap.take(), "\n ")
	if b.ask == nil {
		return nil, errors.New("no way to ask")
	}
	if b.cancel {
		// The person already dismissed a prompt in this operation: do not
		// ask the next one in the unlock chain, give up.
		return nil, tui.ErrCancelled
	}
	ans, err := b.ask(text, hidden)
	if err != nil {
		b.cancel = true
		return nil, err
	}
	return ans, nil
}

// begin and end bracket one backend call: nothing from the previous call
// (unlocked identity, cached registry) carries over.
func (b *uiBackend) begin() {
	b.mu.Lock()
	b.cancel = false
	b.a.cfg = nil
	b.a.firstPin = nil
	b.cap.take()
}

func (b *uiBackend) end(err error) error {
	b.a.identity.Destroy()
	b.a.identity = nil
	b.cap.take()
	cancelled := b.cancel
	b.mu.Unlock()
	if err != nil && cancelled {
		return tui.ErrCancelled
	}
	return err
}

// errText turns an error into what the person should read.
func uiErr(err error) error {
	if err == nil {
		return nil
	}
	var ee *exitErr
	if errors.As(err, &ee) && ee.msg != "" {
		return errors.New(ee.msg)
	}
	return err
}

func (b *uiBackend) ValidateName(name string) error {
	if err := format.ValidateKeyName(name); err != nil {
		return err
	}
	return nil
}

func (b *uiBackend) Snapshot() (tui.Snapshot, error) {
	b.begin()
	a := b.a
	var snap tui.Snapshot
	rows, sums, errs, err := a.collectKeys("", "")
	if err == nil {
		names, nerr := a.vaultNames()
		if nerr != nil {
			err = nerr
		}
		sumBy := map[string]vaultSummary{}
		for _, s := range sums {
			sumBy[s.Name] = s
		}
		errBy := map[string]vaultError{}
		for _, e := range errs {
			errBy[e.Vault] = e
		}
		for _, n := range names {
			switch {
			case errBy[n].Error != "":
				snap.Vaults = append(snap.Vaults, tui.Vault{Name: n, Err: errBy[n].Error, Verify: errBy[n].verify})
			case sumBy[n].Name != "":
				s := sumBy[n]
				snap.Vaults = append(snap.Vaults, tui.Vault{Name: n, Keys: s.Keys, Unlocked: s.Unlocked, Expires: s.expires, IndexState: s.IndexState})
			default:
				snap.Vaults = append(snap.Vaults, tui.Vault{Name: n, Err: "the index of this vault could not be read (the folder may not be synced yet)"})
			}
		}
		for _, r := range rows {
			snap.Keys = append(snap.Keys, tui.Key{Name: r.Name, Vault: r.Vault, Description: r.Description,
				Tags: r.Tags, Updated: r.updatedAt, UpdatedBy: r.UpdatedBy, Verified: r.Verified, Pending: r.PendingChange})
		}
	}
	return snap, b.end(uiErr(err))
}

func (b *uiBackend) Reveal(vault, name string) ([]byte, error) {
	b.begin()
	k, err := b.a.findKey(name, vault)
	if err != nil {
		return nil, b.end(uiErr(err))
	}
	val, err := b.a.revealValue(k)
	return val, b.end(uiErr(err))
}

func (b *uiBackend) Copy(vault, name string) (bool, error) {
	b.begin()
	k, err := b.a.findKey(name, vault)
	if err != nil {
		return false, b.end(uiErr(err))
	}
	ok, err := b.a.copyValue(k)
	return ok, b.end(uiErr(err))
}

func (b *uiBackend) Set(vault, name string, value []byte, desc *string) error {
	b.begin()
	_, err := b.a.setKey(name, vault, func() ([]byte, error) { return append([]byte(nil), value...), nil }, desc)
	return b.end(uiErr(err))
}

func (b *uiBackend) Describe(vault, name, text string) error {
	b.begin()
	_, _, err := b.a.describeKey(name, vault, text)
	return b.end(uiErr(err))
}

func (b *uiBackend) Tag(vault, name string, add, remove []string) error {
	b.begin()
	var err error
	if len(remove) > 0 {
		_, _, _, err = b.a.tagKey(name, vault, remove, true)
	}
	if err == nil && len(add) > 0 {
		for _, t := range add {
			if verr := format.ValidateTag(t); verr != nil {
				err = usageErrf("%v", verr)
				break
			}
		}
		if err == nil {
			_, _, _, err = b.a.tagKey(name, vault, add, false)
		}
	}
	return b.end(uiErr(err))
}

func (b *uiBackend) Move(vault, name, to string) error {
	b.begin()
	_, _, _, err := b.a.moveKey(name, vault, to)
	return b.end(uiErr(err))
}

func (b *uiBackend) Rename(vault, name, newName string) error {
	b.begin()
	_, err := b.a.renameKey(name, vault, newName)
	return b.end(uiErr(err))
}

func (b *uiBackend) Delete(vault, name string) error {
	b.begin()
	k, err := b.a.findKey(name, vault)
	if err == nil {
		err = b.a.deleteKey(k)
	}
	return b.end(uiErr(err))
}

func (b *uiBackend) Unlock(vault string) error {
	b.begin()
	v, err := b.a.vault(vault)
	if err == nil {
		_, err = b.a.unlockVault(v, time.Duration(0))
	}
	return b.end(uiErr(err))
}

func (b *uiBackend) Lock(vault string) error {
	b.begin()
	_, err := b.a.lockVault(vault)
	return b.end(uiErr(err))
}

func (b *uiBackend) LockAll() error {
	b.begin()
	return b.end(uiErr(b.a.lockAll()))
}
