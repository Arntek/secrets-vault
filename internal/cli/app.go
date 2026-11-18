package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/Arntek/secrets-vault/internal/agent"
	"github.com/Arntek/secrets-vault/internal/audit"
	"github.com/Arntek/secrets-vault/internal/crypto"
	"github.com/Arntek/secrets-vault/internal/members"
	"github.com/Arntek/secrets-vault/internal/touchid"
)

// terminal is what the CLI needs to know about the user's terminal. The real
// one looks at the file descriptors; tests script it.
type terminal interface {
	StdinTTY() bool
	StdoutTTY() bool
	// ReadPassword reads one line from the terminal without echo.
	ReadPassword() ([]byte, error)
}

type osTerminal struct {
	in  io.Reader
	out io.Writer
}

func (t osTerminal) StdinTTY() bool {
	f, ok := t.in.(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) // #nosec G115 -- fd fits in int
}

func (t osTerminal) StdoutTTY() bool {
	f, ok := t.out.(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) // #nosec G115 -- fd fits in int
}

func (t osTerminal) ReadPassword() ([]byte, error) {
	f, ok := t.in.(*os.File)
	if !ok {
		return nil, errors.New("no terminal to read from")
	}
	return term.ReadPassword(int(f.Fd())) // #nosec G115 -- fd fits in int
}

// touchBackend is the Touch ID surface the CLI uses. The real one is package
// touchid; tests swap in a software fake because no test may need a finger.
type touchBackend struct {
	available func() bool
	enroll    func(label, keyPath string) (*touchid.Device, error)
	wrapper   func(d *touchid.Device, vault string) (crypto.KeyWrapper, error)
}

func realTouch() touchBackend {
	return touchBackend{
		available: touchid.Available,
		enroll:    touchid.Enroll,
		wrapper:   touchid.WrapperForVault,
	}
}

// testHook, when set by tests, adjusts a freshly built app (inject a fake
// terminal, Touch ID, clipboard or clock). Production code leaves it nil.
var testHook func(*app)

// passphraseLogN is the scrypt work factor for new passphrase unlockers; 0
// means the production default. Tests lower it.
var passphraseLogN = 0

// app is one invocation of the program.
type app struct {
	prog     string
	in       *bufio.Reader
	rawStdin io.Reader
	out      io.Writer
	errOut   io.Writer
	term     terminal
	touch    touchBackend
	audit    audit.Logger
	now      func() time.Time
	getenv   func(string) string
	environ  func() []string
	clip     clipboard
	exePath  func() (string, error)

	asJSON    bool
	passStdin bool
	// expectCode is --expect: a state code from another member's machine
	// (design section 8). signerFP is --signer-fingerprint: the fingerprint
	// of whoever added this person, for a first use without a terminal.
	expectCode string
	signerFP   string
	// identity is this person's identity once unlocked in this command,
	// so one command never asks for it twice. close() destroys it.
	identity *members.Unlocked
	// firstPin describes a first-use pin made by this command, so --json
	// output can say whether it was checked (ue1.10).
	firstPin *firstPinInfo

	cfgPath string
	cfg     *Config

	agentC   agent.Client
	agentErr error // why the last dial failed
	// dialAgent connects to the agent; start says whether to launch it if
	// it is not running.
	dialAgent func(start bool) (agent.Client, error)

	// dialogPassphrase is the Phase 2 hook for a native macOS password
	// dialog when an agent (no terminal) hits a locked vault. It is nil
	// today; unlock falls through to "locked, exit 3" when no terminal is
	// available.
	dialogPassphrase func(vault string) ([]byte, error)
}

func newApp(prog string, stdin io.Reader, stdout, stderr io.Writer) *app {
	a := &app{
		prog:    prog,
		out:     stdout,
		errOut:  stderr,
		term:    osTerminal{in: stdin, out: stdout},
		touch:   realTouch(),
		audit:   audit.Nop{},
		now:     time.Now,
		getenv:  os.Getenv,
		environ: os.Environ,
		clip:    sysClipboard{},
		exePath: os.Executable,
		dialAgent: func(start bool) (agent.Client, error) {
			return agent.DialWith(agent.DialOptions{NoAutoStart: !start})
		},
	}
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	a.rawStdin = stdin
	a.in = bufio.NewReader(stdin)
	if testHook != nil {
		testHook(a)
	}
	return a
}

func (a *app) close() {
	a.identity.Destroy()
	if a.agentC != nil {
		_ = a.agentC.Close()
		a.agentC = nil
	}
}

// client returns the agent client, or nil when there is no agent (not
// running and start is false, or unsupported on this platform).
func (a *app) client(start bool) agent.Client {
	if a.agentC != nil {
		return a.agentC
	}
	c, err := a.dialAgent(start)
	if err != nil {
		a.agentErr = err
		return nil
	}
	a.agentC = c
	return c
}

// agentUnavailableErr explains why the agent could not be used, from the
// last failed dial. Only a platform without an agent is "not available";
// anything else shows the real reason (paths only, never key material).
func (a *app) agentUnavailableErr() error {
	err := a.agentErr
	switch {
	case errors.Is(err, agent.ErrUnsupported) && runtime.GOOS == "windows":
		return failf("there is no unlock agent on Windows yet, so a vault cannot stay unlocked between commands. Each command that needs a key asks for the passphrase")
	case err == nil, errors.Is(err, agent.ErrUnsupported):
		return failf("the unlock agent is not available on this system")
	case errors.Is(err, agent.ErrPathTooLong), errors.Is(err, agent.ErrUnsafeDir):
		return failf("the unlock agent cannot start: %v. Set SECRETS_VAULT_AGENT_DIR to a short folder that only you can use", err)
	}
	return failf("the unlock agent cannot start: %v", err)
}

func (a *app) printf(format string, args ...any) { fmt.Fprintf(a.out, format, args...) }
func (a *app) warnf(format string, args ...any) {
	fmt.Fprintf(a.errOut, a.prog+": "+format+"\n", args...)
}
func (a *app) infof(format string, args ...any) { fmt.Fprintf(a.errOut, format+"\n", args...) }

// --- errors and exit codes ---

type exitErr struct {
	code int
	msg  string
}

func (e *exitErr) Error() string { return e.msg }

func failf(format string, args ...any) error {
	return &exitErr{code: ExitError, msg: fmt.Sprintf(format, args...)}
}

// verifyErrf is a refusal because a vault failed verification (exit 5).
func verifyErrf(format string, args ...any) error {
	return &exitErr{code: ExitUnverified, msg: fmt.Sprintf(format, args...)}
}

func usageErrf(format string, args ...any) error {
	return &exitErr{code: ExitUsage, msg: fmt.Sprintf(format, args...)}
}

func notFoundErr(format string, args ...any) error {
	return &exitErr{code: ExitNotFound, msg: fmt.Sprintf(format, args...)}
}

func (a *app) lockedErr(vault string) error {
	return &exitErr{code: ExitLocked, msg: fmt.Sprintf("Vault '%s' is locked. Run: %s unlock %s", vault, a.prog, vault)}
}

// --- argument parsing ---

type flagSpec struct {
	name  string // long name, without dashes
	short string // one letter, optional
	value bool   // takes a value
}

type parsed struct {
	flags map[string][]string
	args  []string // positional arguments
	rest  []string // everything after "--"
	dash  bool     // "--" was present
}

func (p *parsed) has(name string) bool { _, ok := p.flags[name]; return ok }

func (p *parsed) str(name string) string {
	v := p.flags[name]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

func (p *parsed) all(name string) []string { return p.flags[name] }

// parseArgs splits args into flags and positional arguments. Flags may
// appear anywhere. Nothing the user typed is echoed in errors: a secret
// pasted by mistake must not reach the terminal log.
func parseArgs(args []string, specs []flagSpec) (*parsed, error) {
	p := &parsed{flags: map[string][]string{}}
	find := func(arg string, long bool) *flagSpec {
		for i := range specs {
			if long && specs[i].name == arg || !long && specs[i].short != "" && specs[i].short == arg {
				return &specs[i]
			}
		}
		return nil
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if p.dash {
			p.rest = append(p.rest, arg)
			continue
		}
		switch {
		case arg == "--":
			p.dash = true
		case strings.HasPrefix(arg, "--"):
			name, val, hasVal := strings.Cut(arg[2:], "=")
			spec := find(name, true)
			if spec == nil {
				return nil, usageErrf("unknown option")
			}
			if !spec.value {
				if hasVal {
					return nil, usageErrf("option --%s does not take a value", spec.name)
				}
				p.flags[spec.name] = append(p.flags[spec.name], "true")
				continue
			}
			if !hasVal {
				if i+1 >= len(args) {
					return nil, usageErrf("option --%s needs a value", spec.name)
				}
				i++
				val = args[i]
			}
			p.flags[spec.name] = append(p.flags[spec.name], val)
		case len(arg) == 2 && arg[0] == '-' && arg != "--":
			spec := find(arg[1:], false)
			if spec == nil {
				return nil, usageErrf("unknown option")
			}
			if !spec.value {
				p.flags[spec.name] = append(p.flags[spec.name], "true")
				continue
			}
			if i+1 >= len(args) {
				return nil, usageErrf("option -%s needs a value", spec.short)
			}
			i++
			p.flags[spec.name] = append(p.flags[spec.name], args[i])
		default:
			p.args = append(p.args, arg)
		}
	}
	return p, nil
}

func (p *parsed) wantArgs(min, max int, usage string) error {
	if len(p.args) < min || (max >= 0 && len(p.args) > max) {
		return usageErrf("usage: %s", usage)
	}
	return nil
}

// --- paths and environment ---

func (a *app) home() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// expandPath turns ~ and relative paths into an absolute, cleaned path.
func (a *app) expandPath(p string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		h := a.home()
		if h == "" {
			return "", failf("cannot find your home folder")
		}
		p = filepath.Join(h, strings.TrimPrefix(p, "~"))
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", failf("cannot resolve that path")
	}
	return filepath.Clean(abs), nil
}

func (a *app) configFile() (string, error) {
	if a.cfgPath != "" {
		return a.cfgPath, nil
	}
	if p := a.getenv(EnvConfig); p != "" {
		a.cfgPath = p
		return p, nil
	}
	base := configBase(runtime.GOOS, a.getenv, a.home())
	if base == "" {
		return "", failf("cannot find your home folder; set %s", EnvConfig)
	}
	a.cfgPath = filepath.Join(base, "vault", "config.toml")
	return a.cfgPath, nil
}

// configBase is the folder that holds the "vault" config folder:
// XDG_CONFIG_HOME when set, else %LOCALAPPDATA% on Windows (not the roaming
// profile: the identity and Touch ID/Hello keys belong to this machine),
// else ~/.config. It returns "" when no home folder can be found.
func configBase(goos string, getenv func(string) string, home string) string {
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return x
	}
	if goos == "windows" {
		if l := getenv("LOCALAPPDATA"); l != "" {
			return l
		}
		if home != "" {
			return filepath.Join(home, "AppData", "Local")
		}
		return ""
	}
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".config")
}

func (a *app) configDir() (string, error) {
	p, err := a.configFile()
	if err != nil {
		return "", err
	}
	return filepath.Dir(p), nil
}
