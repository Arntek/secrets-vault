// Package cli is the command-line interface: argument parsing, prompts,
// output formatting (--json), exit codes and the short-name aliases
// (secrets-vault, vault, sv).
//
// Responsibilities:
//   - Parsing commands and flags, and dispatching to the packages below.
//   - Reading secret values only from a hidden prompt or stdin, never from
//     arguments (so values never land in shell history).
//   - Masking values on a terminal; plain output only when piped or --reveal.
//   - The registry (~/.config/vault/config.toml): which vaults exist and
//     where. It holds no secrets.
//   - The unlock flow: agent key, Touch ID, member identity, passphrase.
//   - Mapping errors to the documented exit codes.
//
// Dependency rule: cli is the top of the internal graph. It may import every
// other internal package; none of them may import cli. Keep business rules
// out of cli: it orchestrates, the packages below decide.
//
// The command set is owned by issue rn5. ui (the terminal interface, package
// tui), prime, setup, log and doctor are in; out of scope: backup and the
// MCP server.
package cli

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Arntek/secrets-vault/internal/agent"
)

// Exit codes. 3, 4 and 5 are part of the agent contract printed by `vault
// prime`. 5 means the vault failed verification (tampered, substituted,
// rolled back, behind a state code): never treat it as "key not found".
const (
	ExitOK         = 0
	ExitError      = 1
	ExitUsage      = 2
	ExitLocked     = 3
	ExitNotFound   = 4
	ExitUnverified = 5
)

// Version is set at build time with -ldflags "-X ...cli.Version=v1.2.3".
var Version = "dev"

type command struct {
	name    string
	group   string
	usage   string // what follows the program name
	summary string
	flags   []flagSpec
	run     func(a *app, p *parsed) error
}

var (
	fJSON     = flagSpec{name: "json"}
	fVault    = flagSpec{name: "vault", value: true}
	fPassStd  = flagSpec{name: "passphrase-stdin"}
	fExpect   = flagSpec{name: "expect", value: true}
	fSignFP   = flagSpec{name: "signer-fingerprint", value: true}
	fNoDialog = flagSpec{name: "no-dialog"}
	fYes      = flagSpec{name: "yes", short: "y"}
)

// commands is the command table; help and dispatch both read it.
var commands = []command{
	{name: "list", group: "Finding keys (no unlock needed)", usage: "list [--vault V] [--tag T]",
		summary: "Every key across all vaults: name, vault, description, lock state.",
		flags:   []flagSpec{fVault, {name: "tag", value: true}}, run: cmdList},
	{name: "search", group: "Finding keys (no unlock needed)", usage: "search WORDS",
		summary: "Search names, descriptions and tags.",
		flags:   []flagSpec{fVault, {name: "tag", value: true}}, run: cmdSearch},
	{name: "info", group: "Finding keys (no unlock needed)", usage: "info NAME",
		summary: "Description, vault, tags, updated date and who last changed it.",
		flags:   []flagSpec{fVault}, run: cmdInfo},

	{name: "get", group: "Using keys", usage: "get NAME [--reveal] [-n]",
		summary: "Print one value. Masked on a terminal unless --reveal; plain when piped.",
		flags:   []flagSpec{fVault, {name: "reveal"}, {name: "no-newline", short: "n"}}, run: cmdGet},
	{name: "run", group: "Using keys", usage: "run -k A [-k B] -- cmd args",
		summary: "Run one command with only those keys set as environment variables.",
		flags:   []flagSpec{fVault, {name: "key", short: "k", value: true}}, run: cmdRun},
	{name: "copy", group: "Using keys", usage: "copy NAME",
		summary: "Copy to the clipboard, cleared after 30 seconds if unchanged.",
		flags:   []flagSpec{fVault}, run: cmdCopy},

	{name: "set", group: "Changing keys", usage: "set NAME [--desc TEXT] [--vault V]",
		summary: "Add or update. The value is typed hidden or piped in, never an argument.",
		flags:   []flagSpec{fVault, {name: "desc", value: true}}, run: cmdSet},
	{name: "describe", group: "Changing keys", usage: "describe NAME TEXT",
		summary: "Change the description without touching the value.",
		flags:   []flagSpec{fVault}, run: cmdDescribe},
	{name: "tag", group: "Changing keys", usage: "tag NAME TAG[,TAG...] [--rm]",
		summary: "Add tags for filtering (or remove them with --rm).",
		flags:   []flagSpec{fVault, {name: "rm"}}, run: cmdTag},
	{name: "mv", group: "Changing keys", usage: "mv NAME --to VAULT",
		summary: "Move a key between vaults.",
		flags:   []flagSpec{fVault, {name: "to", value: true}}, run: cmdMv},
	{name: "rename", group: "Changing keys", usage: "rename OLD NEW",
		summary: "Rename a key.",
		flags:   []flagSpec{fVault}, run: cmdRename},
	{name: "rm", group: "Changing keys", usage: "rm NAME [--yes]",
		summary: "Delete, after confirmation. Kept in the trash for 30 days.",
		flags:   []flagSpec{fVault, fYes}, run: cmdRm},

	{name: "ui", group: "Finding keys (no unlock needed)", usage: "ui",
		summary: "Full-screen terminal interface: browse, search, add, edit and move keys. Values stay masked.",
		run:     cmdUI},

	{name: "unlock", group: "Locking", usage: "unlock [VAULT] [--for DURATION]",
		summary: "Unlock ahead of time (default vault if none is named).",
		flags:   []flagSpec{{name: "for", value: true}}, run: cmdUnlock},
	{name: "lock", group: "Locking", usage: "lock [VAULT | --all]",
		summary: "Forget the key now.", flags: []flagSpec{{name: "all"}}, run: cmdLock},
	{name: "log", group: "Locking", usage: "log [--vault V] [--since 24h] [--name K] [--json]",
		summary: "Who read which key and when: program, command, time. Never values.",
		flags:   []flagSpec{fVault, {name: "since", value: true}, {name: "name", value: true}}, run: cmdLog},
	{name: "status", group: "Locking", usage: "status",
		summary: "Each vault, locked or unlocked, time left, state code, pending join requests.", run: cmdStatus},

	{name: "init", group: "Managing vaults", usage: "init NAME --path DIR [--desc TEXT] [--as NAME]",
		summary: "Create a new vault in a folder you choose (and your identity, the first time).",
		flags:   []flagSpec{{name: "path", value: true}, {name: "desc", value: true}, {name: "force"}, {name: "touchid"}, {name: "no-touchid"}, {name: "as", value: true}, {name: "no-passphrase"}}, run: cmdInit},
	{name: "attach", group: "Managing vaults", usage: "attach NAME DIR",
		summary: "Register a vault that already exists; files a join request if you are not a member.",
		flags:   []flagSpec{{name: "as", value: true}, {name: "desc", value: true}, {name: "no-request"}}, run: cmdAttach},
	{name: "detach", group: "Managing vaults", usage: "detach NAME",
		summary: "Remove from this Mac's registry. Files are untouched.", run: cmdDetach},
	{name: "vaults", group: "Managing vaults", usage: "vaults",
		summary: "List registered vaults, paths and key counts.", run: cmdVaults},
	{name: "passwd", group: "Managing vaults", usage: "passwd VAULT [--no-rotate]",
		summary: "Set a new vault passphrase and replace the vault key.",
		flags:   []flagSpec{{name: "no-rotate"}}, run: cmdPasswd},
	{name: "touchid", group: "Managing vaults", usage: "touchid on|off|status",
		summary: "Turn Touch ID on or off for your identity on this Mac (it opens every vault you're a member of).",
		run:     cmdTouchID},
	{name: "trust", group: "Managing vaults", usage: "trust VAULT [--expect CODE] [--accept-rollback]",
		summary: "Check a vault's state against a code from another member, or repair a change that raced another.",
		flags:   []flagSpec{{name: "accept-rollback"}}, run: cmdTrust},
	{name: "doctor", group: "Managing vaults", usage: "doctor VAULT [--quarantine-staging] [--adopt NAME]",
		summary: "Check a vault for sync conflicts, leftover key-rotation folders and index problems; move a foreign folder aside; adopt a file with no signed entry.",
		flags:   []flagSpec{{name: "quarantine-staging"}, {name: "adopt", value: true}, fYes}, run: cmdDoctor},
	{name: "upgrade", group: "Managing vaults", usage: "upgrade VAULT [--yes]",
		summary: "Move a vault made by an earlier version to the current format (signed index, versioned files).",
		flags:   []flagSpec{fYes}, run: cmdUpgrade},
	{name: "rebuild", group: "Managing vaults", usage: "rebuild VAULT [--yes]",
		summary: "Recreate a vault under your identity (lost identity, or a full history); members join again.",
		flags:   []flagSpec{fYes}, run: cmdRebuild},

	{name: "member", group: "Sharing", usage: "member approve|rm|list|requests|log VAULT [NAME]",
		summary: "Per-person keys: approve a join request, remove a member, list members, requests or the signed history.",
		flags: []flagSpec{fYes, {name: "fingerprint", value: true}, {name: "readd"}, {name: "keep-passphrase"},
			{name: "new-passphrase"}, {name: "new-passphrase-stdin"}, {name: "folder-access-removed"}}, run: cmdMember},
	{name: "identity", group: "Sharing", usage: "identity export|import FILE",
		summary: "Move your identity to another Mac (passphrase-protected file).", run: cmdIdentity},

	{name: "prime", group: "AI agents", usage: "prime [--json]",
		summary: "Print the rules for AI agents and which vaults exist and are unlocked. Never prints a value.", run: cmdPrime},
	{name: "setup", group: "AI agents", usage: "setup claude [--claude-md] | setup agents [--path DIR] [--remove] [--dry-run] [--force]",
		summary: "Add agent instructions to your setup (additive only). --remove undoes exactly what was added.",
		flags:   []flagSpec{{name: "claude-md"}, {name: "remove"}, {name: "dry-run"}, {name: "force"}, {name: "path", value: true}}, run: cmdSetup},

	{name: "config", group: "Settings", usage: "config set KEY VALUE [--vault V] | config list",
		summary: "Change settings: default-ttl, default-vault, touch-every-read, dialog.",
		flags:   []flagSpec{fVault}, run: cmdConfig},
	{name: "alias", group: "Settings", usage: "alias add|rm|list NAME [--force]",
		summary: "Manage short names (vault, sv, ...) for this program.",
		flags:   []flagSpec{{name: "force"}}, run: cmdAlias},
}

func findCommand(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

// Run executes one command. args[0] is the program name as invoked, so help
// text uses whichever short name the user actually has.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	prog := "secrets-vault"
	if len(args) > 0 && args[0] != "" {
		prog = strings.TrimSuffix(filepath.Base(args[0]), ".exe")
	}
	if len(args) < 2 {
		usage(stderr, prog)
		return ExitUsage
	}
	a := newApp(prog, stdin, stdout, stderr)
	defer a.close()

	switch args[1] {
	case agent.AgentArg:
		if err := agent.Run(); err != nil {
			return ExitError
		}
		return ExitOK
	case ClipClearArg:
		return a.runClipClear()
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "secrets-vault %s\n", Version)
		return ExitOK
	case "help", "--help", "-h":
		if len(args) > 2 {
			if c := findCommand(args[2]); c != nil {
				commandHelp(stdout, prog, c)
				return ExitOK
			}
		}
		usage(stdout, prog)
		return ExitOK
	}
	c := findCommand(args[1])
	if c == nil {
		// Never echo unknown arguments: a value may have been pasted by
		// mistake.
		fmt.Fprintf(stderr, "%s: unknown command. Run '%s help'.\n", prog, prog)
		return ExitUsage
	}
	return a.dispatch(c, args[2:])
}

func (a *app) dispatch(c *command, args []string) int {
	for _, x := range args {
		if x == "--" {
			break
		}
		if x == "--help" || x == "-h" {
			commandHelp(a.out, a.prog, c)
			return ExitOK
		}
	}
	specs := append([]flagSpec{fJSON, fPassStd, fExpect, fSignFP, fNoDialog}, c.flags...)
	p, err := parseArgs(args, specs)
	if err != nil {
		return a.fail(err, c)
	}
	a.asJSON = p.has("json")
	a.passStdin = p.has("passphrase-stdin")
	a.expectCode = p.str("expect")
	a.signerFP = p.str("signer-fingerprint")
	a.noDialog = p.has("no-dialog")
	a.cmdName = c.name
	if err := c.run(a, p); err != nil {
		return a.fail(err, c)
	}
	return ExitOK
}

func (a *app) fail(err error, c *command) int {
	var ee *exitErr
	if errors.As(err, &ee) {
		if ee.msg != "" {
			fmt.Fprintf(a.errOut, "%s: %s\n", a.prog, ee.msg)
			if ee.code == ExitUsage && c != nil && !strings.HasPrefix(ee.msg, "usage:") {
				fmt.Fprintf(a.errOut, "Run '%s %s --help' for usage.\n", a.prog, c.name)
			}
		}
		return ee.code
	}
	if errors.Is(err, agent.ErrLocked) {
		fmt.Fprintf(a.errOut, "%s: the vault is locked\n", a.prog)
		return ExitLocked
	}
	fmt.Fprintf(a.errOut, "%s: %v\n", a.prog, err)
	return ExitError
}

func usage(w io.Writer, prog string) {
	fmt.Fprintf(w, "%[1]s: one command for every secret.\n\nUsage:\n  %[1]s <command> [flags]\n", prog)
	last := ""
	for _, c := range commands {
		if c.group != last {
			fmt.Fprintf(w, "\n%s:\n", c.group)
			last = c.group
		}
		fmt.Fprintf(w, "  %-46s %s\n", c.usage, c.summary)
	}
	fmt.Fprintf(w, "\nEvery command accepts --json. Exit codes: 0 ok, 1 error, 2 usage, 3 vault locked, 4 key not found, 5 vault failed verification.\n")
	fmt.Fprintf(w, "More: '%s help COMMAND', '%s version'.\n", prog, prog)
}

func commandHelp(w io.Writer, prog string, c *command) {
	fmt.Fprintf(w, "Usage: %s %s\n\n%s\n", prog, c.usage, c.summary)
	var opts []string
	for _, f := range append([]flagSpec{fJSON, fPassStd, fNoDialog}, c.flags...) {
		s := "--" + f.name
		if f.short != "" {
			s = "-" + f.short + ", " + s
		}
		if f.value {
			s += " VALUE"
		}
		opts = append(opts, s)
	}
	fmt.Fprintf(w, "\nOptions: %s\n", strings.Join(opts, ", "))
}
