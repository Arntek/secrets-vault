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
//   - Mapping errors to the documented exit codes.
//
// Dependency rule: cli is the top of the internal graph. It may import every
// other internal package; none of them may import cli. Keep business rules
// out of cli: it orchestrates, the packages below decide.
//
// The command set is owned by issue rn5. This scaffold only has version and
// help so the binary builds and the leak harness has something to run.
package cli

import (
	"fmt"
	"io"
	"path/filepath"
)

// Exit codes. 3 and 4 are part of the agent contract printed by `vault prime`.
const (
	ExitOK       = 0
	ExitError    = 1
	ExitUsage    = 2
	ExitLocked   = 3
	ExitNotFound = 4
)

// Version is set at build time with -ldflags "-X ...cli.Version=v1.2.3".
var Version = "dev"

// Run executes one command. args[0] is the program name as invoked, so help
// text uses whichever short name the user actually has.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	_ = stdin
	prog := "secrets-vault"
	if len(args) > 0 && args[0] != "" {
		prog = filepath.Base(args[0])
	}
	if len(args) < 2 {
		usage(stderr, prog)
		return ExitUsage
	}
	switch args[1] {
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "secrets-vault %s\n", Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout, prog)
		return ExitOK
	default:
		// Never echo unknown arguments: a value may have been pasted by
		// mistake.
		fmt.Fprintf(stderr, "%s: unknown command. Run '%s help'.\n", prog, prog)
		return ExitUsage
	}
}

func usage(w io.Writer, prog string) {
	fmt.Fprintf(w, `%[1]s: one command for every secret.

Usage:
  %[1]s <command> [flags]

Commands:
  version   Print the version
  help      Show this help

More commands arrive with the Phase 1 CLI.
`, prog)
}
