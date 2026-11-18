//go:build windows

package cli

import (
	"os"
	"os/exec"
)

func osExecutable() (string, error) { return os.Executable() }

func detach(cmd *exec.Cmd) {}

func exitCodeOf(err *exec.ExitError) int {
	if c := err.ExitCode(); c >= 0 {
		return c
	}
	return ExitError
}
