//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"syscall"
)

func osExecutable() (string, error) { return os.Executable() }

// detach makes cmd outlive this process and its terminal.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

// exitCodeOf maps a finished child's status to a shell-style exit code.
func exitCodeOf(err *exec.ExitError) int {
	if ws, ok := err.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	if c := err.ExitCode(); c >= 0 {
		return c
	}
	return ExitError
}
