package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Caller returns the name and process ID of the program that started this
// one (the parent process): "python3", "node", "zsh". The name is
// best-effort and only informative: any program can pick its own name. It
// returns "" for the name when it cannot be found.
func Caller() (string, int) {
	ppid := os.Getppid()
	if ppid <= 1 {
		return "", ppid
	}
	return CleanProgram(processName(ppid)), ppid
}

// CleanProgram reduces a process name to a short printable base name,
// without the leading dash a login shell shows ("-zsh").
func CleanProgram(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimLeft(Clean(s), "-")
}

func processName(pid int) string {
	switch runtime.GOOS {
	case "linux":
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm") // #nosec G304 -- fixed /proc path
		if err != nil {
			return ""
		}
		return string(b)
	case "darwin", "freebsd", "openbsd", "netbsd":
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "/bin/ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output() // #nosec G204 -- fixed binary, numeric argument
		if err != nil {
			return ""
		}
		return filepath.Base(strings.TrimSpace(string(out)))
	}
	return ""
}
