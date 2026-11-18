package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Arntek/secrets-vault/internal/leaktest"
)

// TestBinaryLeak builds the real binary and runs it through the leak
// harness, so leaks via os.Stdout/os.Stderr or files are caught end to end.
func TestBinaryLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "secrets-vault")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	h := leaktest.New(t)
	secret := h.Canary()
	cmd := h.Command(bin, secret)
	cmd.Stdin = strings.NewReader(secret + "\n")
	var exitErr *exec.ExitError
	if err := cmd.Run(); err != nil && !errors.As(err, &exitErr) {
		t.Fatal(err)
	}
	h.Check()
}
