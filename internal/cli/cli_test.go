package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Arntek/secrets-vault/internal/leaktest"
)

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"sv", "version"}, nil, &out, &errOut); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.HasPrefix(out.String(), "secrets-vault ") {
		t.Fatalf("unexpected version output %q", out.String())
	}
}

func TestHelpUsesInvokedName(t *testing.T) {
	var out bytes.Buffer
	Run([]string{"/opt/homebrew/bin/sv", "help"}, nil, &out, &out)
	if !strings.Contains(out.String(), "sv <command>") {
		t.Fatalf("help should use the invoked name: %q", out.String())
	}
}

func TestNoArgsIsUsageError(t *testing.T) {
	var out bytes.Buffer
	if code := Run([]string{"vault"}, nil, &out, &out); code != ExitUsage {
		t.Fatalf("exit %d, want %d", code, ExitUsage)
	}
}

// A secret pasted where a command was expected must not be echoed back.
func TestUnknownCommandDoesNotEchoArgs(t *testing.T) {
	leaktest.RunFunc(t, func(h *leaktest.Harness) {
		secret := h.Canary()
		code := Run([]string{"vault", secret}, strings.NewReader(secret), h.Stdout, h.Stderr)
		if code != ExitUsage {
			t.Errorf("exit %d, want %d", code, ExitUsage)
		}
	})
}
