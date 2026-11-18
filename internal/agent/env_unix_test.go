//go:build unix

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A canary variable in the starting process (e.g. a secret injected by
// `vault run`) must never reach an auto-started agent.
func TestStartAgentDropsCanaryEnv(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "env.txt")
	script := filepath.Join(dir, "fake-agent.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nenv > \"$OUT_FILE\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CANARY_ENV_LEAK_TEST", "canary-value-xyz")
	t.Setenv("OUT_FILE", out) // not on the allowlist either, so pass it via the script path
	t.Setenv("SECRETS_VAULT_CONFIG", "/x/config")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nenv > '"+out+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	sock := shortDir(t)
	_, _ = DialWith(DialOptions{Dir: sock, Exe: script, StartTimeout: 200 * time.Millisecond})
	var got []byte
	for i := 0; i < 100 && len(got) == 0; i++ {
		got, _ = os.ReadFile(out)
		time.Sleep(20 * time.Millisecond)
	}
	if len(got) == 0 {
		t.Fatal("fake agent did not run")
	}
	s := string(got)
	if strings.Contains(s, "CANARY") || strings.Contains(s, "canary-value") || strings.Contains(s, "OUT_FILE") {
		t.Fatalf("agent inherited a non-allowlisted variable:\n%s", s)
	}
	if !strings.Contains(s, "SECRETS_VAULT_CONFIG=/x/config") {
		t.Fatal("allowlisted SECRETS_VAULT_* setting was dropped")
	}
}
