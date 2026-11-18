package cli

import (
	"path/filepath"
	"testing"

	"github.com/Arntek/secrets-vault/internal/leaktest"
)

// TestLeakBroadCommandSequence runs most of the command set with canary
// values (secret values, passphrases, a value pasted where it must not be)
// and fails if a canary reaches stdout, stderr, logs, temp files or HOME.
// Commands that legitimately print a value (get when piped, run's child) go
// to their own buffers, which the harness does not scan.
func TestLeakBroadCommandSequence(t *testing.T) {
	skipWindows(t)
	h := leaktest.New(t)
	owner := newEnvAt(t, filepath.Join(h.HomeDir, "owner"))
	dan := newEnvAt(t, filepath.Join(h.HomeDir, "dan"))
	owner.touch.avail = true

	passA, passB := h.Canary(), h.Canary()
	vals := []string{h.Canary(), h.Canary(), h.Canary()}
	wrong := h.Canary()
	personal, transfer := h.Canary(), h.Canary()
	pasted := h.Canary()
	danPass := h.Canary()
	dirA := filepath.Join(owner.home, "vaults", "one")
	dirB := filepath.Join(owner.home, "vaults", "two")

	run := func(e *testEnv, stdin string, args ...string) int {
		t.Helper()
		return e.runTo(h.Stdout, h.Stderr, stdin, args...)
	}
	// ok is run for steps that must succeed, so the sequence cannot pass by
	// failing early and never touching a secret.
	ok := func(e *testEnv, stdin string, args ...string) {
		t.Helper()
		if code := run(e, stdin, args...); code != 0 {
			t.Fatalf("step %v exited %d", args[0], code)
		}
	}

	ok(owner, personal+"\n"+passA+"\n", "init", "one", "--path", dirA, "--passphrase-stdin", "--desc", "first vault", "--as", "owner")
	ok(owner, personal+"\n"+passB+"\n", "init", "two", "--path", dirB, "--passphrase-stdin")
	ok(owner, "", "lock", "--all")
	run(owner, wrong+"\n"+wrong+"\n", "unlock", "one", "--passphrase-stdin") // wrong passphrases
	ok(owner, wrong+"\n"+passA+"\n", "unlock", "one", "--passphrase-stdin")  // identity fails, vault passphrase works
	ok(owner, personal+"\n", "unlock", "two", "--passphrase-stdin")
	ok(owner, vals[0], "set", "EXAMPLE_KEY_ONE", "--desc", "first", "--vault", "one")
	ok(owner, vals[1], "set", "EXAMPLE_KEY_TWO", "--vault", "one")
	ok(owner, vals[2], "set", "EXAMPLE_KEY_THREE", "--vault", "two")
	run(owner, "", "set", "EXAMPLE_KEY_ONE", pasted) // value as an argument
	run(owner, "", "set", "EXAMPLE_KEY_ONE", "--value", pasted)
	run(owner, "", pasted)        // pasted where a command goes
	run(owner, "", "get", pasted) // pasted where a name goes
	run(owner, "", "list", "--"+pasted)
	run(owner, "", "get", "EXAMPLE_KEY_ONE", "extra", pasted)
	run(owner, "", "trust", "one", "--expect", pasted)
	ok(owner, "", "list")
	ok(owner, "", "list", "--json")
	ok(owner, "", "search", "example")
	ok(owner, "", "info", "EXAMPLE_KEY_ONE")
	ok(owner, "", "info", "EXAMPLE_KEY_ONE", "--json")
	ok(owner, "", "describe", "EXAMPLE_KEY_ONE", "a description")
	ok(owner, "", "tag", "EXAMPLE_KEY_ONE", "alpha,beta")
	ok(owner, "", "vaults")
	ok(owner, "", "doctor", "one")
	run(owner, "", "doctor", "one", "--adopt", "EXAMPLE_KEY_ONE", "--yes") // not unlisted: refused
	ok(owner, "", "upgrade", "one")                                        // already current
	ok(owner, "", "status")
	ok(owner, "", "status", "--json")
	ok(owner, "", "trust", "one")
	ok(owner, "", "member", "log", "one")
	ok(owner, "", "mv", "EXAMPLE_KEY_TWO", "--to", "two")
	ok(owner, "", "rename", "EXAMPLE_KEY_TWO", "EXAMPLE_KEY_RENAMED")
	ok(owner, "", "copy", "EXAMPLE_KEY_ONE")
	owner.term.stdoutTTY = true
	ok(owner, "", "get", "EXAMPLE_KEY_ONE")
	ok(owner, "", "get", "EXAMPLE_KEY_ONE", "--json")
	owner.term.stdoutTTY = false
	ok(owner, personal+"\n", "touchid", "on", "--passphrase-stdin")
	ok(owner, "", "touchid", "status")
	ok(owner, "", "touchid", "off")
	ok(owner, "", "config", "set", "default-ttl", "2h")
	ok(owner, "", "config", "list")
	ok(owner, "", "alias", "add", "kv")
	ok(owner, "", "alias", "list")
	ok(owner, "", "alias", "rm", "kv")
	ok(owner, "", "rm", "EXAMPLE_KEY_RENAMED", "--yes")
	ok(owner, "", "run", "-k", "EXAMPLE_KEY_ONE", "--", "true")
	run(owner, "", "run", "-k", "EXAMPLE_KEY_ONE", "--", "/no/such/program", pasted)
	ok(owner, personal+"\n"+passB+"\n", "passwd", "one", "--passphrase-stdin")
	ok(owner, "", "lock", "--all")
	run(owner, "", "get", "EXAMPLE_KEY_ONE")
	run(owner, "", "run", "-k", "EXAMPLE_KEY_ONE", "--", "true")
	ok(owner, personal+"\n", "unlock", "one", "--passphrase-stdin")

	// Members and identities.
	ok(dan, danPass+"\n", "attach", "one", dirA, "--as", "dan", "--passphrase-stdin")
	ok(owner, "", "member", "requests", "one")
	ok(owner, "", "member", "requests", "one", "--json")
	reqs := decodeJSON[map[string]any](t, func() string {
		var out, errb bufferPair
		owner.runTo(&out, &errb, "", "member", "requests", "one", "--json")
		return out.String()
	}())
	fp := reqs["requests"].([]any)[0].(map[string]any)["fingerprint"].(string)
	run(owner, personal+"\n", "member", "approve", "one", "dan", "--fingerprint", pasted, "--passphrase-stdin")
	ok(owner, personal+"\n", "member", "approve", "one", "dan", "--fingerprint", fp, "--passphrase-stdin")
	ok(owner, "", "member", "list", "one")
	ml := decodeJSON[map[string]any](t, func() string {
		var out, errb bufferPair
		owner.runTo(&out, &errb, "", "member", "list", "one", "--json")
		return out.String()
	}())
	var ownerFP string
	for _, m := range ml["members"].([]any) {
		if m.(map[string]any)["name"] == "owner" {
			ownerFP = m.(map[string]any)["fingerprint"].(string)
		}
	}
	run(dan, danPass+"\n", "unlock", "one", "--passphrase-stdin", "--signer-fingerprint", pasted)
	ok(dan, danPass+"\n", "unlock", "one", "--passphrase-stdin", "--signer-fingerprint", ownerFP)
	ok(dan, "", "status")
	file := filepath.Join(dan.home, "id.export")
	ok(dan, danPass+"\n"+transfer+"\n", "identity", "export", file, "--passphrase-stdin")
	mac2 := newEnvAt(t, filepath.Join(h.HomeDir, "mac2"))
	ok(mac2, transfer+"\n"+danPass+"\n", "identity", "import", file, "--passphrase-stdin")
	ok(owner, personal+"\n", "member", "rm", "one", "dan", "--yes", "--folder-access-removed", "--passphrase-stdin")
	ok(owner, personal+"\n"+passB+"\n", "rebuild", "two", "--yes", "--passphrase-stdin")

	// Out-of-band: legitimate outputs of values, not scanned.
	owner.runIn("", "get", "EXAMPLE_KEY_ONE")
	owner.runIn("", "run", "-k", "EXAMPLE_KEY_ONE", "--", "env")
	h.Check()
}

// bufferPair is a tiny io.Writer so the sequence above can read one output.
type bufferPair struct{ b []byte }

func (w *bufferPair) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }
func (w *bufferPair) String() string              { return string(w.b) }
