package cli

import (
	"strings"
	"testing"
)

// 33p: a mistyped --expect code. The format and the vault name are checked
// before anything is pinned; a code that doesn't match the vault's history
// says so (not "behind"); status shows the pending expectation; the correct
// code replaces it.
func TestExpectTypoIsClearAndRecoverable(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("team")
	e.unlock("team")
	e.set("K", "", "v")
	good := decodeJSON[map[string]any](t, e.mustRun("trust", "team", "--json").out)["state_code"].(string)

	// Bad format and a code for another vault: usage errors, nothing pinned.
	expectCode(t, e.run("trust", "team", "--expect", "team@0 NOT-A-CODE"), ExitUsage)
	r := e.run("trust", "team", "--expect", "other@0 ABLE-ABLE-ABLE-ABLE-ABLE-ABLE")
	expectCode(t, r, ExitUsage)
	if !strings.Contains(r.err, "different vault") {
		t.Fatalf("%s", r)
	}
	e.mustRun("get", "K") // still usable: nothing was remembered

	// Same sequence, wrong words: "doesn't match", not "behind"; blocks the vault.
	bad := good[:strings.LastIndex(good, "-")] + "-ABLE"
	r = e.run("trust", "team", "--expect", bad)
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "doesn't match this vault's history") || strings.Contains(r.err, "behind") {
		t.Fatalf("%s", r)
	}
	expectCode(t, e.run("get", "K"), ExitUnverified)
	st := e.mustRun("status").out
	if !strings.Contains(st, "blocked") || !strings.Contains(st, "waiting for state team@") || strings.Contains(st, "unlocked") {
		t.Fatalf("status should show the pending expectation:\n%s", st)
	}
	js := decodeJSON[[]map[string]any](t, e.mustRun("status", "--json").out)
	if js[0]["expecting"] == nil || js[0]["unlocked"] != false {
		t.Fatalf("status --json: %v", js)
	}
	// The correct code replaces the mistyped one.
	e.mustRun("trust", "team", "--expect", good)
	if got := e.mustRun("get", "K").out; got != "v\n" {
		t.Fatalf("after the right code: %q", got)
	}
	if st := e.mustRun("status").out; strings.Contains(st, "blocked") {
		t.Fatalf("still blocked:\n%s", st)
	}
	// A code beyond the folder's last entry is a folder that is behind.
	r = e.run("trust", "team", "--expect", "team@99 ABLE-ABLE-ABLE-ABLE-ABLE-ABLE")
	expectCode(t, r, ExitUnverified)
	if !strings.Contains(r.err, "behind") {
		t.Fatalf("%s", r)
	}
}

// 3zx: a first-time attach with no terminal and no --as is refused before
// anything is registered, so the retry with --as works.
func TestAttachWithoutNameLeavesNothingBehind(t *testing.T) {
	skipWindows(t)
	owner := newEnv(t)
	dir := owner.initVault("team")
	guest := newEnv(t)
	r := guest.runIn(personalPass+"\n", "attach", "team", dir, "--passphrase-stdin")
	expectCode(t, r, ExitUsage)
	if !strings.Contains(r.err, "run attach in a terminal, or pass --as NAME") {
		t.Fatalf("%s", r)
	}
	if out := guest.mustRun("vaults").out; strings.Contains(out, "team") {
		t.Fatalf("the vault was registered anyway:\n%s", out)
	}
	r = guest.runIn(personalPass+"\n", "attach", "team", dir, "--as", "guest", "--passphrase-stdin")
	expectCode(t, r, 0)
	if !strings.Contains(r.out, "Request written") && !strings.Contains(r.out, "request") {
		t.Fatalf("retry: %s", r)
	}
}
