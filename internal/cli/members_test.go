package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const personalPass = "personal passphrase 1"

// TestMembersFlowThroughCLI: two people, two identities, one shared folder:
// attach -> join request -> approve -> read, then removal with rotation.
func TestMembersFlowThroughCLI(t *testing.T) {
	skipWindows(t)
	owner := newEnv(t)
	dan := newEnv(t)
	vdir := owner.initVault("team")
	owner.unlock("team")
	owner.set("EXAMPLE_TEAM_KEY", "", "team-secret-value")

	// Dan attaches: first run creates his identity and files a request.
	r := dan.runIn(personalPass+"\n", "attach", "team", vdir, "--as", "dan", "--passphrase-stdin")
	expectCode(t, r, 0)
	if !strings.Contains(r.out, "not a member") || !strings.Contains(r.out, "Ask a member to approve fingerprint") {
		t.Fatalf("attach output: %s", r)
	}
	// Without a terminal and without --as, a first-time attach explains itself.
	stranger := newEnv(t)
	expectCode(t, stranger.run("attach", "team", vdir), ExitError)

	// Dan cannot read yet.
	expectCode(t, dan.runIn(personalPass+"\n", "get", "EXAMPLE_TEAM_KEY", "--passphrase-stdin"), ExitError)

	// The owner sees the request (also in status).
	req := decodeJSON[map[string]any](t, owner.mustRun("member", "requests", "team", "--json").out)
	reqs := req["requests"].([]any)
	if len(reqs) != 1 {
		t.Fatalf("requests: %v", req)
	}
	fp := reqs[0].(map[string]any)["fingerprint"].(string)
	if fp == "" || reqs[0].(map[string]any)["name"] != "dan" {
		t.Fatalf("request: %v", reqs[0])
	}
	if !strings.Contains(owner.mustRun("status").out, "1 join request") || !strings.Contains(owner.mustRun("status").out, fp) {
		t.Fatal("status should show the pending request and its fingerprint")
	}
	if !strings.Contains(owner.mustRun("member", "requests", "team").out, fp) {
		t.Fatal("requests table should show the fingerprint")
	}

	// Approval needs a human check: nothing happens without it.
	expectCode(t, owner.run("member", "approve", "team", "dan"), ExitError)                                     // no terminal
	expectCode(t, owner.run("member", "approve", "team", "dan", "--fingerprint", "WRONG-WORD-0000"), ExitError) // wrong fingerprint
	owner.term.stdinTTY = true
	r = owner.runIn("n\n", "member", "approve", "team", "dan")
	expectCode(t, r, ExitError)
	if !strings.Contains(r.out, fp) {
		t.Fatalf("approve should show the fingerprint: %s", r)
	}
	if l := decodeJSON[map[string]any](t, owner.mustRun("member", "list", "team", "--json").out); len(l["members"].([]any)) != 0 {
		t.Fatalf("nothing should have been approved: %v", l)
	}
	owner.mustRunIn("y\n", "member", "approve", "team", "dan")
	owner.term.stdinTTY = false
	expectCode(t, owner.run("member", "approve", "team", "dan", "--fingerprint", fp), ExitError) // request is gone now

	ml := owner.mustRun("member", "list", "team").out
	if !strings.Contains(ml, "dan") || !strings.Contains(ml, fp) {
		t.Fatalf("member list: %s", ml)
	}

	// Dan reads with his own key: no vault passphrase involved.
	r = dan.runIn(personalPass+"\n", "get", "EXAMPLE_TEAM_KEY", "--passphrase-stdin")
	expectCode(t, r, 0)
	if r.out != "team-secret-value\n" {
		t.Fatalf("dan's read: %q", r.out)
	}
	// Unlocked for the window: no more passphrase.
	if got := dan.mustRun("get", "EXAMPLE_TEAM_KEY").out; got != "team-secret-value\n" {
		t.Fatalf("%q", got)
	}
	// Without a terminal and after locking, Dan is told to unlock.
	dan.mustRun("lock", "--all")
	expectCode(t, dan.run("get", "EXAMPLE_TEAM_KEY"), ExitLocked)
	// He can also write: the owner then reads Dan's key.
	dan.mustRunIn(personalPass+"\n", "unlock", "team", "--passphrase-stdin")
	dan.mustRunIn("from-dan", "set", "EXAMPLE_DAN_KEY", "--vault", "team")
	if got := owner.mustRun("get", "EXAMPLE_DAN_KEY").out; got != "from-dan\n" {
		t.Fatalf("%q", got)
	}
	info := decodeJSON[map[string]any](t, owner.mustRun("info", "EXAMPLE_DAN_KEY", "--json").out)
	if info["updated_by"] != "dan" {
		t.Fatalf("updated_by: %v", info)
	}

	// Removal: confirmation, the vault passphrase to keep recovery, rotation.
	expectCode(t, owner.runIn(testPass+"\n", "member", "rm", "team", "dan", "--passphrase-stdin"), ExitError) // needs --yes without a terminal
	expectCode(t, owner.runIn("wrong passphrase!\n", "member", "rm", "team", "dan", "--yes", "--passphrase-stdin"), ExitError)
	expectCode(t, owner.run("member", "rm", "team", "nobody", "--yes"), ExitError)
	r = owner.mustRunIn(testPass+"\n", "member", "rm", "team", "dan", "--yes", "--passphrase-stdin")
	for _, want := range []string{"EXAMPLE_TEAM_KEY", "EXAMPLE_DAN_KEY", "Rotate them"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("removal should list exposed keys; missing %q:\n%s", want, r.out)
		}
	}
	// The owner keeps working without another prompt, on the new key.
	if got := owner.mustRun("get", "EXAMPLE_TEAM_KEY").out; got != "team-secret-value\n" {
		t.Fatalf("%q", got)
	}
	if l := decodeJSON[map[string]any](t, owner.mustRun("member", "list", "team", "--json").out); len(l["members"].([]any)) != 0 {
		t.Fatalf("dan should be gone: %v", l)
	}
	// Dan is locked out: his pinned key no longer matches, and his member
	// key opens nothing.
	dan.mustRun("lock", "--all")
	r = dan.runIn(personalPass+"\n", "get", "EXAMPLE_TEAM_KEY", "--passphrase-stdin")
	if r.code == 0 {
		t.Fatalf("a removed member must not read: %s", r)
	}
	notContains(t, "removed member's output", r.out+r.err, "team-secret-value")
	r = dan.runIn(personalPass+"\n", "unlock", "team", "--accept-key-change", "--passphrase-stdin")
	if r.code == 0 {
		t.Fatalf("a removed member must not unlock even if they accept the key change: %s", r)
	}
}

func TestMemberRemoveAsksOnTerminal(t *testing.T) {
	skipWindows(t)
	owner := newEnv(t)
	dan := newEnv(t)
	vdir := owner.initVault("team")
	owner.unlock("team")
	dan.mustRunIn(personalPass+"\n", "attach", "team", vdir, "--as", "dan", "--passphrase-stdin")
	owner.mustRun("member", "approve", "team", "dan", "--fingerprint", func() string {
		j := decodeJSON[map[string]any](t, owner.mustRun("member", "requests", "team", "--json").out)
		return j["requests"].([]any)[0].(map[string]any)["fingerprint"].(string)
	}())
	owner.term.stdinTTY = true
	owner.term.queue(testPass)
	expectCode(t, owner.runIn("n\n", "member", "rm", "team", "dan"), ExitError) // declined
	if l := decodeJSON[map[string]any](t, owner.mustRun("member", "list", "team", "--json").out); len(l["members"].([]any)) != 1 {
		t.Fatalf("declined removal must change nothing: %v", l)
	}
	owner.mustRunIn("y\n", "member", "rm", "team", "dan")
}

func TestIdentityExportImportAndSecondMac(t *testing.T) {
	skipWindows(t)
	owner := newEnv(t)
	mac1 := newEnv(t)
	mac2 := newEnv(t)
	vdir := owner.initVault("team")
	owner.unlock("team")
	owner.set("EXAMPLE_TEAM_KEY", "", "team-secret-value")

	mac1.mustRunIn(personalPass+"\n", "attach", "team", vdir, "--as", "dan", "--passphrase-stdin")
	j := decodeJSON[map[string]any](t, owner.mustRun("member", "requests", "team", "--json").out)
	fp := j["requests"].([]any)[0].(map[string]any)["fingerprint"].(string)
	owner.mustRun("member", "approve", "team", "dan", "--fingerprint", fp)

	// Export from the first Mac, import on the second.
	file := filepath.Join(mac1.home, "identity.export")
	expectCode(t, mac2.run("identity", "export", file), ExitError) // no identity there yet
	mac1.mustRunIn(personalPass+"\n"+"transfer passphrase 1\n", "identity", "export", file, "--passphrase-stdin")
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("export file: %v %v", fi, err)
	}
	expectCode(t, mac1.runIn(personalPass+"\n"+"transfer passphrase 1\n", "identity", "export", file, "--passphrase-stdin"), ExitError) // never overwrites
	expectCode(t, mac2.runIn("wrong transfer pass\nnew personal pass 22\n", "identity", "import", file, "--passphrase-stdin"), ExitError)
	mac2.mustRunIn("transfer passphrase 1\nmac two passphrase 2\n", "identity", "import", file, "--passphrase-stdin")
	expectCode(t, mac2.runIn("transfer passphrase 1\nmac two passphrase 2\n", "identity", "import", file, "--passphrase-stdin"), ExitError) // already has one

	// Same person: attach is registered straight away (already a member).
	r := mac2.mustRun("attach", "team", vdir)
	if !strings.Contains(r.out, "Registered 'team' (1 keys)") || strings.Contains(r.out, "not a member") {
		t.Fatalf("second Mac attach: %s", r)
	}
	if got := mac2.runIn("mac two passphrase 2\n", "get", "EXAMPLE_TEAM_KEY", "--passphrase-stdin"); got.out != "team-secret-value\n" {
		t.Fatalf("second Mac read: %s", got)
	}
	// Exported files are not accepted as an identity of their own.
	expectCode(t, mac2.run("identity", "bogus", file), ExitUsage)
}

func TestAttachFilesPendingRequestOnce(t *testing.T) {
	skipWindows(t)
	owner := newEnv(t)
	dan := newEnv(t)
	vdir := owner.initVault("team")
	dan.mustRunIn(personalPass+"\n", "attach", "team", vdir, "--as", "dan", "--passphrase-stdin")
	dan.mustRun("detach", "team")
	r := dan.mustRun("attach", "team", vdir) // identity exists now; request already pending
	if !strings.Contains(r.out, "already waiting") {
		t.Fatalf("%s", r)
	}
	reqs := decodeJSON[map[string]any](t, owner.mustRun("member", "requests", "team", "--json").out)
	if len(reqs["requests"].([]any)) != 1 {
		t.Fatalf("one request expected: %v", reqs)
	}
	// Interactive first-time attach asks for a name and passphrase.
	eve := newEnv(t)
	eve.term.stdinTTY = true
	eve.term.queue(personalPass, personalPass)
	eve.mustRunIn("eve\nn\n", "attach", "team", vdir)
	if !strings.Contains(owner.mustRun("member", "requests", "team").out, "eve") {
		t.Fatal("eve's request should be listed")
	}
}
