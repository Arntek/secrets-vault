package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Arntek/secrets-vault/internal/audit"
)

func (e *testEnv) auditPath() string { return filepath.Join(filepath.Dir(e.cfg), "audit.log") }

func (e *testEnv) auditEvents(extra ...string) []audit.Event {
	e.t.Helper()
	args := append([]string{"log", "--json"}, extra...)
	return decodeJSON[[]audit.Event](e.t, e.mustRun(args...).out)
}

func countAction(evs []audit.Event, act audit.Action, key string) int {
	n := 0
	for _, ev := range evs {
		if ev.Action == act && (key == "" || ev.Key == key) {
			n++
		}
	}
	return n
}

func TestAuditRecordsEachCommand(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.initVault("other")
	e.set("EXAMPLE_KEY", "main", "VALUE_ONE")
	e.set("EXAMPLE_TWO", "main", "VALUE_TWO")
	e.mustRun("get", "EXAMPLE_KEY")
	e.mustRun("get", "EXAMPLE_KEY", "--json")
	e.mustRun("copy", "EXAMPLE_KEY")
	e.mustRun("run", "-k", "EXAMPLE_KEY", "-k", "EXAMPLE_TWO", "--", "true")
	e.mustRun("rename", "EXAMPLE_TWO", "EXAMPLE_RENAMED")
	e.mustRun("mv", "EXAMPLE_RENAMED", "--to", "other")
	e.mustRun("rm", "EXAMPLE_RENAMED", "--yes", "--vault", "other")
	e.mustRun("lock", "main")
	e.mustRunIn(testPass+"\n", "unlock", "main", "--passphrase-stdin")
	e.mustRun("lock", "--all")

	evs := e.auditEvents()
	if n := countAction(evs, audit.ActionRead, "EXAMPLE_KEY"); n != 4 {
		t.Fatalf("EXAMPLE_KEY reads: want 4 (get, get --json, copy, run), got %d", n)
	}
	if n := countAction(evs, audit.ActionRead, "EXAMPLE_TWO"); n != 1 {
		t.Fatalf("run must record every key it passes on: %d", n)
	}
	for _, act := range []audit.Action{audit.ActionSet, audit.ActionRename, audit.ActionMove, audit.ActionDelete, audit.ActionUnlock, audit.ActionLock} {
		if countAction(evs, act, "") == 0 {
			t.Errorf("no %q event", act)
		}
	}
	for _, ev := range evs {
		if ev.Program != "testprog" || ev.PID != 4242 || ev.Command == "" || ev.Time.IsZero() {
			t.Fatalf("every event names the program, pid, command and time: %+v", ev)
		}
		if ev.Action == audit.ActionRead && ev.Vault != "main" {
			t.Fatalf("read vault: %+v", ev)
		}
	}
	var got []string
	for _, ev := range evs {
		if ev.Action == audit.ActionRead {
			got = append(got, ev.Command)
		}
	}
	if strings.Join(got, ",") != "get,get,copy,run,run" {
		t.Fatalf("commands of the reads: %v", got)
	}
	// Nothing is recorded for commands that read no value.
	n := len(evs)
	e.mustRun("list")
	e.mustRun("info", "EXAMPLE_KEY")
	e.mustRun("status")
	if len(e.auditEvents()) != n {
		t.Fatal("list, info and status must not log")
	}
}

func TestAuditRecordsDialogUnlock(t *testing.T) {
	e := lockedEnv(t)
	e.dialog.answers = []string{testPass}
	e.mustRun("get", "EXAMPLE_KEY")
	found := false
	for _, ev := range e.auditEvents() {
		if ev.Action == audit.ActionUnlock && ev.Via == "dialog" && ev.Vault == "main" {
			found = true
		}
	}
	if !found {
		t.Fatal("a dialog unlock must be in the log")
	}
}

func TestAuditRecordsMembershipChanges(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("team")
	// Passphrase change.
	e.mustRunIn(testPass+"\nnew passphrase two\n", "passwd", "team", "--passphrase-stdin")
	if countAction(e.auditEvents(), audit.ActionPasswd, "") != 1 {
		t.Fatal("passwd not logged")
	}
}

func TestAuditNeverHoldsValues(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	canary := "CANARY_VALUE_9d41f0c2"
	e.set("EXAMPLE_KEY", "main", canary)
	e.mustRun("get", "EXAMPLE_KEY")
	e.mustRun("run", "-k", "EXAMPLE_KEY", "--", "true")
	e.mustRun("copy", "EXAMPLE_KEY")
	e.mustRun("log")
	b, err := os.ReadFile(e.auditPath())
	if err != nil || len(b) == 0 {
		t.Fatalf("no log: %v", err)
	}
	if strings.Contains(string(b), canary) || strings.Contains(string(b), testPass) {
		t.Fatal("the audit log holds a value or passphrase")
	}
	fi, _ := os.Stat(e.auditPath())
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestAuditFailureWarnsOnceAndDoesNotBlock(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	e.initVault("main")
	e.set("EXAMPLE_KEY", "main", "VALUE_ONE")
	// A directory where the log file should be: every write fails.
	_ = os.Remove(e.auditPath())
	if err := os.Mkdir(e.auditPath(), 0o700); err != nil {
		t.Fatal(err)
	}
	r := e.mustRun("run", "-k", "EXAMPLE_KEY", "--", "true") // records one read, still succeeds
	if strings.Count(r.err, "read log") != 1 {
		t.Fatalf("want exactly one warning: %q", r.err)
	}
	notContains(t, "warning", r.err, "VALUE_ONE", "EXAMPLE_KEY", e.home)
	r = e.mustRun("get", "EXAMPLE_KEY")
	if strings.TrimSpace(r.out) != "VALUE_ONE" || strings.Count(r.err, "read log") != 1 {
		t.Fatalf("%s", r)
	}
}

func TestLogFilters(t *testing.T) {
	skipWindows(t)
	e := newEnv(t)
	now := time.Now()
	lg := audit.NewFile(e.auditPath())
	rec := func(ago time.Duration, vault, key string, act audit.Action) {
		if err := lg.Record(audit.Event{Time: now.Add(-ago), Vault: vault, Key: key, Action: act, Program: "py", PID: 5, Command: "get"}); err != nil {
			t.Fatal(err)
		}
	}
	rec(72*time.Hour, "work", "OLD_KEY", audit.ActionRead)
	rec(2*time.Hour, "work", "EXAMPLE_ONE", audit.ActionRead)
	rec(time.Hour, "home", "EXAMPLE_TWO", audit.ActionRead)
	rec(time.Minute, "work", "EXAMPLE_TWO", audit.ActionRead)

	cases := []struct {
		args []string
		want int
	}{
		{nil, 4},
		{[]string{"--vault", "work"}, 3},
		{[]string{"--since", "24h"}, 3},
		{[]string{"--since", "90m"}, 2},
		{[]string{"--since", "4d"}, 4},
		{[]string{"--name", "EXAMPLE_TWO"}, 2},
		{[]string{"--vault", "work", "--name", "EXAMPLE_TWO", "--since", "1h"}, 1},
		{[]string{"--vault", "nothing"}, 0},
	}
	for _, c := range cases {
		if got := len(e.auditEvents(c.args...)); got != c.want {
			t.Errorf("%v: want %d, got %d", c.args, c.want, got)
		}
	}
	r := e.mustRun("log", "--vault", "home")
	for _, w := range []string{"EXAMPLE_TWO", "home", "read", "py (5)", "WHEN"} {
		if !strings.Contains(r.out, w) {
			t.Fatalf("table lacks %q:\n%s", w, r.out)
		}
	}
	if !strings.Contains(e.mustRun("log", "--vault", "nothing").out, "Nothing logged") {
		t.Fatal("empty message")
	}
	expectCode(t, e.run("log", "--since", "yesterday"), ExitUsage)
	expectCode(t, e.run("log", "extra"), ExitUsage)
	// A JSON line is one object per event with the documented fields.
	var raw []map[string]any
	if err := json.Unmarshal([]byte(e.mustRun("log", "--json", "--name", "EXAMPLE_ONE").out), &raw); err != nil || len(raw) != 1 {
		t.Fatalf("%v", err)
	}
	for _, k := range []string{"time", "vault", "key", "action", "program", "pid", "command"} {
		if _, ok := raw[0][k]; !ok {
			t.Errorf("json lacks %q", k)
		}
	}
	// No log yet: an empty list, not an error.
	e2 := newEnv(t)
	if got := e2.mustRun("log", "--json").out; strings.TrimSpace(got) != "[]" {
		t.Fatalf("%q", got)
	}
}
