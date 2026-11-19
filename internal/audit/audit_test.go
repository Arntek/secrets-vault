package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func newLog(t *testing.T) *File {
	t.Helper()
	return NewFile(filepath.Join(t.TempDir(), "vault", "audit.log"))
}

func TestRecordAndReadBack(t *testing.T) {
	f := newLog(t)
	now := time.Now()
	for i, k := range []string{"A", "B", "C"} {
		if err := f.Record(Event{Time: now.Add(time.Duration(i) * time.Minute), Vault: "v", Key: k, Action: ActionRead, Program: "py", PID: 7, Command: "get"}); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := f.Read(Filter{})
	if err != nil || len(evs) != 3 || evs[0].Key != "A" || evs[2].Key != "C" || evs[1].PID != 7 || evs[1].Command != "get" {
		t.Fatalf("%v %v", evs, err)
	}
	fi, _ := os.Stat(f.Path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("log mode %v", fi.Mode())
	}
	di, _ := os.Stat(filepath.Dir(f.Path))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode())
	}
}

func TestFilters(t *testing.T) {
	f := newLog(t)
	now := time.Now()
	_ = f.Record(Event{Time: now.Add(-48 * time.Hour), Vault: "a", Key: "OLD", Action: ActionRead})
	_ = f.Record(Event{Time: now.Add(-time.Hour), Vault: "a", Key: "K1", Action: ActionRead})
	_ = f.Record(Event{Time: now, Vault: "b", Key: "K2", Action: ActionRead})
	cases := []struct {
		fl   Filter
		want int
	}{
		{Filter{}, 3},
		{Filter{Vault: "a"}, 2},
		{Filter{Key: "K2"}, 1},
		{Filter{Since: now.Add(-24 * time.Hour)}, 2},
		{Filter{Vault: "a", Since: now.Add(-24 * time.Hour)}, 1},
		{Filter{Vault: "nope"}, 0},
	}
	for _, c := range cases {
		evs, err := f.Read(c.fl)
		if err != nil || len(evs) != c.want {
			t.Fatalf("%+v: got %d (%v), want %d", c.fl, len(evs), err, c.want)
		}
	}
}

func TestRotationKeepsThreeFiles(t *testing.T) {
	f := newLog(t)
	f.MaxSize = 400
	for i := 0; i < 60; i++ {
		if err := f.Record(Event{Time: time.Now(), Vault: "v", Key: fmt.Sprintf("KEY_%02d", i), Action: ActionRead}); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Dir(f.Path)
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
		fi, _ := os.Stat(filepath.Join(dir, e.Name()))
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s has mode %v", e.Name(), fi.Mode())
		}
		if fi.Size() > 400 {
			t.Fatalf("%s grew past the limit: %d", e.Name(), fi.Size())
		}
	}
	if len(names) != 3 {
		t.Fatalf("want audit.log, .1, .2; got %v", names)
	}
	evs, err := f.Read(Filter{})
	if err != nil || len(evs) == 0 || evs[len(evs)-1].Key != "KEY_59" {
		t.Fatalf("newest event missing: %v", err)
	}
	// Oldest first across the rotated files.
	for i := 1; i < len(evs); i++ {
		if evs[i].Key < evs[i-1].Key {
			t.Fatalf("out of order: %s after %s", evs[i].Key, evs[i-1].Key)
		}
	}
}

func TestMalformedAndHugeLinesAreSkipped(t *testing.T) {
	f := newLog(t)
	_ = f.Record(Event{Vault: "v", Key: "GOOD1", Action: ActionRead})
	h, _ := os.OpenFile(f.Path, os.O_APPEND|os.O_WRONLY, 0o600)
	fmt.Fprint(h, "not json\n{\"vault\":\"x\"\n"+strings.Repeat("x", 20000)+"\n")
	_ = h.Close()
	_ = f.Record(Event{Vault: "v", Key: "GOOD2", Action: ActionRead})
	evs, err := f.Read(Filter{})
	if err != nil || len(evs) != 2 || evs[1].Key != "GOOD2" {
		t.Fatalf("%v %v", evs, err)
	}
}

func TestFieldsCannotBreakTheLine(t *testing.T) {
	f := newLog(t)
	_ = f.Record(Event{Vault: "v\n{\"fake\":1}", Key: "K\r\nX", Action: ActionRead, Program: "evil\x1b[2J" + strings.Repeat("a", 500)})
	b, _ := os.ReadFile(f.Path)
	if strings.Count(string(b), "\n") != 1 || strings.ContainsAny(string(b), "\x1b\r") {
		t.Fatalf("one record must be one clean line: %q", b)
	}
	evs, _ := f.Read(Filter{})
	if len(evs) != 1 || len(evs[0].Program) > maxFieldLen {
		t.Fatalf("%+v", evs)
	}
}

func TestErrorsDoNotCarryContentsOrPaths(t *testing.T) {
	dir := t.TempDir()
	f := NewFile(filepath.Join(dir, "audit.log"))
	if err := os.Mkdir(f.Path, 0o700); err != nil { // a directory where the file should be
		t.Fatal(err)
	}
	err := f.Record(Event{Vault: "CANARY_VAULT", Key: "CANARY_KEY", Action: ActionRead})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), dir) {
		t.Fatalf("error leaks: %v", err)
	}
	// Reading a log path that is unreadable is an error without the path too.
	if _, err := f.Read(Filter{}); err != nil && strings.Contains(err.Error(), dir) {
		t.Fatalf("read error leaks the path: %v", err)
	}
}

func TestSymlinkLogIsRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	_ = os.WriteFile(target, nil, 0o600)
	p := filepath.Join(dir, "audit.log")
	if err := os.Symlink(target, p); err != nil {
		t.Skip("no symlinks")
	}
	if err := NewFile(p).Record(Event{Vault: "v", Action: ActionRead}); err == nil {
		t.Fatal("a symlinked log must be refused")
	}
	if b, _ := os.ReadFile(target); len(b) != 0 {
		t.Fatal("wrote through the symlink")
	}
}

func TestConcurrentWritersKeepWholeLines(t *testing.T) {
	f := newLog(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Separate File values behave like separate processes.
			w := NewFile(f.Path)
			for i := 0; i < 50; i++ {
				_ = w.Record(Event{Vault: "v", Key: "K", Action: ActionRead})
			}
		}()
	}
	wg.Wait()
	evs, err := f.Read(Filter{})
	if err != nil || len(evs) != 400 {
		t.Fatalf("got %d events (%v)", len(evs), err)
	}
}

func TestMissingLogIsEmpty(t *testing.T) {
	evs, err := newLog(t).Read(Filter{})
	if err != nil || len(evs) != 0 {
		t.Fatalf("%v %v", evs, err)
	}
}

func TestCleanProgram(t *testing.T) {
	for in, want := range map[string]string{
		"-zsh": "zsh", "/usr/bin/python3": "python3", "node\n": "node", "--x": "x", "": "", "a\x00b": "ab",
	} {
		if got := CleanProgram(in); got != want {
			t.Errorf("CleanProgram(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCallerFindsAParent(t *testing.T) {
	name, pid := Caller()
	if pid != os.Getppid() {
		t.Fatalf("pid %d", pid)
	}
	t.Logf("parent: %q", name) // the name is best-effort
}

func TestLogFileIsTightenedOnWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permissions")
	}
	p := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := NewFile(p).Record(Event{Time: time.Now(), Vault: "v", Key: "K", Action: ActionRead}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}
