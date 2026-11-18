package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)

func TestWriteReadListRequest(t *testing.T) {
	alice := newPerson(t, "alice")
	bob := newPerson(t, "bob")
	dir, _ := newSharedVault(t, alice)

	if err := WriteRequest(dir, bob.pub, t0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "requests", "bob.json")
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("request file: %v %v", fi, err)
	}
	req, err := ReadRequest(dir, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if req.Identity != bob.pub || !req.Created.Equal(t0) {
		t.Fatalf("round trip: %+v", req)
	}
	good, bad, err := ListRequests(dir)
	if err != nil || len(good) != 1 || len(bad) != 0 {
		t.Fatalf("list: %v %v %v", good, bad, err)
	}
	if _, err := ReadRequest(dir, "nobody"); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("missing: %v", err)
	}
	// No temp files left behind (sync-safe write).
	entries, _ := os.ReadDir(filepath.Join(dir, "requests"))
	if len(entries) != 1 {
		t.Fatalf("requests dir holds %d files", len(entries))
	}
}

func TestWriteRequestRefusals(t *testing.T) {
	alice := newPerson(t, "alice")
	bob := newPerson(t, "bob")
	other := newPerson(t, "other")
	dir, _ := newSharedVault(t, alice)

	// Not a vault folder.
	if err := WriteRequest(t.TempDir(), bob.pub, t0); err == nil {
		t.Fatal("request written outside a vault")
	}
	// Already a member (same key); same name as a member (different key).
	if err := WriteRequest(dir, alice.pub, t0); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("member's own key: %v", err)
	}
	impostor := other.pub
	impostor.Name = "alice"
	if err := WriteRequest(dir, impostor, t0); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("member's name: %v", err)
	}
	// Mismatched fingerprint and bad key.
	badFP := bob.pub
	badFP.Fingerprint = other.pub.Fingerprint
	if err := WriteRequest(dir, badFP, t0); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("wrong fingerprint: %v", err)
	}
	badKey := bob.pub
	badKey.Recipient = "age1notakey"
	if err := WriteRequest(dir, badKey, t0); !errors.Is(err, ErrInvalidRecipient) {
		t.Fatalf("bad key: %v", err)
	}
	badName := bob.pub
	badName.Name = "../escape"
	if err := WriteRequest(dir, badName, t0); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("bad name: %v", err)
	}
	// Duplicates among requests: same name, then same key under another name.
	if err := WriteRequest(dir, bob.pub, t0); err != nil {
		t.Fatal(err)
	}
	if err := WriteRequest(dir, bob.pub, t0); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("same request twice: %v", err)
	}
	renamed := bob.pub
	renamed.Name = "robert"
	if err := WriteRequest(dir, renamed, t0); !errors.Is(err, ErrRequestPending) {
		t.Fatalf("same key other name: %v", err)
	}
	clash := other.pub
	clash.Name = "bob"
	if err := WriteRequest(dir, clash, t0); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("other key same pending name: %v", err)
	}
	// An unreadable file squatting on the name also blocks it.
	mustWrite(t, filepath.Join(dir, "requests", "other.json"), []byte("junk"))
	if err := WriteRequest(dir, other.pub, t0); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("squatted name: %v", err)
	}
	// Only bob's request exists as a valid one.
	good, bad, _ := ListRequests(dir)
	if len(good) != 1 || len(bad) != 1 || bad[0].File != "other.json" {
		t.Fatalf("list: %v %v", good, bad)
	}
}

func validRequestJSON(t testing.TB) []byte {
	t.Helper()
	bob := newPerson(t, "bob")
	dir, _ := newSharedVault(t, newPerson(t, "alice"))
	if err := WriteRequest(dir, bob.pub, t0); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "requests", "bob.json"))
	return data
}

func TestParseRequestRejects(t *testing.T) {
	valid := validRequestJSON(t)
	if _, err := ParseRequest(valid); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(valid, &m)
	set := func(k string, v any) []byte {
		c := map[string]any{}
		for kk, vv := range m {
			c[kk] = vv
		}
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		b, _ := json.Marshal(c)
		return b
	}
	otherKey := newRecipient(t)
	fp := m["fingerprint"].(string)
	cases := map[string][]byte{
		"empty":             {},
		"not json":          []byte("hello"),
		"truncated":         valid[:len(valid)/2],
		"trailing":          append(bytes.Clone(valid), []byte("{}")...),
		"unknown field":     set("admin", true),
		"duplicate key":     bytes.Replace(valid, []byte(`"name"`), []byte(`"name": "x", "name"`), 1),
		"upper-case key":    bytes.Replace(valid, []byte(`"name"`), []byte(`"Name"`), 1),
		"version 2":         set("version", 2),
		"no version":        set("version", nil),
		"bad name":          set("name", "Bob!"),
		"path name":         set("name", "../bob"),
		"swapped key":       set("recipient", otherKey), // fingerprint no longer matches
		"flipped words":     set("fingerprint", strings.Replace(fp, fp[:2], "ZZ", 1)),
		"lower fingerprint": set("fingerprint", strings.ToLower(fp)),
		"bad key":           set("recipient", "age1xyz"),
		"upper key":         set("recipient", strings.ToUpper(m["recipient"].(string))),
		"no created":        set("created", nil),
		"zero created":      set("created", "0001-01-01T00:00:00Z"),
		"bad created":       set("created", "yesterday"),
		"wrong type":        set("name", 7),
		"oversize":          append(append([]byte(`{"name":"`), bytes.Repeat([]byte("a"), MaxRequestSize)...), []byte(`"}`)...),
		"invalid utf8":      bytes.Replace(valid, []byte("bob"), []byte("b\xffb"), 1),
	}
	for name, data := range cases {
		_, err := ParseRequest(data)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if len(data) > 8 && len(data) < 200 && strings.Contains(err.Error(), string(data)) {
			t.Errorf("%s: error echoes the file", name)
		}
	}
	if _, err := ParseRequest(cases["oversize"]); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversize error = %v", err)
	}
}

func TestListRequestsHandlesJunk(t *testing.T) {
	alice := newPerson(t, "alice")
	dir, _ := newSharedVault(t, alice)
	rd := filepath.Join(dir, "requests")
	mustMkdir(t, rd)
	valid := validRequestJSON(t)

	mustWrite(t, filepath.Join(rd, "bob.json"), valid)
	mustWrite(t, filepath.Join(rd, "bob (conflicted copy).json"), valid) // sync copy: ignored
	mustWrite(t, filepath.Join(rd, ".DS_Store"), []byte("x"))
	mustWrite(t, filepath.Join(rd, ".sv-tmp-123"), []byte("x"))
	mustWrite(t, filepath.Join(rd, "carol.json"), valid)            // name inside is bob
	mustWrite(t, filepath.Join(rd, "notes.txt"), []byte("x"))       // unexpected
	mustWrite(t, filepath.Join(rd, "bad\x01name.json"), []byte("")) // control char in name
	if err := os.Symlink(filepath.Join(rd, "bob.json"), filepath.Join(rd, "dan.json")); err != nil {
		t.Skip("no symlinks")
	}
	good, bad, err := ListRequests(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(good) != 1 || good[0].Identity.Name != "bob" {
		t.Fatalf("good: %+v", good)
	}
	got := map[string]bool{}
	for _, b := range bad {
		got[b.File] = true
		for _, r := range b.File {
			if r < ' ' || r > '~' {
				t.Errorf("unsanitised file name %q", b.File)
			}
		}
	}
	for _, want := range []string{"carol.json", "notes.txt", "dan.json"} {
		if !got[want] {
			t.Errorf("%s not reported (have %v)", want, got)
		}
	}
	if got["bob (conflicted copy).json"] || got[".DS_Store"] {
		t.Error("litter reported")
	}
}

func TestDeleteRequest(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	dir, _ := newSharedVault(t, alice)
	if err := DeleteRequest(dir, "bob"); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("missing: %v", err)
	}
	_ = WriteRequest(dir, bob.pub, t0)
	if err := DeleteRequest(dir, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRequest(dir, "bob"); !errors.Is(err, ErrNoRequest) {
		t.Fatal("still there")
	}
}

func FuzzParseRequest(f *testing.F) {
	valid := validRequestJSON(f)
	f.Add(valid)
	f.Add([]byte(`{"version":1,"name":"bob","recipient":"age1","fingerprint":"A-B-1","created":"2026-01-01T00:00:00Z"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := ParseRequest(data)
		if err != nil {
			if len(data) > 12 && bytes.Contains([]byte(err.Error()), data) {
				t.Fatal("error echoes input")
			}
			return
		}
		// Anything accepted must be self-consistent and safe to use as a file name.
		if ValidateMemberName(req.Identity.Name) != nil {
			t.Fatal("accepted a bad name")
		}
		if fp, err := Fingerprint(req.Identity.Recipient); err != nil || fp != req.Identity.Fingerprint {
			t.Fatal("accepted a request whose fingerprint does not match")
		}
		if _, err := RequestPath("/v", req.Identity.Name); err != nil || strings.ContainsAny(req.Identity.Name, `/\.`) && strings.Contains(req.Identity.Name, "..") {
			t.Fatal("unsafe path")
		}
	})
}
