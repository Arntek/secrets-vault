package members

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Arntek/secrets-vault/internal/format"
)

func TestWriteRequestRefusals(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	v := newVault(t, alice)
	if err := WriteRequest(v.dir, alice.un, t0); !errors.Is(err, ErrAlreadyMember) {
		t.Fatalf("member's own request = %v", err)
	}
	if err := WriteRequest(v.dir, bob.un, t0); err != nil {
		t.Fatal(err)
	}
	if err := WriteRequest(v.dir, bob.un, t0); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("second request = %v", err)
	}
	other := newPerson(t, "bob") // same name, other keys
	if err := WriteRequest(v.dir, other.un, t0); !errors.Is(err, ErrDuplicateName) {
		t.Fatalf("name clash = %v", err)
	}
	reqs, bad, err := ListRequests(v.dir, v.c.File.ID)
	if err != nil || len(reqs) != 1 || len(bad) != 0 {
		t.Fatalf("list = %+v %+v %v", reqs, bad, err)
	}
}

func TestListRequestsHandlesJunk(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	v := newVault(t, alice)
	if err := WriteRequest(v.dir, bob.un, t0); err != nil {
		t.Fatal(err)
	}
	rd := filepath.Join(v.dir, "requests")
	valid := mustReadFile(t, filepath.Join(rd, "bob.json"))
	mustWriteFile(t, filepath.Join(rd, "bob (conflicted copy).json"), valid) // sync copy: ignored
	mustWriteFile(t, filepath.Join(rd, ".DS_Store"), []byte("x"))
	mustWriteFile(t, filepath.Join(rd, "carol.json"), valid)            // name inside is bob
	mustWriteFile(t, filepath.Join(rd, "notes.txt"), []byte("x"))       // unexpected
	mustWriteFile(t, filepath.Join(rd, "bad\x01name.json"), []byte("")) // control char in name
	if err := os.Symlink(filepath.Join(rd, "bob.json"), filepath.Join(rd, "dan.json")); err != nil {
		t.Skip("no symlinks")
	}
	good, bad, err := ListRequests(v.dir, v.c.File.ID)
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

// ue1.4: a symlinked requests/ folder is refused before any write.
func TestRequestsDirSymlinkRefused(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	v := newVault(t, alice)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(v.dir, "requests")); err != nil {
		t.Skip("no symlinks")
	}
	if err := WriteRequest(v.dir, bob.un, t0); err == nil {
		t.Fatal("request written through a symlinked folder")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatal("wrote outside the vault")
	}
}

func TestDeleteRequest(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	v := newVault(t, alice)
	if err := DeleteRequest(v.dir, "bob"); !errors.Is(err, ErrNoRequest) {
		t.Fatalf("missing: %v", err)
	}
	_ = WriteRequest(v.dir, bob.un, t0)
	if err := DeleteRequest(v.dir, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRequest(v.dir, v.c.File.ID, "bob"); !errors.Is(err, ErrNoRequest) {
		t.Fatal("still there")
	}
}

func FuzzParseRequest(f *testing.F) {
	alice, bob := newPerson(f, "alice"), newPerson(f, "bob")
	v := newVault(f, alice)
	_ = WriteRequest(v.dir, bob.un, t0)
	valid := mustReadFile(f, filepath.Join(v.dir, "requests", "bob.json"))
	id := v.c.File.ID
	f.Add(valid)
	f.Add([]byte(`{"version":2,"body":"e30=","sig":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := ParseRequest(data, id)
		if err != nil {
			if len(data) > 12 && bytes.Contains([]byte(err.Error()), data) {
				t.Fatal("error echoes input")
			}
			return
		}
		if ValidateMemberName(req.Identity.Name) != nil {
			t.Fatal("accepted a bad name")
		}
		if fp, err := Fingerprint(req.Identity.Recipient, req.Identity.SignKey); err != nil || fp != req.Identity.Fingerprint {
			t.Fatal("accepted a request whose fingerprint does not match")
		}
	})
}

// ue1.8: every file whose format changed carries a version number above
// what builds from before the membership log accept, so those builds
// refuse them ("upgrade") instead of misreading them. Those builds accepted
// vault.json, identity and request files of version 1 only.
func TestFormatVersionsBumped(t *testing.T) {
	if format.VaultVersion <= 1 || identityVersion <= 1 || requestVersion <= 1 {
		t.Fatalf("versions: vault %d, identity %d, request %d", format.VaultVersion, identityVersion, requestVersion)
	}
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	v := newVault(t, alice)
	_ = WriteRequest(v.dir, bob.un, t0)
	for _, p := range []string{format.VaultFilePath(v.dir), filepath.Join(v.dir, "requests", "bob.json"), alice.store.path()} {
		if !bytes.Contains(mustReadFile(t, p), []byte(`"version": 2`)) {
			t.Errorf("%s is not written as version 2", filepath.Base(p))
		}
	}
}
