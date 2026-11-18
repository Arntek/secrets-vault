package format

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestConflictOriginal(t *testing.T) {
	cases := map[string]string{
		"index (Dan's conflicted copy 2026-11-20).json":      "index.json",
		"vault (conflicted copy).json":                       "vault.json",
		"API_KEY (Dan Smith's conflicted copy).age":          "API_KEY.age",
		"API_KEY (Dan's conflicted copy 2026-11-20) (1).age": "API_KEY.age",
		"API_KEY (1).age": "API_KEY.age",
		"index (2).json":  "index.json",
		"API_KEY.sync-conflict-20261120-101500-ABCDEFG.age": "API_KEY.age",
		"index.sync-conflict-20261120-101500-ABCDEFG.json":  "index.json",
		"photo (1).jpg":                     "", // bare (n) on an unknown file
		"API_KEY.age":                       "",
		"README.md":                         "",
		"notes (Dan's conflicted copy).txt": "notes.txt",
		"weird ((conflicted copy)).age":     "",
		"API_KEY (conflicted copy 2026-11-20).age.sv-tmp-123456": "",
	}
	for in, want := range cases {
		if got := conflictOriginal(in); got != want {
			t.Errorf("conflictOriginal(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFindConflicts(t *testing.T) {
	dir := newTestVault(t)
	files := map[string]string{
		"index (Dan's conflicted copy 2026-11-20).json": "",
		"README.md":           "",
		".DS_Store":           "",
		"secrets/API_KEY.age": "",
		"secrets/API_KEY (Dan's conflicted copy 2026-11-20).age": "",
		"secrets/OTHER (1).age":                                  "",
		"secrets/notes.txt":                                      "",
		"secrets/.DS_Store":                                      "",
		"secrets/.sv-tmp-123":                                    "",
		"secrets/.trash/API_KEY.20261117T143045.000000005Z.age":  "",
	}
	for rel := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := FindConflicts(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []Conflict{
		{Path: "index (Dan's conflicted copy 2026-11-20).json", Kind: ConflictSyncCopy, Original: "index.json"},
		{Path: "secrets/.sv-tmp-123", Kind: ConflictTempFile},
		{Path: "secrets/API_KEY (Dan's conflicted copy 2026-11-20).age", Kind: ConflictSyncCopy, Original: "secrets/API_KEY.age"},
		{Path: "secrets/OTHER (1).age", Kind: ConflictSyncCopy, Original: "secrets/OTHER.age"},
		{Path: "secrets/notes.txt", Kind: ConflictUnknown},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("FindConflicts =\n%+v\nwant\n%+v", got, want)
	}
	clean := newTestVault(t)
	if c, err := FindConflicts(clean); err != nil || len(c) != 0 {
		t.Fatalf("clean vault conflicts = %+v, %v", c, err)
	}
}

func FuzzConflictOriginal(f *testing.F) {
	for _, s := range []string{"index (Dan's conflicted copy 2026-11-20).json", "A (1).age", "x.sync-conflict-20261120-101500-ABCDEFG.age", "((("} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		orig := conflictOriginal(s)
		if orig != "" && len(orig) >= len(s) {
			t.Fatalf("original %q not shorter than %q", orig, s)
		}
	})
}

const testKeyID = "00112233445566778899aabbccddeeff"

func TestStagingCommit(t *testing.T) {
	dir := newTestVault(t)
	if err := WriteSecretFile(dir, "A", []byte("old-a")); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecretFile(dir, "T", []byte("old-t")); err != nil {
		t.Fatal(err)
	}
	trashed, err := TrashSecret(dir, "T", testTime)
	if err != nil {
		t.Fatal(err)
	}
	s, err := BeginStaging(dir, testKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddSecret("A", []byte("new-a")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSecret("A", []byte("again")); err == nil {
		t.Fatal("same file staged twice")
	}
	if err := s.AddTrashed(trashed, []byte("new-t")); err != nil {
		t.Fatal(err)
	}
	// Without a MANIFEST nothing is committed.
	if err := CommitStaged(dir, testKeyID); !errors.Is(err, ErrRotationIncomplete) {
		t.Fatalf("commit before Finish = %v", err)
	}
	if err := s.Finish(); err != nil {
		t.Fatal(err)
	}
	// Staging is invisible to the normal listing and conflict scan.
	if list, _ := ListSecrets(dir); len(list) != 1 {
		t.Fatalf("staging leaked into ListSecrets: %+v", list)
	}
	if c, _ := FindConflicts(dir); len(c) != 0 {
		t.Fatalf("staging reported as conflict: %+v", c)
	}
	if ids, _ := PendingRotations(dir); !slices.Equal(ids, []string{testKeyID}) {
		t.Fatalf("PendingRotations = %v", ids)
	}
	if got, _ := ReadSecretFile(dir, "A"); string(got) != "old-a" {
		t.Fatal("live file changed before commit")
	}
	if err := CommitStaged(dir, testKeyID); err != nil {
		t.Fatalf("CommitStaged = %v", err)
	}
	if got, _ := ReadSecretFile(dir, "A"); string(got) != "new-a" {
		t.Fatalf("A after commit = %q", got)
	}
	if got, _ := ReadTrashedFile(dir, trashed); string(got) != "new-t" {
		t.Fatalf("trashed after commit = %q", got)
	}
	if ids, _ := PendingRotations(dir); len(ids) != 0 {
		t.Fatalf("staging left after commit: %v", ids)
	}
}

func TestStagingIncompleteAndResume(t *testing.T) {
	dir := newTestVault(t)
	for _, n := range []string{"A", "B"} {
		if err := WriteSecretFile(dir, n, []byte("old")); err != nil {
			t.Fatal(err)
		}
	}
	s, err := BeginStaging(dir, testKeyID)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"A", "B"} {
		if err := s.AddSecret(n, []byte("new")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Finish(); err != nil {
		t.Fatal(err)
	}
	staged := stagingDir(dir, testKeyID)
	// A staged file not yet synced: refuse.
	if err := os.Rename(filepath.Join(staged, "B.age"), filepath.Join(t.TempDir(), "B.age")); err != nil {
		t.Fatal(err)
	}
	if err := CommitStaged(dir, testKeyID); !errors.Is(err, ErrRotationIncomplete) {
		t.Fatalf("commit with a missing file = %v", err)
	}
	if got, _ := ReadSecretFile(dir, "A"); string(got) != "old" {
		t.Fatal("partial commit happened")
	}
	// A commit that started (marker present) resumes past moved files.
	if err := os.WriteFile(filepath.Join(staged, committingName), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CommitStaged(dir, testKeyID); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReadSecretFile(dir, "A"); string(got) != "new" {
		t.Fatal("resume did not move A")
	}
	// Abandon removes a staging folder.
	s2, err := BeginStaging(dir, "ffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Abandon(); err != nil {
		t.Fatal(err)
	}
	if ids, _ := PendingRotations(dir); len(ids) != 0 {
		t.Fatalf("abandoned staging remains: %v", ids)
	}
}

func manifestBytes(keyID string, files ...string) []byte {
	b := []byte(manifestHeader + "\nkey " + keyID + "\n")
	for _, f := range files {
		b = append(b, f+"\n"...)
	}
	return b
}

func TestParseManifest(t *testing.T) {
	good := manifestBytes(testKeyID, "A.age", ".trash/A.20261117T143045.000000005Z.age")
	files, err := ParseManifest(good, testKeyID)
	if err != nil || len(files) != 2 {
		t.Fatalf("ParseManifest = %v, %v", files, err)
	}
	bad := [][]byte{
		nil,
		good[:len(good)-1],
		manifestBytes("ffffffffffffffffffffffffffffffff", "A.age"),
		manifestBytes(testKeyID, "../vault.json"),
		manifestBytes(testKeyID, "A.age", "A.age"),
		manifestBytes(testKeyID, ".trash/../../x"),
		manifestBytes(testKeyID, ""),
		[]byte("wrong header\nkey " + testKeyID + "\n"),
	}
	for i, b := range bad {
		if _, err := ParseManifest(b, testKeyID); err == nil {
			t.Errorf("bad manifest %d accepted", i)
		}
	}
}

func FuzzParseManifest(f *testing.F) {
	f.Add(manifestBytes(testKeyID, "A.age", ".trash/A.20261117T143045.000000005Z.age"))
	f.Add(manifestBytes(testKeyID))
	f.Fuzz(func(t *testing.T, data []byte) {
		files, err := ParseManifest(data, testKeyID)
		if err != nil {
			return
		}
		for _, rel := range files {
			clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(rel)))
			if clean != rel || filepath.IsAbs(rel) || rel == ".." || len(rel) > 2 && rel[:3] == "../" {
				t.Fatalf("accepted unsafe path %q", rel)
			}
		}
	})
}
