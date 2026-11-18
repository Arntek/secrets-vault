package format

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func newTestVault(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	if err := CreateVault(dir, validVaultFile()); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCreateVault(t *testing.T) {
	dir := newTestVault(t)
	vf, err := ReadVaultFile(dir)
	if err != nil {
		t.Fatal(err)
	}
	if vf.Name != "personal" {
		t.Fatalf("name = %q", vf.Name)
	}
	idx, err := ReadIndex(dir)
	if err != nil || len(idx.Entries) != 0 {
		t.Fatalf("index = %+v, %v", idx, err)
	}
	if err := CreateVault(dir, validVaultFile()); !errors.Is(err, ErrVaultExists) {
		t.Fatalf("second CreateVault = %v, want ErrVaultExists", err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(VaultFilePath(dir))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != FileMode {
			t.Fatalf("vault.json mode = %v", fi.Mode().Perm())
		}
	}
}

func TestWriteFileAtomicLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	for _, s := range []string{"one", "two"} {
		if err := WriteFileAtomic(p, []byte(s), FileMode); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != "two" {
		t.Fatalf("content = %q, %v", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
	// A failed write (missing directory) leaves nothing.
	if err := WriteFileAtomic(filepath.Join(dir, "missing", "f"), []byte("x"), FileMode); err == nil {
		t.Fatal("write into missing dir succeeded")
	}
}

func TestSecretFiles(t *testing.T) {
	dir := newTestVault(t)
	if ok, err := SecretExists(dir, "API_KEY"); ok || err != nil {
		t.Fatalf("SecretExists before write = %v, %v", ok, err)
	}
	if err := WriteSecretFile(dir, "API_KEY", []byte("ciphertext")); err != nil {
		t.Fatal(err)
	}
	if ok, err := SecretExists(dir, "API_KEY"); !ok || err != nil {
		t.Fatalf("SecretExists after write = %v, %v", ok, err)
	}
	got, err := ReadSecretFile(dir, "API_KEY")
	if err != nil || string(got) != "ciphertext" {
		t.Fatalf("ReadSecretFile = %q, %v", got, err)
	}
	if _, err := ReadSecretFile(dir, "MISSING"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing secret error = %v", err)
	}
	if err := WriteSecretFile(dir, "../ESCAPE", nil); !errors.Is(err, ErrInvalidKeyName) {
		t.Fatalf("traversal name = %v", err)
	}
	if err := WriteSecretFile(dir, "BIG", make([]byte, MaxSecretFileSize+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize write = %v", err)
	}
	// Junk in secrets/ is not listed as a secret.
	for _, junk := range []string{"lower.age", "API_KEY (1).age", ".DS_Store", "NOTES.txt"} {
		if err := os.WriteFile(filepath.Join(SecretsPath(dir), junk), []byte("x"), FileMode); err != nil {
			t.Fatal(err)
		}
	}
	list, err := ListSecrets(dir)
	if err != nil || len(list) != 1 || list[0].Name != "API_KEY" {
		t.Fatalf("ListSecrets = %+v, %v", list, err)
	}
}

func TestReadRefusesSymlinksAndOversize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := newTestVault(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("not a vault file"), 0o600); err != nil {
		t.Fatal(err)
	}
	link, err := SecretPath(dir, "LINKED")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecretFile(dir, "LINKED"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("symlinked secret = %v, want ErrNotRegular", err)
	}
	if err := os.Remove(VaultFilePath(dir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, VaultFilePath(dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVaultFile(dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("symlinked vault.json = %v, want ErrNotRegular", err)
	}
	if err := os.Remove(VaultFilePath(dir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(VaultFilePath(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVaultFile(dir); err == nil {
		t.Fatal("directory accepted as vault.json")
	}
	big := filepath.Join(dir, IndexFileName)
	if err := os.WriteFile(big, make([]byte, MaxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadIndex(dir); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize index = %v", err)
	}
}

// Tamper: every truncation of vault.json and index.json is rejected
// cleanly, never half-read.
func TestTruncatedFilesRejected(t *testing.T) {
	vfData, err := MarshalVaultFile(validVaultFile())
	if err != nil {
		t.Fatal(err)
	}
	idxData, err := MarshalIndex(validIndex())
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(vfData); n++ {
		// Dropping only the trailing newline still leaves complete JSON.
		if n == len(vfData)-1 {
			continue
		}
		if vf, err := ParseVaultFile(vfData[:n]); err == nil {
			t.Fatalf("vault.json truncated to %d bytes accepted: %+v", n, vf)
		}
	}
	for n := 0; n < len(idxData)-1; n++ {
		if _, err := ParseIndex(idxData[:n]); err == nil {
			t.Fatalf("index.json truncated to %d bytes accepted", n)
		}
	}
}

func TestIndexHelpersAndRebuild(t *testing.T) {
	dir := newTestVault(t)
	idx := NewIndex()
	idx.Upsert(IndexEntry{Name: "B", Updated: testTime})
	idx.Upsert(IndexEntry{Name: "A", Updated: testTime, Description: "first"})
	idx.Upsert(IndexEntry{Name: "B", Updated: testTime, Description: "second"})
	if len(idx.Entries) != 2 || idx.Entries[0].Name != "A" {
		t.Fatalf("Upsert result: %+v", idx.Entries)
	}
	if e, ok := idx.Get("B"); !ok || e.Description != "second" {
		t.Fatalf("Get(B) = %+v, %v", e, ok)
	}
	idx.Upsert(IndexEntry{Name: "GONE", Updated: testTime})

	for _, n := range []string{"A", "B", "NEW"} {
		if err := WriteSecretFile(dir, n, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	rebuilt, changed, err := RebuildIndex(dir, idx)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("rebuild reported no change")
	}
	var names []string
	for _, e := range rebuilt.Entries {
		names = append(names, e.Name)
	}
	if !slices.Equal(names, []string{"A", "B", "NEW"}) {
		t.Fatalf("rebuilt names = %v", names)
	}
	if e, _ := rebuilt.Get("A"); e.Description != "first" {
		t.Fatal("rebuild lost metadata")
	}
	if e, _ := rebuilt.Get("NEW"); e.Updated.IsZero() {
		t.Fatal("new entry has no time")
	}
	if err := WriteIndex(dir, rebuilt); err != nil {
		t.Fatal(err)
	}
	if _, changed, _ := RebuildIndex(dir, rebuilt); changed {
		t.Fatal("rebuilding a matching index reported a change")
	}
	if !rebuilt.Remove("NEW") || rebuilt.Remove("NEW") {
		t.Fatal("Remove result wrong")
	}
	if fresh, changed, err := RebuildIndex(dir, nil); err != nil || !changed || len(fresh.Entries) != 3 {
		t.Fatalf("rebuild from nil = %+v, %v, %v", fresh, changed, err)
	}
}

func TestTrash(t *testing.T) {
	dir := newTestVault(t)
	if err := WriteSecretFile(dir, "OLD", []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecretFile(dir, "RECENT", []byte("recent")); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 17, 12, 0, 0, 123456789, time.UTC)
	old, err := TrashSecret(dir, "OLD", now.Add(-31*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if old.Name != "OLD" || !strings.HasPrefix(old.File, "OLD.") {
		t.Fatalf("trashed = %+v", old)
	}
	recent, err := TrashSecret(dir, "RECENT", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := SecretExists(dir, "OLD"); ok {
		t.Fatal("trashed key still live")
	}
	if _, err := TrashSecret(dir, "OLD", now); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("trashing a missing key = %v", err)
	}
	list, err := ListTrash(dir)
	if err != nil || len(list) != 2 || list[0] != old || list[1] != recent {
		t.Fatalf("ListTrash = %+v, %v", list, err)
	}
	data, err := ReadTrashedFile(dir, recent)
	if err != nil || string(data) != "recent" {
		t.Fatalf("ReadTrashedFile = %q, %v", data, err)
	}
	purged, err := PurgeTrash(dir, now)
	if err != nil || len(purged) != 1 || purged[0].Name != "OLD" {
		t.Fatalf("PurgeTrash = %+v, %v", purged, err)
	}
	if err := WriteSecretFile(dir, "RECENT", []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	if err := RestoreSecret(dir, recent); !errors.Is(err, ErrTrashedExists) {
		t.Fatalf("restore over live key = %v", err)
	}
	if _, err := TrashSecret(dir, "RECENT", now); err != nil {
		t.Fatal(err)
	}
	if err := RestoreSecret(dir, recent); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReadSecretFile(dir, "RECENT"); string(got) != "recent" {
		t.Fatalf("restored content = %q", got)
	}
	if err := RestoreSecret(dir, TrashedSecret{File: "../../vault.json"}); err == nil {
		t.Fatal("restore of a crafted trash name succeeded")
	}
}

func TestParseTrashName(t *testing.T) {
	name, err := TrashFileName("API_KEY", time.Date(2026, 11, 17, 15, 30, 45, 5, time.FixedZone("x", 3600)))
	if err != nil {
		t.Fatal(err)
	}
	if name != "API_KEY.20261117T143045.000000005Z.age" {
		t.Fatalf("TrashFileName = %q", name)
	}
	got, err := ParseTrashName(name)
	if err != nil || got.Name != "API_KEY" || got.Deleted.Nanosecond() != 5 {
		t.Fatalf("ParseTrashName = %+v, %v", got, err)
	}
	for _, bad := range []string{"", "API_KEY.age", "api.20261117T143045.000000005Z.age", "API_KEY.20261317T143045.000000005Z.age", "API_KEY.20261117T143045.000000005Z.txt", "../X.20261117T143045.000000005Z.age"} {
		if _, err := ParseTrashName(bad); err == nil {
			t.Errorf("ParseTrashName(%q) accepted", bad)
		}
	}
}

func FuzzParseTrashName(f *testing.F) {
	f.Add("API_KEY.20261117T143045.000000005Z.age")
	f.Add("A.x.age")
	f.Fuzz(func(t *testing.T, s string) {
		ts, err := ParseTrashName(s)
		if err != nil {
			return
		}
		again, err := TrashFileName(ts.Name, ts.Deleted)
		if err != nil || again != s || filepath.Base(s) != s {
			t.Fatalf("accepted trash name does not round trip: %q -> %q", s, again)
		}
	})
}
