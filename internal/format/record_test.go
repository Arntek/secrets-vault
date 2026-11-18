package format

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func validRecord() *Record {
	return &Record{
		Seq: 1, Prev: strings.Repeat("a", 64), VaultID: "0123456789abcdef0123456789abcdef",
		Time: testTime, Op: OpAddMember,
		Member:      &Member{Name: "dan", Recipient: testRecipB, SignKey: testSignB, Role: RoleMember},
		KeyID:       "fedcba9876543210fedcba9876543210",
		MembersHash: strings.Repeat("b", 64), UnlockersHash: strings.Repeat("c", 64),
	}
}

func TestRecordRoundTrip(t *testing.T) {
	body, err := MarshalRecordBody(validRecord())
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRecordBody(body)
	if err != nil {
		t.Fatal(err)
	}
	again, err := MarshalRecordBody(r)
	if err != nil || !bytes.Equal(body, again) {
		t.Fatalf("round trip changed the body: %v\n%s\n%s", err, body, again)
	}
}

func TestRecordRules(t *testing.T) {
	cases := map[string]func(r *Record){
		"negative seq":         func(r *Record) { r.Seq = -1 },
		"seq at cap":           func(r *Record) { r.Seq = MaxLogEntries },
		"no prev":              func(r *Record) { r.Prev = "" },
		"genesis not at 0":     func(r *Record) { r.Op = OpGenesis; r.Member.Role = RoleOwner },
		"prev on seq 0":        func(r *Record) { r.Seq = 0; r.Op = OpGenesis; r.Member.Role = RoleOwner },
		"bad prev":             func(r *Record) { r.Prev = "xyz" },
		"bad vault id":         func(r *Record) { r.VaultID = "nope" },
		"no time":              func(r *Record) { r.Time = time.Time{} },
		"unknown op":           func(r *Record) { r.Op = "grant-admin" },
		"add without member":   func(r *Record) { r.Member = nil },
		"rotate with member":   func(r *Record) { r.Op = OpRotate; r.Passphrase = PassDropped },
		"rotate without pass":  func(r *Record) { r.Op = OpRotate; r.Member = nil },
		"add with passphrase":  func(r *Record) { r.Passphrase = PassKept },
		"remove bad pass":      func(r *Record) { r.Op = OpRemoveMember; r.Passphrase = "forgotten" },
		"bad key id":           func(r *Record) { r.KeyID = "x" },
		"bad members hash":     func(r *Record) { r.MembersHash = "x" },
		"bad member sign key":  func(r *Record) { r.Member.SignKey = "short" },
		"bad member name":      func(r *Record) { r.Member.Name = "Dan" },
		"genesis member owner": func(r *Record) { r.Seq = 0; r.Prev = ""; r.Op = OpGenesis },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			r := validRecord()
			mut(r)
			if r.Validate() == nil {
				t.Fatal("accepted")
			}
			if _, err := MarshalRecordBody(r); err == nil {
				t.Fatal("marshalled")
			}
		})
	}
	ok := validRecord()
	ok.Op, ok.Member, ok.Passphrase = OpRotate, nil, PassReplaced
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid rotate rejected: %v", err)
	}
	body, _ := MarshalRecordBody(validRecord())
	for name, data := range map[string][]byte{
		"unknown field": bytes.Replace(body, []byte(`"seq":1`), []byte(`"seq":1,"admin":true`), 1),
		"mac smuggled":  bytes.Replace(body, []byte(`"seq":1`), []byte(`"seq":1,"mac":"AA"`), 1),
		"too large":     append(bytes.Repeat([]byte(" "), MaxRecordSize), body...),
		"truncated":     body[:len(body)-2],
	} {
		if _, err := ParseRecordBody(data); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDigestsDistinguish(t *testing.T) {
	ms := validVaultFile().Members
	d := MembersDigest(ms)
	if d != MembersDigest(validVaultFile().Members) {
		t.Fatal("digest not deterministic")
	}
	other := validVaultFile().Members
	other[1].Role = RoleOwner
	if MembersDigest(other) == d {
		t.Fatal("role change not detected")
	}
	// Length prefixes: moving a byte between fields changes the digest.
	a := []Member{{Name: "ab", Recipient: "c"}}
	b := []Member{{Name: "a", Recipient: "bc"}}
	if MembersDigest(a) == MembersDigest(b) {
		t.Fatal("field boundary not encoded")
	}
	us := validVaultFile().Unlockers
	u := UnlockersDigest(us)
	us[1].WrappedKey = []byte("planted")
	if UnlockersDigest(us) == u {
		t.Fatal("wrapped key change not detected")
	}
	us = validVaultFile().Unlockers
	us[0].Created = us[0].Created.Add(1)
	if UnlockersDigest(us) == u {
		t.Fatal("created change not detected")
	}
	if RecordHash([]byte("x")) == RecordHash([]byte("y")) || len(RecordHash(nil)) != 64 {
		t.Fatal("RecordHash wrong")
	}
}

func TestWriteVaultFileCAS(t *testing.T) {
	dir := newTestVault(t)
	_, raw, err := ReadVaultFileBytes(dir)
	if err != nil {
		t.Fatal(err)
	}
	vf := validVaultFile()
	vf.Name = "renamed"
	stale := append([]byte{}, raw...)
	stale[0] = ' '
	if err := WriteVaultFileCAS(dir, vf, stale); !errors.Is(err, ErrChanged) {
		t.Fatalf("CAS with stale bytes = %v", err)
	}
	if err := WriteVaultFileCAS(dir, vf, nil); !errors.Is(err, ErrChanged) {
		t.Fatalf("CAS expecting no file = %v", err)
	}
	if got, _ := ReadVaultFile(dir); got.Name != "personal" {
		t.Fatal("vault.json changed despite CAS failure")
	}
	if err := WriteVaultFileCAS(dir, vf, raw); err != nil {
		t.Fatal(err)
	}
	if got, _ := ReadVaultFile(dir); got.Name != "renamed" {
		t.Fatal("CAS write lost")
	}
}

// ue1.4: symlinked folders inside a vault are refused before any write.
func TestSymlinkedVaultDirsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	for _, rel := range []string{SecretsDir, filepath.Join(SecretsDir, TrashDir), RequestsDir, filepath.Join(SecretsDir, stagingPrefix+testKeyID)} {
		t.Run(rel, func(t *testing.T) {
			dir := newTestVault(t)
			if err := WriteSecretFile(dir, "A", []byte("a")); err != nil {
				t.Fatal(err)
			}
			elsewhere := t.TempDir()
			target := filepath.Join(dir, rel)
			_ = os.RemoveAll(target)
			if err := os.MkdirAll(filepath.Dir(target), DirMode); err != nil {
				t.Fatal(err)
			}
			if rel == SecretsDir {
				// Move the real files away so the link points at a copy.
				_ = os.WriteFile(filepath.Join(elsewhere, "A.age"), []byte("a"), FileMode)
			}
			if err := os.Symlink(elsewhere, target); err != nil {
				t.Fatal(err)
			}
			if err := CheckVaultDirs(dir); !errors.Is(err, ErrUnsafeDir) {
				t.Fatalf("CheckVaultDirs = %v", err)
			}
			if err := WriteSecretFile(dir, "B", []byte("b")); !errors.Is(err, ErrUnsafeDir) {
				t.Fatalf("WriteSecretFile = %v", err)
			}
			if _, err := PurgeTrash(dir, testTime); !errors.Is(err, ErrUnsafeDir) {
				t.Fatalf("PurgeTrash = %v", err)
			}
			if _, err := BeginStaging(dir, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, ErrUnsafeDir) {
				t.Fatalf("BeginStaging = %v", err)
			}
			if err := WriteIndex(dir, NewIndex()); !errors.Is(err, ErrUnsafeDir) {
				t.Fatalf("WriteIndex = %v", err)
			}
			if _, _, err := ReadVaultFileBytes(dir); !errors.Is(err, ErrUnsafeDir) {
				t.Fatalf("ReadVaultFileBytes = %v", err)
			}
			if entries, _ := os.ReadDir(elsewhere); len(entries) > 1 {
				t.Fatalf("wrote through the symlink: %v", entries)
			}
		})
	}
}

// ue1.4: a staged entry that is not a regular file is never moved.
func TestCommitStagedRequiresRegularFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := newTestVault(t)
	if err := WriteSecretFile(dir, "A", []byte("old")); err != nil {
		t.Fatal(err)
	}
	s, err := BeginStaging(dir, testKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddSecret("A", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(SecretsPath(dir), stagingPrefix+testKeyID, "A.age")
	_ = os.Remove(staged)
	if err := os.Symlink("/etc/hosts", staged); err != nil {
		t.Fatal(err)
	}
	if err := CommitStaged(dir, testKeyID); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("CommitStaged = %v", err)
	}
	if got, _ := ReadSecretFile(dir, "A"); string(got) != "old" {
		t.Fatal("live file replaced")
	}
}

func FuzzParseRecordBody(f *testing.F) {
	body, err := MarshalRecordBody(validRecord())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(body)
	f.Add([]byte(`{"seq":0}`))
	f.Add([]byte(`{"seq":1,"prev":"` + strings.Repeat("a", 64) + `","vault_id":"0123456789abcdef0123456789abcdef","time":"2026-11-20T10:00:00Z","op":"upgrade-format","format":3,"key_id":"fedcba9876543210fedcba9876543210","members_hash":"` + strings.Repeat("b", 64) + `","unlockers_hash":"` + strings.Repeat("c", 64) + `"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseRecordBody(data)
		if err != nil {
			if r != nil {
				t.Fatal("non-nil result with error")
			}
			return
		}
		out, err := MarshalRecordBody(r)
		if err != nil {
			t.Fatalf("accepted record fails to marshal: %v", err)
		}
		if _, err := ParseRecordBody(out); err != nil {
			t.Fatalf("re-marshalled record rejected: %v", err)
		}
	})
}

// The vault format is part of the signed history (docs/design/index-auth.md):
// genesis and upgrade-format records carry it, nothing else may.
func TestRecordFormatField(t *testing.T) {
	genesis := func(f int) *Record {
		r := validRecord()
		r.Seq, r.Prev, r.Op, r.Format = 0, "", OpGenesis, f
		r.Member.Role = RoleOwner
		return r
	}
	upgrade := func(f int) *Record {
		r := validRecord()
		r.Op, r.Member, r.Format = OpUpgradeFormat, nil, f
		return r
	}
	ok := map[string]*Record{"genesis 3": genesis(3), "genesis legacy": genesis(0), "upgrade 3": upgrade(3)}
	for name, r := range ok {
		body, err := MarshalRecordBody(r)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if back, err := ParseRecordBody(body); err != nil || back.Format != r.Format {
			t.Errorf("%s: round trip %v", name, err)
		}
	}
	rotate := validRecord()
	rotate.Op, rotate.Member, rotate.Passphrase, rotate.Format = OpRotate, nil, PassDropped, 3
	bad := map[string]*Record{
		"genesis 2":        genesis(2),
		"genesis 4":        genesis(4),
		"upgrade 0":        upgrade(0),
		"upgrade 2":        upgrade(2),
		"upgrade 4":        upgrade(4),
		"format on rotate": rotate,
	}
	addFmt := validRecord()
	addFmt.Format = 3
	bad["format on add-member"] = addFmt
	withMember := upgrade(3)
	withMember.Member = &Member{Name: "dan", Recipient: testRecipB, SignKey: testSignB, Role: RoleMember}
	bad["upgrade naming a member"] = withMember
	for name, r := range bad {
		if _, err := MarshalRecordBody(r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A record from a build before this field has no "format" and is read
	// as before; the upgrade op is unknown to such builds by design.
	body, _ := MarshalRecordBody(validRecord())
	if bytes.Contains(body, []byte(`"format"`)) {
		t.Fatal("format written when unset")
	}
}

func TestQuarantineSecretMovesNeverDeletes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteSecretFile(dir, "STALE", []byte("old bytes")); err != nil {
		t.Fatal(err)
	}
	rel, err := QuarantineSecret(dir, "STALE", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel))); err != nil || string(got) != "old bytes" {
		t.Fatalf("quarantined file: %q %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets", "STALE.age")); err == nil {
		t.Fatal("still in secrets/")
	}
	if _, err := QuarantineSecret(dir, "STALE", testTime); err == nil {
		t.Fatal("quarantined a file that is gone")
	}
	if _, err := QuarantineSecret(dir, "../x", testTime); err == nil {
		t.Fatal("accepted a bad name")
	}
}
