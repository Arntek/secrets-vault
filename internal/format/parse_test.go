package format

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

var testTime = time.Date(2026, 11, 17, 15, 30, 0, 0, time.UTC)

func validVaultFile() *VaultFile {
	return &VaultFile{
		Version: CurrentVersion,
		ID:      "0123456789abcdef0123456789abcdef",
		Name:    "personal",
		KeyID:   "fedcba9876543210fedcba9876543210",
		Unlockers: []Unlocker{
			{Type: UnlockerPassphrase, WrappedKey: []byte("aaaaaaaaa"), Created: testTime},
			{Type: UnlockerTouchID, Label: "Test Mac", Recipient: "se-pub-1", WrappedKey: []byte("wrapped-2"), Created: testTime},
			{Type: UnlockerMember, Label: "dan", Recipient: "age1example", WrappedKey: []byte("wrapped-3"), Created: testTime},
		},
	}
}

func validIndex() *Index {
	return &Index{Version: CurrentVersion, Entries: []IndexEntry{
		{Name: "B_KEY", Description: "Second key · ünïcode ok", Tags: []string{"xero", "reporting"}, Updated: testTime, UpdatedBy: "arnold"},
		{Name: "A_KEY", Updated: testTime},
	}}
}

func TestVaultFileRoundTrip(t *testing.T) {
	data, err := MarshalVaultFile(validVaultFile())
	if err != nil {
		t.Fatal(err)
	}
	vf, err := ParseVaultFile(data)
	if err != nil {
		t.Fatal(err)
	}
	again, err := MarshalVaultFile(vf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, again) {
		t.Fatalf("round trip changed the file:\n%s\n%s", data, again)
	}
}

func TestIndexRoundTripSorts(t *testing.T) {
	data, err := MarshalIndex(validIndex())
	if err != nil {
		t.Fatal(err)
	}
	idx, err := ParseIndex(data)
	if err != nil {
		t.Fatal(err)
	}
	if idx.Entries[0].Name != "A_KEY" || idx.Entries[1].Name != "B_KEY" {
		t.Fatalf("entries not sorted: %+v", idx.Entries)
	}
	empty, err := MarshalIndex(NewIndex())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(empty, []byte(`"entries": []`)) {
		t.Fatalf("empty index should write an empty list: %s", empty)
	}
}

func mutateJSON(t *testing.T, data []byte, old, new string) []byte {
	t.Helper()
	if !bytes.Contains(data, []byte(old)) {
		t.Fatalf("test setup: %q not in %s", old, data)
	}
	return bytes.Replace(data, []byte(old), []byte(new), 1)
}

func TestParseVaultFileRejects(t *testing.T) {
	good, err := MarshalVaultFile(validVaultFile())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":             {},
		"null":              []byte("null"),
		"array":             []byte("[]"),
		"truncated":         good[:len(good)/2],
		"trailing data":     append(append([]byte{}, good...), []byte(`{}`)...),
		"unknown field":     mutateJSON(t, good, `"version": 1,`, `"version": 1, "extra": true,`),
		"upper-case key":    mutateJSON(t, good, `"name":`, `"NAME":`),
		"duplicate key":     mutateJSON(t, good, `"name": "personal",`, `"name": "personal", "name": "other",`),
		"version zero":      mutateJSON(t, good, `"version": 1`, `"version": 0`),
		"version string":    mutateJSON(t, good, `"version": 1`, `"version": "1"`),
		"version float":     mutateJSON(t, good, `"version": 1`, `"version": 1.5`),
		"bad id":            mutateJSON(t, good, `0123456789abcdef0123456789abcdef`, `../../etc`),
		"upper id":          mutateJSON(t, good, `0123456789abcdef0123456789abcdef`, `0123456789ABCDEF0123456789ABCDEF`),
		"bad key id":        mutateJSON(t, good, `fedcba9876543210fedcba9876543210`, `x`),
		"bad name":          mutateJSON(t, good, `"personal"`, `"Personal Vault"`),
		"no unlockers":      []byte(`{"version":1,"id":"0123456789abcdef0123456789abcdef","name":"v","key_id":"fedcba9876543210fedcba9876543210","unlockers":[]}`),
		"unknown unlocker":  mutateJSON(t, good, `"type": "touchid"`, `"type": "yubikey"`),
		"bad base64":        mutateJSON(t, good, `"wrapped_key": "YWFhYWFhYWFh"`, `"wrapped_key": "!!!"`),
		"empty wrapped key": mutateJSON(t, good, `"wrapped_key": "YWFhYWFhYWFh"`, `"wrapped_key": ""`),
		"bad time":          mutateJSON(t, good, `"created": "2026-11-17T15:30:00Z"`, `"created": "yesterday"`),
		"control in label":  mutateJSON(t, good, `"Test Mac"`, `"Test\u001b[2JMac"`),
		"bidi in label":     mutateJSON(t, good, `"Test Mac"`, `"Test\u202eMac"`),
		"member no label":   mutateJSON(t, good, `"label": "dan",`, ``),
		"deep nesting":      []byte(strings.Repeat("[", 100) + strings.Repeat("]", 100)),
		"invalid utf8":      append([]byte(`{"version":1,"name":"`), 0xff, '"', '}'),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			vf, err := ParseVaultFile(data)
			if err == nil || vf != nil {
				t.Fatalf("accepted: %v", vf)
			}
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("error does not wrap ErrMalformed: %v", err)
			}
		})
	}
}

func TestParseVaultFileNewerVersion(t *testing.T) {
	data := []byte(`{"version": 2, "id": "x", "new_field": {"a": 1}}`)
	if _, err := ParseVaultFile(data); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
}

func TestParseVaultFileTooLarge(t *testing.T) {
	data := []byte(`{"version":1,"name":"` + strings.Repeat("a", MaxFileSize) + `"}`)
	if _, err := ParseVaultFile(data); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestVaultFileValidateRules(t *testing.T) {
	vf := validVaultFile()
	vf.Unlockers = append(vf.Unlockers, vf.Unlockers[0])
	if vf.Validate() == nil {
		t.Error("two passphrase unlockers accepted")
	}
	vf = validVaultFile()
	vf.Unlockers = append(vf.Unlockers, vf.Unlockers[2])
	if vf.Validate() == nil {
		t.Error("duplicate member recipient accepted")
	}
	vf = validVaultFile()
	vf.Unlockers[1].Created = time.Time{}
	if vf.Validate() == nil {
		t.Error("zero created time accepted")
	}
	vf = validVaultFile()
	vf.Unlockers[2].Recipient = "age1 with space"
	if vf.Validate() == nil {
		t.Error("recipient with space accepted")
	}
	if _, err := MarshalVaultFile(&VaultFile{}); err == nil {
		t.Error("Marshal wrote an invalid vault file")
	}
}

// Parse errors describe the problem but never quote the input, in case a
// secret was pasted into a vault file by mistake.
func TestParseErrorsDoNotEchoInput(t *testing.T) {
	const marker = "SVCANARY_PASTED_VALUE"
	good, err := MarshalVaultFile(validVaultFile())
	if err != nil {
		t.Fatal(err)
	}
	inputs := [][]byte{
		mutateJSON(t, good, `"version": 1,`, `"version": 1, "`+strings.ToLower(marker)+`": 1,`),
		mutateJSON(t, good, `"version": 1,`, `"version": 1, "`+marker+`": 1,`),
		mutateJSON(t, good, `"personal"`, `"`+marker+`"`),
		mutateJSON(t, good, `"created": "2026-11-17T15:30:00Z"`, `"created": "`+marker+`"`),
		mutateJSON(t, good, `"wrapped_key": "YWFhYWFhYWFh"`, `"wrapped_key": "`+marker+`!"`),
		mutateJSON(t, good, `"version": 1`, `"version": `+marker),
		[]byte(`{"version":1,"entries":[{"name":"` + marker + `x"}]}`),
	}
	for i, in := range inputs {
		_, err1 := ParseVaultFile(in)
		_, err2 := ParseIndex(in)
		for _, err := range []error{err1, err2} {
			if err == nil {
				t.Fatalf("input %d accepted", i)
			}
			if strings.Contains(strings.ToUpper(err.Error()), marker) {
				t.Errorf("input %d: error echoes input: %v", i, err)
			}
		}
	}
}

func TestParseIndexRejects(t *testing.T) {
	good, err := MarshalIndex(validIndex())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"truncated":         good[:len(good)-3],
		"bad key name":      mutateJSON(t, good, `"A_KEY"`, `"../etc/passwd"`),
		"lower key name":    mutateJSON(t, good, `"A_KEY"`, `"a_key"`),
		"duplicate entry":   mutateJSON(t, good, `"A_KEY"`, `"B_KEY"`),
		"ansi description":  mutateJSON(t, good, `"Second key`, `"\u001b]0;pwned\u0007Second key`),
		"bad tag":           mutateJSON(t, good, `"xero"`, `"Xero Tag"`),
		"duplicate tag":     mutateJSON(t, good, `"reporting"`, `"xero"`),
		"no updated":        mutateJSON(t, good, `"updated": "2026-11-17T15:30:00Z"`, `"updated": "0001-01-01T00:00:00Z"`),
		"unknown field":     mutateJSON(t, good, `"name": "A_KEY",`, `"name": "A_KEY", "value": "x",`),
		"entries not array": []byte(`{"version":1,"entries":{}}`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if idx, err := ParseIndex(data); err == nil {
				t.Fatalf("accepted: %+v", idx)
			}
		})
	}
}

func TestValidateVaultNameAndTag(t *testing.T) {
	for _, ok := range []string{"personal", "work", "client-1", "a_b", "9"} {
		if err := ValidateVaultName(ok); err != nil {
			t.Errorf("ValidateVaultName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-x", "_x", "Personal", "a b", "a/b", "..", strings.Repeat("a", 65)} {
		if ValidateVaultName(bad) == nil {
			t.Errorf("ValidateVaultName(%q) accepted", bad)
		}
	}
	if ValidateTag("Xero") == nil || ValidateTag("") == nil || ValidateTag("xero-api_2") != nil {
		t.Error("ValidateTag rules wrong")
	}
}

func TestVaultFileUnlockerHelpers(t *testing.T) {
	vf := validVaultFile()
	if got := len(vf.UnlockersOf(UnlockerMember)); got != 1 {
		t.Fatalf("UnlockersOf member = %d", got)
	}
	repl := Unlocker{Type: UnlockerPassphrase, WrappedKey: []byte("new"), Created: testTime}
	if !vf.SetUnlocker(repl) || string(vf.UnlockersOf(UnlockerPassphrase)[0].WrappedKey) != "new" {
		t.Fatal("SetUnlocker did not replace the passphrase")
	}
	if vf.SetUnlocker(Unlocker{Type: UnlockerMember, Label: "eve", Recipient: "age1other", WrappedKey: []byte("w"), Created: testTime}) {
		t.Fatal("SetUnlocker replaced a different member")
	}
	if n := vf.RemoveUnlockers(func(u Unlocker) bool { return u.Type == UnlockerMember }); n != 2 {
		t.Fatalf("RemoveUnlockers removed %d", n)
	}
	if err := vf.Validate(); err != nil {
		t.Fatal(err)
	}
}

func FuzzParseVaultFile(f *testing.F) {
	good, err := MarshalVaultFile(validVaultFile())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"version":2}`))
	f.Add([]byte(`{"version":1,"version":1}`))
	f.Add([]byte(`[[[[{}]]]]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		vf, err := ParseVaultFile(data)
		if err != nil {
			if vf != nil {
				t.Fatal("non-nil result with error")
			}
			return
		}
		// Anything accepted is valid and survives a round trip unchanged.
		out, err := MarshalVaultFile(vf)
		if err != nil {
			t.Fatalf("accepted file fails to marshal: %v", err)
		}
		vf2, err := ParseVaultFile(out)
		if err != nil {
			t.Fatalf("re-marshalled file rejected: %v", err)
		}
		out2, err := MarshalVaultFile(vf2)
		if err != nil || !bytes.Equal(out, out2) {
			t.Fatal("round trip not stable")
		}
	})
}

func FuzzParseIndex(f *testing.F) {
	good, err := MarshalIndex(validIndex())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"version":1,"entries":null}`))
	f.Add([]byte(`{"version":1,"private":true,"entries":[{"name":"A","updated":"2026-01-01T00:00:00Z"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		idx, err := ParseIndex(data)
		if err != nil {
			return
		}
		for _, e := range idx.Entries {
			if ValidateKeyName(e.Name) != nil {
				t.Fatal("accepted invalid key name")
			}
		}
		out, err := MarshalIndex(idx)
		if err != nil {
			t.Fatalf("accepted index fails to marshal: %v", err)
		}
		if _, err := ParseIndex(out); err != nil {
			t.Fatalf("re-marshalled index rejected: %v", err)
		}
	})
}
