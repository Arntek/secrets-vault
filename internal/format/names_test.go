package format

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateKeyName(t *testing.T) {
	valid := []string{"A", "_", "API_KEY", "KEY_2", "_PRIVATE", strings.Repeat("A", MaxKeyNameLen)}
	for _, n := range valid {
		if err := ValidateKeyName(n); err != nil {
			t.Errorf("ValidateKeyName(%q) = %v, want nil", n, err)
		}
	}
	invalid := []string{
		"", "api_key", "Key", "2KEY", "KEY-1", "KEY.1", "KEY 1",
		"../KEY", "KEY/X", `KEY\X`, "..", ".", "KEY\x00", "KÉY",
		strings.Repeat("A", MaxKeyNameLen+1),
	}
	for _, n := range invalid {
		err := ValidateKeyName(n)
		if !errors.Is(err, ErrInvalidKeyName) {
			t.Errorf("ValidateKeyName(%q) = %v, want ErrInvalidKeyName", n, err)
		}
	}
}

func TestValidateKeyNameDoesNotEchoInput(t *testing.T) {
	const pasted = "sk-live-NOT-A-NAME"
	err := ValidateKeyName(pasted)
	if err == nil || strings.Contains(err.Error(), pasted) {
		t.Fatalf("error must not echo the rejected input: %v", err)
	}
}

func TestSecretPath(t *testing.T) {
	dir := t.TempDir()
	p, err := SecretPath(dir, "API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, SecretsDir, "API_KEY.age"); p != want {
		t.Fatalf("SecretPath = %q, want %q", p, want)
	}
	if _, err := SecretPath(dir, "../ESCAPE"); err == nil {
		t.Fatal("SecretPath accepted a traversal name")
	}
}

func FuzzValidateKeyName(f *testing.F) {
	for _, s := range []string{"API_KEY", "../x", "", "A\x00", "Ä", "9"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if ValidateKeyName(name) != nil {
			return
		}
		// Anything accepted must map to a direct child of secrets/.
		dir := filepath.Join("v")
		p, err := SecretPath(dir, name)
		if err != nil {
			t.Fatalf("SecretPath rejected a valid name: %v", err)
		}
		if filepath.Dir(p) != filepath.Join(dir, SecretsDir) {
			t.Fatalf("valid name escaped secrets dir: %q", p)
		}
		if filepath.Base(p) != name+SecretExt {
			t.Fatalf("name altered by path join: %q", p)
		}
	})
}
