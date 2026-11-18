package arch

import (
	"go/build"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const module = "github.com/Arntek/secrets-vault/"

// allowed lists, for each internal package, the internal packages its
// non-test code may import. Keep in sync with docs/architecture.md.
var allowed = map[string][]string{
	"internal/format":     {},
	"internal/audit":      {},
	"internal/leaktest":   {},
	"internal/arch":       {},
	"internal/agentsetup": {},
	"internal/crypto":     {"internal/format"},
	"internal/index":      {"internal/crypto", "internal/format"},
	"internal/agent":      {"internal/crypto", "internal/format"},
	"internal/touchid":    {"internal/crypto", "internal/format"},
	"internal/members":    {"internal/crypto", "internal/format", "internal/audit"},
	"internal/cli": {
		"internal/format", "internal/crypto", "internal/agent",
		"internal/touchid", "internal/members", "internal/audit", "internal/index", "internal/agentsetup",
	},
	"cmd/secrets-vault": {"internal/cli"},
}

func TestDependencyDirection(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil || !d.IsDir() || d.Name() == "testdata" {
				return err
			}
			pkg, err := build.ImportDir(path, 0)
			if err != nil {
				if _, ok := err.(*build.NoGoError); ok {
					return nil
				}
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			seen[rel] = true
			ok, known := allowed[rel]
			if !known {
				t.Errorf("%s is not listed in arch_test.go and docs/architecture.md; add its allowed imports", rel)
				return nil
			}
			for _, imp := range pkg.Imports {
				if !strings.HasPrefix(imp, module) {
					continue
				}
				dep := strings.TrimPrefix(imp, module)
				if !contains(ok, dep) {
					t.Errorf("%s must not import %s (allowed: %v)", rel, dep, ok)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var missing []string
	for p := range allowed {
		if !seen[p] {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("packages listed but not found: %v", missing)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
