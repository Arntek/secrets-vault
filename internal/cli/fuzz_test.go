package cli

import (
	"strings"
	"testing"
)

// The registry file is read on every run; a damaged or tampered one must be
// rejected cleanly and never echoed.
func FuzzParseConfig(f *testing.F) {
	f.Add([]byte(`default_ttl = "4h"` + "\n" + `[vaults.main]` + "\n" + `path = "/x"` + "\n"))
	f.Add([]byte(`[vaults.""]` + "\npath = 1\n"))
	f.Add([]byte("\x00\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := parseConfig(data)
		if err != nil {
			if s := string(data); len(s) > 8 && strings.Contains(err.Error(), s) {
				t.Fatal("error quotes the input")
			}
			return
		}
		if c.Vaults == nil {
			t.Fatal("nil vault map")
		}
	})
}

// parseArgs sees whatever the user (or an agent) typed, secrets pasted by
// mistake included: it must never panic and never echo an argument.
func FuzzParseArgs(f *testing.F) {
	f.Add("-k", "NAME", "--", "cmd")
	f.Add("--vault=x", "--json", "-y", "")
	f.Add("--", "--", "-", "-kk")
	specs := []flagSpec{fJSON, fVault, fYes, {name: "key", short: "k", value: true}}
	f.Fuzz(func(t *testing.T, a, b, c, d string) {
		p, err := parseArgs([]string{a, b, c, d}, specs)
		if err != nil {
			for _, x := range []string{a, b, c, d} {
				if len(x) > 5 && strings.Contains(err.Error(), x) {
					t.Fatal("error echoes an argument")
				}
			}
			return
		}
		if len(p.args)+len(p.rest) > 4 {
			t.Fatal("more arguments than were given")
		}
	})
}
