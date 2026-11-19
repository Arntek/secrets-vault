package cli

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Arntek/secrets-vault/internal/audit"
)

// parseSince reads a duration such as 90m, 24h or 7d.
func parseSince(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 0 || days > 36500 {
			return 0, fmt.Errorf("bad duration")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("bad duration")
	}
	return d, nil
}

// cmdLog: log [--vault V] [--since 24h] [--name K] [--json]
func cmdLog(a *app, p *parsed) error {
	if err := p.wantArgs(0, 0, a.prog+" log [--vault V] [--since 24h] [--name K] [--json]"); err != nil {
		return err
	}
	fl := audit.Filter{Vault: p.str("vault"), Key: p.str("name")}
	if s := p.str("since"); s != "" {
		d, err := parseSince(s)
		if err != nil {
			return usageErrf("--since is a duration such as 90m, 24h or 7d")
		}
		fl.Since = a.now().Add(-d)
	}
	dir, err := a.configDir()
	if err != nil {
		return err
	}
	evs, err := audit.NewFile(filepath.Join(dir, "audit.log")).Read(fl)
	if err != nil {
		return failf("%v", err)
	}
	if a.asJSON {
		if evs == nil {
			evs = []audit.Event{}
		}
		return a.printJSON(evs)
	}
	if len(evs) == 0 {
		a.printf("Nothing logged for that.\n")
		return nil
	}
	t := newTable(a.out, "WHEN", "VAULT", "KEY", "ACTION", "COMMAND", "PROGRAM")
	for _, e := range evs {
		who := e.Program
		if e.PID > 0 {
			who += " (" + strconv.Itoa(e.PID) + ")"
		}
		act := string(e.Action)
		if e.Member != "" {
			act += " " + e.Member
		}
		if e.Via != "" {
			act += " via " + e.Via
		}
		t.row(e.Time.Local().Format("2006-01-02 15:04:05"), e.Vault, e.Key, act, e.Command, who)
	}
	t.flush()
	return nil
}
