package cli

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Arntek/secrets-vault/internal/agentsetup"
	"github.com/Arntek/secrets-vault/internal/format"
)

// cmdPrime prints the agent rules and the registered vaults. It reads no
// secret, asks for no unlock and never starts the agent, so it works with
// every vault locked.
func cmdPrime(a *app, p *parsed) error {
	if err := p.wantArgs(0, 0, a.prog+" prime [--json]"); err != nil {
		return err
	}
	type vrow struct {
		Name        string `json:"name"`
		Description string `json:"description,omitempty"`
		State       string `json:"state"` // locked, unlocked, unavailable
		SecondsLeft int    `json:"seconds_left,omitempty"`
		TimeLeft    string `json:"time_left,omitempty"`
	}
	vaults := []vrow{}
	var note string
	if names, err := a.vaultNames(); err != nil {
		note = "The list of vaults could not be read."
	} else {
		states := a.lockStates()
		for _, n := range names {
			v, err := a.vault(n)
			if err != nil {
				vaults = append(vaults, vrow{Name: n, State: "unavailable"})
				continue
			}
			r := vrow{Name: n, Description: cleanText(v.entry.Description), State: "locked"}
			if vf, err := format.ReadVaultFile(v.dir); err != nil {
				r.State = "unavailable"
			} else if st := states[vf.ID]; st.Unlocked {
				left := time.Until(st.Expires)
				r.State, r.SecondsLeft, r.TimeLeft = "unlocked", int(left.Seconds()), timeLeft(left)
			}
			vaults = append(vaults, r)
		}
	}
	rules := agentsetup.Rules(a.prog)
	if a.asJSON {
		return a.printJSON(map[string]any{
			"command":    a.prog,
			"intro":      agentsetup.Intro,
			"rules":      rules,
			"exit_codes": agentsetup.ExitCodes,
			"vaults":     vaults,
			"note":       "These are rules an agent follows, not enforcement.",
		})
	}
	a.printf("%s\n\nRules:\n", agentsetup.Intro)
	for i, r := range rules {
		a.printf("%d. %s\n", i+1, r)
	}
	a.printf("\nVaults on this machine:\n")
	if note != "" {
		a.printf("  %s\n", note)
	}
	if len(vaults) == 0 && note == "" {
		a.printf("  none registered. The human can create one with: %s init NAME --path DIR\n", a.prog)
	}
	for _, v := range vaults {
		line := "  " + v.Name + ": " + v.State
		if v.TimeLeft != "" {
			line += ", " + v.TimeLeft + " left"
		}
		if v.Description != "" {
			line += " (" + v.Description + ")"
		}
		a.printf("%s\n", line)
	}
	a.printf("\nThese are rules you follow. The tool does not enforce them.\n")
	return nil
}

// claudeDir is Claude Code's config folder: CLAUDE_CONFIG_DIR if set, else
// ~/.claude.
func (a *app) claudeDir() (string, error) {
	if d := a.getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return a.expandPath(d)
	}
	h := a.home()
	if h == "" {
		return "", failf("cannot find your home folder")
	}
	return filepath.Join(h, ".claude"), nil
}

func cmdSetup(a *app, p *parsed) error {
	usage := a.prog + " setup claude [--claude-md] [--remove] [--dry-run] [--force] | " + a.prog + " setup agents [--path DIR] [--remove] [--dry-run] [--force]"
	if len(p.args) != 1 || (p.args[0] != "claude" && p.args[0] != "agents") {
		return usageErrf("usage: %s", usage)
	}
	target := p.args[0]
	if target == "claude" && p.has("path") || target == "agents" && p.has("claude-md") {
		return usageErrf("usage: %s", usage)
	}
	o := agentsetup.Opts{DryRun: p.has("dry-run"), Force: p.has("force")}
	remove := p.has("remove")

	var results []agentsetup.Result
	do := func(r agentsetup.Result, err error) error {
		if err == nil {
			results = append(results, r)
		}
		return err
	}
	var err error
	switch target {
	case "claude":
		var dir string
		if dir, err = a.claudeDir(); err != nil {
			return err
		}
		skill := filepath.Join(dir, "skills", "vault", "SKILL.md")
		if remove {
			err = do(agentsetup.RemoveFile(skill, o))
		} else {
			err = do(agentsetup.SetFile(skill, agentsetup.SkillContent(a.prog), o))
		}
		if err == nil && p.has("claude-md") {
			md := filepath.Join(dir, "CLAUDE.md")
			if remove {
				err = do(agentsetup.RemoveBlock(md, o))
			} else {
				err = do(agentsetup.SetBlock(md, agentsetup.BlockBody(a.prog), o))
			}
		}
	case "agents":
		dir := "."
		if p.has("path") {
			dir = p.str("path")
		}
		if dir, err = a.expandPath(dir); err != nil {
			return err
		}
		if fi, serr := os.Stat(dir); serr != nil || !fi.IsDir() {
			return failf("%s is not a folder", dir)
		}
		md := filepath.Join(dir, "AGENTS.md")
		if remove {
			err = do(agentsetup.RemoveBlock(md, o))
		} else {
			err = do(agentsetup.SetBlock(md, agentsetup.BlockBody(a.prog), o))
		}
	}
	if err != nil {
		return setupErr(err)
	}
	if a.asJSON {
		return a.printJSON(map[string]any{"dry_run": o.DryRun, "results": results})
	}
	for _, r := range results {
		verb := r.Action
		if o.DryRun && r.Action != "unchanged" && r.Action != "absent" {
			verb = "would be " + r.Action
		}
		a.printf("%s: %s\n", r.Path, verb)
		if o.DryRun && r.Diff != "" {
			a.printf("%s", r.Diff)
		}
	}
	if !remove {
		a.printf("These are instructions an agent follows. They are not enforced: run '%s prime' to see them.\n", a.prog)
	}
	return nil
}

// setupErr turns a refusal into a plain message with exit 1.
func setupErr(err error) error {
	return failf("%s", strings.TrimPrefix(err.Error(), "refused: "))
}
