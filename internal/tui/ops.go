package tui

import (
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// Every operation runs through Backend in one goroutine at a time (busy
// blocks the next key) and ends with a fresh Snapshot, so the screen always
// shows what is on disk.

func (m *Model) runOp(busy string, selVault, selName string, fn func(b Backend) (string, error)) tea.Cmd {
	m.busy = busy
	m.setStatus(busy+"…", false)
	b := m.b
	return func() tea.Msg {
		status, err := fn(b)
		snap, serr := b.Snapshot()
		return opDoneMsg{status: status, err: err, snap: snap, serr: serr, selectVault: selVault, selectName: selName}
	}
}

func (m *Model) needKey() (Key, bool) {
	k, ok := m.selectedKey()
	if !ok {
		m.setStatus("Pick a key first.", true)
	}
	return k, ok
}

func (m *Model) doReveal() tea.Cmd {
	if m.rev != nil { // space again hides it
		m.hide()
		return nil
	}
	k, ok := m.needKey()
	if !ok {
		return nil
	}
	m.busy = "Reading"
	m.setStatus("Reading "+clean(k.Name)+"…", false)
	b := m.b
	return func() tea.Msg {
		// The call site for the audit hook is inside Backend.Reveal (the
		// CLI's revealValue records the read).
		val, err := b.Reveal(k.Vault, k.Name)
		if m.closing.Load() { // the UI ended while this was decrypting
			clear(val)
			val, err = nil, ErrCancelled
		}
		snap, serr := b.Snapshot()
		return revealMsg{vault: k.Vault, name: k.Name, val: val, err: err, snap: snap, serr: serr}
	}
}

func (m *Model) doCopy() tea.Cmd {
	k, ok := m.needKey()
	if !ok {
		return nil
	}
	return m.runOp("Copying", "", "", func(b Backend) (string, error) {
		clears, err := b.Copy(k.Vault, k.Name)
		if err != nil {
			return "", err
		}
		if !clears {
			return "Copied " + clean(k.Name) + ". Clear the clipboard yourself.", nil
		}
		return "Copied " + clean(k.Name) + "; the clipboard clears in " + itoa(int(ClipboardClear.Seconds())) + "s.", nil
	})
}

// targetVault is the vault u and l act on: the selected key's, else the
// highlighted vault, else the only one.
func (m *Model) targetVault() (string, bool) {
	if m.focus == paneKeys {
		if r, ok := m.selectedRow(); ok {
			if r.vault != nil {
				return r.vault.Name, true
			}
			return r.key.Vault, true
		}
	}
	if v, ok := m.currentVault(); ok {
		return v.Name, true
	}
	if len(m.snap.Vaults) == 1 {
		return m.snap.Vaults[0].Name, true
	}
	if k, ok := m.selectedKey(); ok {
		return k.Vault, true
	}
	m.setStatus("Pick a vault or a key first.", true)
	return "", false
}

func (m *Model) doUnlock() tea.Cmd {
	v, ok := m.targetVault()
	if !ok {
		return nil
	}
	return m.runOp("Unlocking "+clean(v), "", "", func(b Backend) (string, error) {
		return "Unlocked " + clean(v) + ".", b.Unlock(v)
	})
}

func (m *Model) doLock(all bool) tea.Cmd {
	m.hide()
	if all {
		return m.runOp("Locking", "", "", func(b Backend) (string, error) {
			return "Locked every vault.", b.LockAll()
		})
	}
	v, ok := m.targetVault()
	if !ok {
		return nil
	}
	return m.runOp("Locking", "", "", func(b Backend) (string, error) {
		return "Locked " + clean(v) + ".", b.Lock(v)
	})
}

// --- add ---

// startAdd asks for a name, a value (hidden) and a description, then saves.
// With several vaults and none highlighted it also asks which vault.
func (m *Model) startAdd() tea.Cmd {
	vault := ""
	if v, ok := m.currentVault(); ok {
		vault = v.Name
	} else if len(m.snap.Vaults) == 1 {
		vault = m.snap.Vaults[0].Name
	}
	var name string
	askDesc := func(m *Model) {
		m.openPrompt(&prompt{title: "Add key", label: "Description (optional): ",
			cancel: func(m *Model) { m.dropPending() },
			submit: func(m *Model, text []byte) tea.Cmd {
				desc := string(text)
				val := m.pending
				m.pending = nil
				// The description is shown in clear and stored unencrypted:
				// refuse one that is, or contains, the value just typed.
				if len(val) >= minGuard && strings.Contains(desc, string(val)) {
					clear(val)
					m.setStatus("The description contains the value. Nothing was saved: a description is stored in clear.", true)
					return nil
				}
				v := vault
				return m.runOp("Saving", v, name, func(b Backend) (string, error) {
					defer clear(val)
					if err := b.Set(v, name, val, &desc); err != nil {
						return "", err
					}
					return "Saved " + clean(name) + ".", nil
				})
			}})
	}
	askValue := func(m *Model) {
		m.openPrompt(&prompt{title: "Add key", label: "Value for " + clean(name) + " (hidden): ", hidden: true,
			submit: func(m *Model, text []byte) tea.Cmd {
				if len(text) == 0 {
					m.setStatus("No value given.", true)
					return nil
				}
				m.pending = slices.Clone(text)
				askDesc(m)
				return nil
			}})
	}
	askName := func(m *Model) {
		m.openPrompt(&prompt{title: "Add key", label: "Key name (like STRIPE_API_KEY): ",
			submit: func(m *Model, text []byte) tea.Cmd {
				n := strings.TrimSpace(string(text))
				if err := m.b.ValidateName(n); err != nil {
					m.fail(err)
					return nil
				}
				name = n
				askValue(m)
				return nil
			}})
	}
	if vault != "" {
		askName(m)
		return nil
	}
	if len(m.snap.Vaults) == 0 {
		m.setStatus("No vaults yet. Create one with: vault init NAME --path DIR", true)
		return nil
	}
	m.openPrompt(&prompt{title: "Add key", label: "Vault (" + m.vaultNames() + "): ",
		submit: func(m *Model, text []byte) tea.Cmd {
			v := strings.TrimSpace(string(text))
			if !m.hasVault(v) {
				m.setStatus("No vault called that. Choose one of: "+m.vaultNames(), true)
				return nil
			}
			vault = v
			askName(m)
			return nil
		}})
	return nil
}

// minGuard is the shortest value the description guard compares (a one or
// two letter value would match ordinary words).
const minGuard = 6

func (m *Model) dropPending() {
	clear(m.pending)
	m.pending = nil
}

func (m *Model) vaultNames() string {
	var ns []string
	for _, v := range m.snap.Vaults {
		ns = append(ns, clean(v.Name))
	}
	return strings.Join(ns, ", ")
}

func (m *Model) hasVault(n string) bool {
	return slices.ContainsFunc(m.snap.Vaults, func(v Vault) bool { return v.Name == n })
}

// --- edit value, describe, tag, move, rename, delete ---

func (m *Model) startEdit() tea.Cmd {
	k, ok := m.needKey()
	if !ok {
		return nil
	}
	m.openPrompt(&prompt{title: "Edit value", label: "New value for " + clean(k.Name) + " (hidden): ", hidden: true,
		submit: func(m *Model, text []byte) tea.Cmd {
			if len(text) == 0 {
				m.setStatus("No value given.", true)
				return nil
			}
			val := slices.Clone(text)
			return m.runOp("Saving", k.Vault, k.Name, func(b Backend) (string, error) {
				defer clear(val)
				if err := b.Set(k.Vault, k.Name, val, nil); err != nil {
					return "", err
				}
				return "Updated " + clean(k.Name) + ".", nil
			})
		}})
	return nil
}

func (m *Model) startDescribe() tea.Cmd {
	k, ok := m.needKey()
	if !ok {
		return nil
	}
	m.openPrompt(&prompt{title: "Describe", label: "Description of " + clean(k.Name) + ": ", buf: []rune(k.Description),
		submit: func(m *Model, text []byte) tea.Cmd {
			t := string(text)
			return m.runOp("Saving", k.Vault, k.Name, func(b Backend) (string, error) {
				return "Updated the description.", b.Describe(k.Vault, k.Name, t)
			})
		}})
	return nil
}

func (m *Model) startTag() tea.Cmd {
	k, ok := m.needKey()
	if !ok {
		return nil
	}
	m.openPrompt(&prompt{title: "Tags", label: "Tags of " + clean(k.Name) + " (comma separated): ",
		buf: []rune(strings.Join(k.Tags, ", ")),
		submit: func(m *Model, text []byte) tea.Cmd {
			var want []string
			for _, t := range strings.Split(string(text), ",") {
				if t = strings.TrimSpace(t); t != "" {
					want = append(want, t)
				}
			}
			var add, rm []string
			for _, t := range want {
				if !slices.Contains(k.Tags, t) {
					add = append(add, t)
				}
			}
			for _, t := range k.Tags {
				if !slices.Contains(want, t) {
					rm = append(rm, t)
				}
			}
			if len(add) == 0 && len(rm) == 0 {
				m.setStatus("Tags unchanged.", false)
				return nil
			}
			return m.runOp("Saving", k.Vault, k.Name, func(b Backend) (string, error) {
				return "Updated the tags.", b.Tag(k.Vault, k.Name, add, rm)
			})
		}})
	return nil
}

func (m *Model) startMove() tea.Cmd {
	k, ok := m.needKey()
	if !ok {
		return nil
	}
	m.openPrompt(&prompt{title: "Move", label: "Move " + clean(k.Name) + " to vault (" + m.vaultNames() + "): ",
		submit: func(m *Model, text []byte) tea.Cmd {
			to := strings.TrimSpace(string(text))
			if !m.hasVault(to) {
				m.setStatus("No vault called that. Choose one of: "+m.vaultNames(), true)
				return nil
			}
			return m.runOp("Moving", to, k.Name, func(b Backend) (string, error) {
				return "Moved " + clean(k.Name) + " to " + clean(to) + ".", b.Move(k.Vault, k.Name, to)
			})
		}})
	return nil
}

func (m *Model) startRename() tea.Cmd {
	k, ok := m.needKey()
	if !ok {
		return nil
	}
	m.openPrompt(&prompt{title: "Rename", label: "New name for " + clean(k.Name) + ": ", buf: []rune(k.Name),
		submit: func(m *Model, text []byte) tea.Cmd {
			n := strings.TrimSpace(string(text))
			if err := m.b.ValidateName(n); err != nil {
				m.fail(err)
				return nil
			}
			if n == k.Name {
				m.setStatus("Name unchanged.", false)
				return nil
			}
			return m.runOp("Renaming", k.Vault, n, func(b Backend) (string, error) {
				return "Renamed to " + clean(n) + ".", b.Rename(k.Vault, k.Name, n)
			})
		}})
	return nil
}

func (m *Model) startDelete() tea.Cmd {
	k, ok := m.needKey()
	if !ok {
		return nil
	}
	m.hide()
	m.mode = modeConfirm
	m.conf = &confirmState{
		text: "Delete " + clean(k.Name) + " from '" + clean(k.Vault) + "'? It stays in the trash for 30 days.",
		yes: func(m *Model) tea.Cmd {
			return m.runOp("Deleting", "", "", func(b Backend) (string, error) {
				return "Deleted " + clean(k.Name) + " (kept in the trash for 30 days).", b.Delete(k.Vault, k.Name)
			})
		},
	}
	return nil
}
