package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

func itoa(i int) string { return strconv.Itoa(i) }

func runtimeIsWindows() bool { return runtime.GOOS == "windows" }

func (a *app) printJSON(v any) error {
	// A first-use pin made by this command is part of the result, so an
	// agent parsing stdout can't miss that it was not checked (ue1.10).
	if m, ok := v.(map[string]any); ok && a.firstPin != nil {
		m["state_code_checked"] = a.firstPin.Checked
		m["first_pin"] = a.firstPin
	}
	enc := json.NewEncoder(a.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

type table struct{ w *tabwriter.Writer }

func newTable(out io.Writer, header ...string) *table {
	t := &table{w: tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)}
	t.row(header...)
	return t
}

func (t *table) row(cols ...string) {
	for i, c := range cols {
		if i > 0 {
			fmt.Fprint(t.w, "\t")
		}
		fmt.Fprint(t.w, c)
	}
	fmt.Fprintln(t.w)
}

func (t *table) flush() { _ = t.w.Flush() }

// timeLeft renders a duration as "3h 58m".
func timeLeft(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Minute)
	h := int(d / time.Hour)
	m := int((d % time.Hour) / time.Minute)
	switch {
	case h > 0 && m > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	case h > 0:
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dm", m)
}

func keyCopy(k *crypto.VaultKey) (*crypto.VaultKey, error) {
	return crypto.VaultKeyFromBytes(k.Bytes())
}
