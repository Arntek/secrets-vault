package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rotation: audit.log is renamed to audit.log.1 (and .1 to .2) once it
// reaches MaxSize, so at most Keep files exist.
const (
	DefaultMaxSize = 5 << 20
	DefaultKeep    = 3
	maxLine        = 4096
	maxFieldLen    = 128
)

// File appends events as JSON lines to a per-user log (0600, directory
// 0700). It is safe to use from several goroutines and, because every event
// is one O_APPEND write, from several processes at once.
type File struct {
	Path    string
	MaxSize int64 // rotate at this size; 0 means DefaultMaxSize
	Keep    int   // files kept including the live one; 0 means DefaultKeep

	mu sync.Mutex
}

// NewFile returns a File logger for path.
func NewFile(path string) *File { return &File{Path: path} }

func (f *File) limits() (int64, int) {
	m, k := f.MaxSize, f.Keep
	if m <= 0 {
		m = DefaultMaxSize
	}
	if k <= 0 {
		k = DefaultKeep
	}
	return m, k
}

// Clean makes a field safe to store and show: control characters removed,
// length capped.
func Clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			return -1
		}
		return r
	}, s)
	if len(s) > maxFieldLen {
		s = strings.ToValidUTF8(s[:maxFieldLen], "")
	}
	return s
}

// Record appends e. Errors never carry event contents.
func (f *File) Record(e Event) error {
	e.Vault, e.Key, e.Program = Clean(e.Vault), Clean(e.Key), Clean(e.Program)
	e.Command, e.Member, e.Via, e.User = Clean(e.Command), Clean(e.Member), Clean(e.Via), Clean(e.User)
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	line, err := json.Marshal(e)
	if err != nil {
		return errors.New("cannot encode the event")
	}
	line = append(line, '\n')

	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return unwrapPath(err)
	}
	if err := f.rotateIfNeeded(int64(len(line))); err != nil {
		return err
	}
	if fi, err := os.Lstat(f.Path); err == nil && !fi.Mode().IsRegular() {
		return errors.New("the log path is not a regular file")
	}
	h, err := os.OpenFile(f.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600) // #nosec G304 -- the user's own log path
	if err != nil {
		return unwrapPath(err)
	}
	if _, err := h.Write(line); err != nil {
		_ = h.Close()
		return unwrapPath(err)
	}
	return unwrapPath(h.Close())
}

func (f *File) rotateIfNeeded(next int64) error {
	max, keep := f.limits()
	fi, err := os.Lstat(f.Path)
	if err != nil || fi.Size()+next <= max {
		return nil
	}
	if keep < 2 {
		return unwrapPath(os.Remove(f.Path))
	}
	// Drop the oldest, then shift the rest up.
	_ = os.Remove(f.rotated(keep - 1))
	for i := keep - 2; i >= 1; i-- {
		if err := os.Rename(f.rotated(i), f.rotated(i+1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return unwrapPath(err)
		}
	}
	if err := os.Rename(f.Path, f.rotated(1)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return unwrapPath(err)
	}
	return nil
}

func (f *File) rotated(i int) string { return f.Path + "." + strconv.Itoa(i) }

func unwrapPath(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s: %w", pe.Op, pe.Err)
	}
	return err
}

// Filter selects events for Read. Zero fields match everything.
type Filter struct {
	Vault string
	Key   string
	Since time.Time
}

func (fl Filter) match(e Event) bool {
	if fl.Vault != "" && e.Vault != fl.Vault {
		return false
	}
	if fl.Key != "" && e.Key != fl.Key {
		return false
	}
	if !fl.Since.IsZero() && e.Time.Before(fl.Since) {
		return false
	}
	return true
}

// Read returns the matching events, oldest first, across the live file and
// its rotated copies. Lines that do not parse are skipped. A missing log is
// an empty result, not an error.
func (f *File) Read(fl Filter) ([]Event, error) {
	_, keep := f.limits()
	var out []Event
	for i := keep - 1; i >= 0; i-- {
		p := f.Path
		if i > 0 {
			p = f.rotated(i)
		}
		evs, err := readOne(p, fl)
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
	}
	return out, nil
}

func readOne(path string, fl Filter) ([]Event, error) {
	h, err := os.Open(path) // #nosec G304 -- the user's own log path
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read the log: %w", unwrapPath(err))
	}
	defer func() { _ = h.Close() }()
	var out []Event
	r := bufio.NewReaderSize(h, maxLine)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && len(line) <= maxLine {
			var e Event
			if json.Unmarshal(bytes.TrimSpace(line), &e) == nil && fl.match(e) {
				out = append(out, e)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				// An over-long line: skip the rest of it.
				for errors.Is(err, bufio.ErrBufferFull) {
					_, err = r.ReadBytes('\n')
				}
				if err == nil {
					continue
				}
				if errors.Is(err, io.EOF) {
					return out, nil
				}
			}
			return nil, fmt.Errorf("cannot read the log: %w", unwrapPath(err))
		}
	}
}
