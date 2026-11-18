package members

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"unicode/utf8"
)

const maxJSONDepth = 16

// decodeStrict decodes exactly one JSON value from data into v. On top of
// encoding/json it rejects oversize input, invalid UTF-8, duplicate keys,
// keys other than lower-case a-z, 0-9 and "_", unknown fields, deep nesting
// and trailing data. Errors never quote the input.
//
// (Same rules as the unexported parser in package format; keep them in
// step.)
func decodeStrict(data []byte, max int, v any) error {
	if len(data) > max {
		return ErrTooLarge
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: not valid UTF-8", ErrMalformed)
	}
	if err := checkShape(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: invalid JSON or unknown field", ErrMalformed)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: unexpected data after the JSON value", ErrMalformed)
	}
	return nil
}

func checkShape(data []byte) error {
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]struct{}
	}
	var stack []*frame
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: invalid JSON", ErrMalformed)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack) >= maxJSONDepth {
					return fmt.Errorf("%w: nested too deeply", ErrMalformed)
				}
				if top != nil && top.object {
					top.expectKey = true
				}
				f := &frame{object: d == '{', expectKey: d == '{'}
				if f.object {
					f.keys = map[string]struct{}{}
				}
				stack = append(stack, f)
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if top != nil && top.object && top.expectKey {
			key, _ := tok.(string)
			if !validJSONKey(key) {
				return fmt.Errorf("%w: unexpected key spelling", ErrMalformed)
			}
			if _, dup := top.keys[key]; dup {
				return fmt.Errorf("%w: duplicate key", ErrMalformed)
			}
			top.keys[key] = struct{}{}
			top.expectKey = false
			continue
		}
		if top != nil && top.object {
			top.expectKey = true
		}
	}
}

func validJSONKey(k string) bool {
	if k == "" || len(k) > 64 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// readSmallFile reads a regular file of at most max bytes. Symlinks and
// non-regular files are refused (a tampered shared folder must not point us
// at another file on this machine). A missing file returns an error
// wrapping fs.ErrNotExist.
func readSmallFile(path string, max int64) ([]byte, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", ErrMalformed)
	}
	if li.Size() > max {
		return nil, ErrTooLarge
	}
	f, err := os.Open(path) // #nosec G304 -- path is built from a validated name under a user-chosen folder
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(li, fi) {
		return nil, fmt.Errorf("%w: not a regular file", ErrMalformed)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, ErrTooLarge
	}
	return data, nil
}

func isNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }
