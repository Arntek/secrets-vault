package format

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// maxJSONDepth bounds nesting so a crafted file cannot recurse deeply.
const maxJSONDepth = 16

// decodeStrict decodes exactly one JSON value from data into v.
//
// On top of encoding/json it rejects: input over MaxFileSize, invalid UTF-8,
// duplicate object keys (encoding/json silently keeps the last), keys that
// are not lower case (encoding/json matches field names case-insensitively),
// unknown fields, nesting deeper than maxJSONDepth and trailing data. Error
// messages give offsets and our own field names only, never input bytes.
func decodeStrict(data []byte, v any) error { return decodeStrictMax(data, MaxFileSize, v) }

// decodeStrictMax is decodeStrict with its own size limit.
func decodeStrictMax(data []byte, maxSize int, v any) error {
	if err := checkJSONShapeMax(data, maxSize); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return describeJSONError(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: unexpected data after the JSON value", ErrMalformed)
	}
	return nil
}

// checkJSONShape walks the token stream once without decoding values.
func checkJSONShapeMax(data []byte, maxSize int) error {
	if len(data) > maxSize {
		return fmt.Errorf("%w: larger than %d bytes", ErrTooLarge, maxSize)
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: not valid UTF-8", ErrMalformed)
	}
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
			break
		}
		if err != nil {
			return describeJSONError(err)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				if len(stack) >= maxJSONDepth {
					return fmt.Errorf("%w: nested deeper than %d levels", ErrMalformed, maxJSONDepth)
				}
				if top != nil && top.object {
					top.expectKey = true // the child is this key's value
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
			if err := checkKey(key); err != nil {
				return fmt.Errorf("%w at offset %d", err, dec.InputOffset())
			}
			if _, dup := top.keys[key]; dup {
				return fmt.Errorf("%w: duplicate key at offset %d", ErrMalformed, dec.InputOffset())
			}
			top.keys[key] = struct{}{}
			top.expectKey = false
			continue
		}
		if top != nil && top.object {
			top.expectKey = true
		}
	}
	return nil
}

// checkKey allows the key spellings our structs use: lower-case ASCII
// letters, digits and underscore.
func checkKey(k string) error {
	if k == "" || len(k) > 64 {
		return fmt.Errorf("%w: bad key length", ErrMalformed)
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return fmt.Errorf("%w: key with characters other than a-z, 0-9 and _", ErrMalformed)
		}
	}
	return nil
}

// describeJSONError turns an encoding/json error into one that never quotes
// the input.
func describeJSONError(err error) error {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return fmt.Errorf("%w: invalid JSON at offset %d", ErrMalformed, syn.Offset)
	case errors.As(err, &typ):
		return fmt.Errorf("%w: wrong type for field %q at offset %d", ErrMalformed, typ.Field, typ.Offset)
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return fmt.Errorf("%w: truncated JSON", ErrMalformed)
	default:
		// Unknown-field errors and time/base64 parse errors land here; their
		// messages can quote input, so they are not passed on.
		return fmt.Errorf("%w: invalid or unknown field", ErrMalformed)
	}
}
