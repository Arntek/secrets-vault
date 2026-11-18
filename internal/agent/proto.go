package agent

import (
	"encoding/binary"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

// Wire format. Every message is a frame: a 4-byte big-endian length followed
// by that many body bytes. Bodies are small binary records, parsed strictly
// (no trailing bytes, no unknown opcodes), never JSON, so no copies of key
// material are left in decoder intermediates.
//
// Request body:
//
//	op u8 | vaultLen u16 | vault | ttlMillis u64 | keyLen u16 | key
//
// Response body:
//
//	status u8, then for status 0 an op-specific payload:
//	  OpKey:    keyLen u16 | key
//	  OpStatus: count u16 | count * (vaultLen u16 | vault | expiresUnixMillis i64)
//	  others:   empty
//
// Error responses carry only a status code; the client maps codes to fixed
// messages, so no free text (and no accidental secret) crosses the wire.
const (
	// MaxRequestSize bounds a request frame body.
	MaxRequestSize = 1024
	// MaxResponseSize bounds a response frame body.
	MaxResponseSize = 64 * 1024
	// MaxVaultIDLen bounds a vault ID in bytes.
	MaxVaultIDLen = 128
)

// maxWireTTLMillis is a sanity bound on the TTL field (48h); ValidateTTL
// applies the real 5m to 24h range when an unlock is served.
const maxWireTTLMillis uint64 = 48 * 60 * 60 * 1000

// Op is a request opcode.
type Op uint8

// Opcodes.
const (
	OpPing Op = iota + 1
	OpUnlock
	OpKey
	OpLock
	OpLockAll
	OpStatus
	OpShutdown
	opMax
)

// Status codes in responses.
const (
	statusOK uint8 = iota
	statusLocked
	statusBadRequest
	statusBadTTL
	statusFull
	statusInternal
)

// Errors from parsing untrusted messages.
var (
	ErrMessageTooLarge = errors.New("agent: message too large")
	ErrBadMessage      = errors.New("agent: malformed message")
)

// Request is a parsed client request.
type Request struct {
	Op    Op
	Vault string
	TTL   time.Duration
	Key   []byte // 0 or crypto.KeySize bytes; the parser's own copy
}

// ReadFrame reads one frame body of at most max bytes from r. A declared
// length over max is rejected before any body is read or allocated.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, ErrBadMessage
	}
	if n > uint32(max) { // #nosec G115 -- max is a small positive constant
		return nil, ErrMessageTooLarge
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		clear(body)
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return body, nil
}

// WriteFrame writes body as one frame.
func WriteFrame(w io.Writer, body []byte) error {
	if len(body) == 0 || len(body) > MaxResponseSize {
		return ErrMessageTooLarge
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body))) // #nosec G115 -- bounded above
	copy(buf[4:], body)
	_, err := w.Write(buf)
	clear(buf)
	return err
}

// validVaultID reports whether s is acceptable as a vault ID.
func validVaultID(s string) bool {
	if len(s) == 0 || len(s) > MaxVaultIDLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// EncodeRequest builds a request body. key may be nil.
func EncodeRequest(op Op, vault string, ttl time.Duration, key []byte) ([]byte, error) {
	if op == 0 || op >= opMax || len(vault) > MaxVaultIDLen || len(key) > crypto.KeySize || ttl < 0 {
		return nil, ErrBadMessage
	}
	b := make([]byte, 0, 1+2+len(vault)+8+2+len(key))
	b = append(b, byte(op))
	b = binary.BigEndian.AppendUint16(b, uint16(len(vault))) // #nosec G115 -- checked above
	b = append(b, vault...)
	b = binary.BigEndian.AppendUint64(b, uint64(ttl.Milliseconds())) // #nosec G115 -- non-negative ttl validated by caller
	b = binary.BigEndian.AppendUint16(b, uint16(len(key)))           // #nosec G115 -- checked above
	b = append(b, key...)
	return b, nil
}

// ParseRequest strictly parses a request body. The returned Key (if any) is
// a copy the caller must clear.
func ParseRequest(b []byte) (Request, error) {
	var req Request
	if len(b) < 1+2 {
		return req, ErrBadMessage
	}
	req.Op = Op(b[0])
	if req.Op == 0 || req.Op >= opMax {
		return req, ErrBadMessage
	}
	vl := int(binary.BigEndian.Uint16(b[1:]))
	rest := b[3:]
	if vl > MaxVaultIDLen || len(rest) < vl+8+2 {
		return req, ErrBadMessage
	}
	vault := string(rest[:vl])
	rest = rest[vl:]
	ttlMS := binary.BigEndian.Uint64(rest)
	rest = rest[8:]
	kl := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if kl != 0 && kl != crypto.KeySize {
		return req, ErrBadMessage
	}
	if len(rest) != kl { // trailing or missing bytes
		return req, ErrBadMessage
	}
	if ttlMS > maxWireTTLMillis { // sanity bound; the real range is checked per op
		return req, ErrBadMessage
	}
	req.TTL = time.Duration(ttlMS) * time.Millisecond // #nosec G115 -- bounded above
	req.Vault = vault
	if kl > 0 {
		req.Key = append([]byte(nil), rest...)
	}
	// Shape rules per op.
	switch req.Op {
	case OpUnlock:
		if !validVaultID(vault) || kl != crypto.KeySize {
			clear(req.Key)
			return Request{}, ErrBadMessage
		}
	case OpKey, OpLock:
		if !validVaultID(vault) || kl != 0 {
			return Request{}, ErrBadMessage
		}
	default: // ping, lock-all, status, shutdown carry nothing
		if vault != "" || kl != 0 {
			return Request{}, ErrBadMessage
		}
	}
	return req, nil
}

// encodeResponse builds a response body: status, then payload.
func encodeResponse(status uint8, payload []byte) []byte {
	return append([]byte{status}, payload...)
}

func encodeKeyPayload(key []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(key))) // #nosec G115 -- always KeySize
	return append(b, key...)
}

func parseKeyPayload(p []byte) ([]byte, error) {
	if len(p) < 2 {
		return nil, ErrBadMessage
	}
	n := int(binary.BigEndian.Uint16(p))
	if n != crypto.KeySize || len(p) != 2+n {
		return nil, ErrBadMessage
	}
	return p[2:], nil
}

func encodeStatusPayload(list []VaultStatus) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(list))) // #nosec G115 -- capped by MaxVaults
	for _, s := range list {
		b = binary.BigEndian.AppendUint16(b, uint16(len(s.VaultID))) // #nosec G115 -- validated vault ID
		b = append(b, s.VaultID...)
		b = binary.BigEndian.AppendUint64(b, uint64(s.ExpiresAt.UnixMilli())) // #nosec G115 -- timestamp
	}
	return b
}

func parseStatusPayload(p []byte) ([]VaultStatus, error) {
	if len(p) < 2 {
		return nil, ErrBadMessage
	}
	count := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if count > MaxVaults {
		return nil, ErrBadMessage
	}
	out := make([]VaultStatus, 0, count)
	for range count {
		if len(p) < 2 {
			return nil, ErrBadMessage
		}
		vl := int(binary.BigEndian.Uint16(p))
		p = p[2:]
		if vl > MaxVaultIDLen || len(p) < vl+8 {
			return nil, ErrBadMessage
		}
		id := string(p[:vl])
		ms := int64(binary.BigEndian.Uint64(p[vl:])) // #nosec G115 -- timestamp round trip
		p = p[vl+8:]
		if !validVaultID(id) {
			return nil, ErrBadMessage
		}
		out = append(out, VaultStatus{VaultID: id, Unlocked: true, ExpiresAt: time.UnixMilli(ms)})
	}
	if len(p) != 0 {
		return nil, ErrBadMessage
	}
	return out, nil
}
