package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

func testKeyBytes() []byte {
	b := make([]byte, crypto.KeySize)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func TestRequestRoundTrip(t *testing.T) {
	body, err := EncodeRequest(OpUnlock, "vault-1", time.Hour, testKeyBytes())
	if err != nil {
		t.Fatal(err)
	}
	req, err := ParseRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if req.Op != OpUnlock || req.Vault != "vault-1" || req.TTL != time.Hour || !bytes.Equal(req.Key, testKeyBytes()) {
		t.Fatalf("round trip mismatch: %+v", req)
	}
}

func TestParseRequestRejects(t *testing.T) {
	good, _ := EncodeRequest(OpUnlock, "v", time.Hour, testKeyBytes())
	cases := map[string][]byte{
		"empty":        {},
		"op zero":      {0, 0, 0},
		"op too big":   {byte(opMax), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"truncated":    good[:len(good)-1],
		"trailing":     append(bytes.Clone(good), 0),
		"short key":    mustEncode(t, OpUnlock, "v", time.Hour, make([]byte, 5)),
		"no key":       mustEncode(t, OpUnlock, "v", time.Hour, nil),
		"unlock no id": mustEncode(t, OpUnlock, "", time.Hour, testKeyBytes()),
		"ctrl in id":   mustEncode(t, OpKey, "a\nb", 0, nil),
		"key on lock":  mustEncode(t, OpLock, "v", 0, testKeyBytes()),
		"id on ping":   mustEncode(t, OpPing, "v", 0, nil),
		"huge ttl":     hugeTTL(),
	}
	for name, b := range cases {
		if _, err := ParseRequest(b); !errors.Is(err, ErrBadMessage) {
			t.Errorf("%s: err = %v, want ErrBadMessage", name, err)
		}
	}
}

func mustEncode(t *testing.T, op Op, v string, ttl time.Duration, k []byte) []byte {
	t.Helper()
	b, err := EncodeRequest(op, v, ttl, k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hugeTTL() []byte {
	b, _ := EncodeRequest(OpPing, "", 0, nil)
	binary.BigEndian.PutUint64(b[3:], ^uint64(0))
	return b
}

func TestEncodeRequestRejects(t *testing.T) {
	if _, err := EncodeRequest(OpKey, strings.Repeat("x", MaxVaultIDLen+1), 0, nil); err == nil {
		t.Error("long vault id accepted")
	}
	if _, err := EncodeRequest(0, "", 0, nil); err == nil {
		t.Error("op 0 accepted")
	}
}

func TestReadFrameLimits(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteFrame(&buf, []byte("hello"))
	got, err := ReadFrame(&buf, 16)
	if err != nil || string(got) != "hello" {
		t.Fatalf("ReadFrame = %q, %v", got, err)
	}
	// Declared length over the cap is refused without reading the body.
	over := binary.BigEndian.AppendUint32(nil, 17)
	if _, err := ReadFrame(bytes.NewReader(over), 16); !errors.Is(err, ErrMessageTooLarge) {
		t.Errorf("oversize: %v", err)
	}
	// Absurd length (4 GiB) must not allocate.
	if _, err := ReadFrame(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff}), MaxRequestSize); !errors.Is(err, ErrMessageTooLarge) {
		t.Errorf("huge: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 0}), 16); !errors.Is(err, ErrBadMessage) {
		t.Errorf("zero length: %v", err)
	}
	short := append(binary.BigEndian.AppendUint32(nil, 10), 1, 2, 3)
	if _, err := ReadFrame(bytes.NewReader(short), 16); err == nil {
		t.Error("truncated body accepted")
	}
}

func TestStatusPayloadRoundTrip(t *testing.T) {
	in := []VaultStatus{
		{VaultID: "a", Unlocked: true, ExpiresAt: time.UnixMilli(1_700_000_000_000)},
		{VaultID: "b", Unlocked: true, ExpiresAt: time.UnixMilli(1_700_000_100_000)},
	}
	out, err := parseStatusPayload(encodeStatusPayload(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].VaultID != "a" || !out[1].ExpiresAt.Equal(in[1].ExpiresAt) {
		t.Fatalf("got %+v", out)
	}
	if _, err := parseStatusPayload(append(encodeStatusPayload(in), 0)); err == nil {
		t.Error("trailing bytes accepted")
	}
}

func FuzzParseRequest(f *testing.F) {
	for _, op := range []Op{OpPing, OpUnlock, OpKey, OpLock, OpLockAll, OpStatus, OpShutdown} {
		b, _ := EncodeRequest(op, map[bool]string{true: "v", false: ""}[op == OpKey || op == OpLock || op == OpUnlock], time.Hour, nil)
		f.Add(b)
	}
	k, _ := EncodeRequest(OpUnlock, "vault", DefaultTTL, testKeyBytes())
	f.Add(k)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 40))
	f.Fuzz(func(t *testing.T, b []byte) {
		req, err := ParseRequest(b)
		if err != nil {
			return
		}
		// Anything accepted must re-encode to exactly the same bytes.
		again, err := EncodeRequest(req.Op, req.Vault, req.TTL, req.Key)
		if err != nil {
			t.Fatalf("accepted request does not re-encode: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("round trip differs")
		}
	})
}

func FuzzReadFrame(f *testing.F) {
	var buf bytes.Buffer
	_ = WriteFrame(&buf, []byte("seed"))
	f.Add(buf.Bytes())
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		body, err := ReadFrame(bytes.NewReader(b), MaxRequestSize)
		if err == nil && (len(body) == 0 || len(body) > MaxRequestSize) {
			t.Fatalf("frame of %d bytes accepted", len(body))
		}
	})
}

func FuzzParseStatusPayload(f *testing.F) {
	f.Add(encodeStatusPayload([]VaultStatus{{VaultID: "a", ExpiresAt: time.UnixMilli(5)}}))
	f.Add([]byte{0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := parseStatusPayload(b)
		if err == nil && len(out) > MaxVaults {
			t.Fatal("too many entries accepted")
		}
	})
}
