package agent

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_800_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newKey(t *testing.T) *crypto.VaultKey {
	t.Helper()
	k, err := crypto.NewVaultKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func allZero(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

func TestStoreExpiryDestroysKey(t *testing.T) {
	clk := newFakeClock()
	s := newStore(clk.Now)
	k := newKey(t)
	if err := s.put("v", k, time.Hour); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Hour - time.Second)
	got, ok := s.get("v")
	if !ok {
		t.Fatal("key gone before expiry")
	}
	got.Destroy()
	clk.Advance(time.Second) // exactly at expiry: expired
	if _, ok := s.get("v"); ok {
		t.Fatal("key still available at expiry")
	}
	if !allZero(k.Bytes()) {
		t.Fatal("expired key was not zeroed")
	}
}

func TestStoreReapZeroesWithoutAccess(t *testing.T) {
	clk := newFakeClock()
	s := newStore(clk.Now)
	k := newKey(t)
	_ = s.put("v", k, MinTTL)
	clk.Advance(MinTTL + time.Second)
	s.reap()
	if !allZero(k.Bytes()) || len(s.status()) != 0 {
		t.Fatal("reap did not destroy the expired key")
	}
}

func TestStoreReplaceLockWipe(t *testing.T) {
	clk := newFakeClock()
	s := newStore(clk.Now)
	a, b, c := newKey(t), newKey(t), newKey(t)
	_ = s.put("a", a, time.Hour)
	_ = s.put("a", b, time.Hour) // replaces a
	if !allZero(a.Bytes()) {
		t.Error("replaced key not zeroed")
	}
	_ = s.put("c", c, time.Hour)
	s.lock("a")
	if !allZero(b.Bytes()) || allZero(c.Bytes()) {
		t.Error("lock affected the wrong key")
	}
	s.wipe()
	if !allZero(c.Bytes()) || len(s.status()) != 0 {
		t.Error("wipe left a key")
	}
}

func TestStoreGetReturnsCopy(t *testing.T) {
	s := newStore(newFakeClock().Now)
	k := newKey(t)
	want := bytes.Clone(k.Bytes())
	_ = s.put("v", k, time.Hour)
	got, _ := s.get("v")
	got.Destroy() // caller destroys its copy
	again, ok := s.get("v")
	if !ok || !bytes.Equal(again.Bytes(), want) {
		t.Fatal("destroying a returned copy damaged the stored key")
	}
}

func TestStoreCapacity(t *testing.T) {
	s := newStore(newFakeClock().Now)
	for i := range MaxVaults {
		if err := s.put(string(rune('a'+i%26))+string(rune('A'+i/26)), newKey(t), time.Hour); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if err := s.put("one-too-many", newKey(t), time.Hour); err == nil {
		t.Fatal("capacity not enforced")
	}
}

func TestStoreIdleTracking(t *testing.T) {
	clk := newFakeClock()
	s := newStore(clk.Now)
	clk.Advance(2 * time.Minute)
	if got := s.reap(); got != 2*time.Minute {
		t.Errorf("idle = %s, want 2m", got)
	}
	_ = s.put("v", newKey(t), MinTTL)
	if s.reap() != 0 {
		t.Error("holding a key must not count as idle")
	}
	clk.Advance(MinTTL + time.Minute)
	if got := s.reap(); got != 0 { // the key is destroyed by this very reap
		t.Errorf("idle at moment of expiry = %s, want 0", got)
	}
	clk.Advance(time.Minute)
	if got := s.reap(); got != time.Minute {
		t.Errorf("idle after expiry = %s, want 1m", got)
	}
}

// A clock that returns times carrying a monotonic reading must not make the
// expiry depend on it: stored deadlines are pure wall-clock times.
func TestStoreExpiryHasNoMonotonicReading(t *testing.T) {
	s := newStore(time.Now) // real clock: values carry a monotonic reading
	if err := s.put("v", newKey(t), time.Hour); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.keys["v"].expires.String(), "m=") {
		t.Fatal("expiry still carries a monotonic reading")
	}
}

// Simulated sleep: wall time jumps forward (monotonic time would not). The
// key must be gone on the next request and on the next sweep.
func TestStoreWallJumpForwardExpires(t *testing.T) {
	for _, via := range []string{"get", "reap"} {
		clk := newFakeClock()
		s := newStore(clk.Now)
		if err := s.put("v", newKey(t), 4*time.Hour); err != nil {
			t.Fatal(err)
		}
		clk.Advance(14 * time.Hour) // overnight sleep
		if via == "get" {
			if _, ok := s.get("v"); ok {
				t.Fatal("key survived a wall-clock jump past its deadline")
			}
		} else {
			s.reap()
			if len(s.keys) != 0 {
				t.Fatal("sweep kept an expired key")
			}
		}
	}
}

// Moving the clock back by more than the tolerance locks everything.
func TestStoreClockBackwardsLocksAll(t *testing.T) {
	clk := newFakeClock()
	s := newStore(clk.Now)
	if err := s.put("v", newKey(t), time.Hour); err != nil {
		t.Fatal(err)
	}
	clk.Advance(-10 * time.Minute)
	if _, ok := s.get("v"); ok {
		t.Fatal("key still available after the clock moved back")
	}
	// the clock going forward again must not bring anything back
	clk.Advance(10 * time.Minute)
	if _, ok := s.get("v"); ok {
		t.Fatal("key came back")
	}
}

func TestStoreSmallClockBackwardsTolerated(t *testing.T) {
	clk := newFakeClock()
	s := newStore(clk.Now)
	if err := s.put("v", newKey(t), time.Hour); err != nil {
		t.Fatal(err)
	}
	clk.Advance(-time.Minute)
	if _, ok := s.get("v"); !ok {
		t.Fatal("a one-minute correction should not lock")
	}
	// repeated small steps must not accumulate past the tolerance
	for i := 0; i < 5; i++ {
		clk.Advance(-time.Minute)
	}
	if _, ok := s.get("v"); ok {
		t.Fatal("accumulated backwards steps beyond the tolerance should lock")
	}
}
