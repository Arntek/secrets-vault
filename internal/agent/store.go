package agent

import (
	"sort"
	"sync"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

// entry is one held key with its expiry.
type entry struct {
	key     *crypto.VaultKey
	expires time.Time
}

// store holds unlocked keys in memory only. It takes ownership of every key
// it is given and destroys it on replacement, lock, expiry or Wipe.
type store struct {
	mu        sync.Mutex
	now       func() time.Time
	keys      map[string]entry
	emptyFrom time.Time // when the store last became empty (or was created)
}

func newStore(now func() time.Time) *store {
	return &store{now: now, keys: map[string]entry{}, emptyFrom: now()}
}

func (s *store) destroy(e entry) {
	unlockMemory(e.key.Bytes())
	e.key.Destroy()
}

// put stores key for vault until ttl elapses. ttl must already be validated.
func (s *store) put(vault string, key *crypto.VaultKey, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.keys[vault]; !ok && len(s.keys) >= MaxVaults {
		return errFull
	} else if ok {
		s.destroy(old)
	}
	lockMemory(key.Bytes()) // best effort: keep the key out of swap
	s.keys[vault] = entry{key: key, expires: s.now().Add(ttl)}
	return nil
}

// get returns a fresh copy of the key (caller destroys), or false if absent
// or expired. An expired key is destroyed on the spot.
func (s *store) get(vault string) (*crypto.VaultKey, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.keys[vault]
	if !ok {
		return nil, false
	}
	if !s.now().Before(e.expires) {
		s.drop(vault, e)
		return nil, false
	}
	cp, err := crypto.VaultKeyFromBytes(e.key.Bytes())
	if err != nil {
		return nil, false
	}
	return cp, true
}

func (s *store) drop(vault string, e entry) {
	s.destroy(e)
	delete(s.keys, vault)
	if len(s.keys) == 0 {
		s.emptyFrom = s.now()
	}
}

// lock forgets one vault's key.
func (s *store) lock(vault string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.keys[vault]; ok {
		s.drop(vault, e)
	}
}

// wipe forgets every key.
func (s *store) wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for v, e := range s.keys {
		s.drop(v, e)
	}
	s.emptyFrom = s.now()
}

// reap destroys expired keys and reports how long the store has been empty
// (zero if it holds keys).
func (s *store) reap() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for v, e := range s.keys {
		if !now.Before(e.expires) {
			s.drop(v, e)
		}
	}
	if len(s.keys) > 0 {
		return 0
	}
	return now.Sub(s.emptyFrom)
}

// status lists live vaults and their expiry, never keys.
func (s *store) status() []VaultStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make([]VaultStatus, 0, len(s.keys))
	for v, e := range s.keys {
		if now.Before(e.expires) {
			out = append(out, VaultStatus{VaultID: v, Unlocked: true, ExpiresAt: e.expires})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VaultID < out[j].VaultID })
	return out
}
