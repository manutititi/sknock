package nonce

import (
	"context"
	"encoding/hex"
	"sync"
	"time"
)

type Store struct {
	mu      sync.Mutex
	entries map[string]time.Time
	ttl     time.Duration
}

func NewStore(ttl time.Duration) *Store {
	return &Store{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}
}

// CheckAndStore returns true if the nonce is new (not a replay).
// Returns false if the nonce was already seen.
func (s *Store) CheckAndStore(nonce []byte) bool {
	key := hex.EncodeToString(nonce)
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.entries[key]; exists {
		return false
	}
	s.entries[key] = time.Now().Add(s.ttl)
	return true
}

// StartCleanup runs a goroutine that purges expired nonces.
func (s *Store) StartCleanup(ctx context.Context) {
	interval := s.ttl / 2
	if interval < time.Second {
		interval = time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				s.mu.Lock()
				for k, exp := range s.entries {
					if now.After(exp) {
						delete(s.entries, k)
					}
				}
				s.mu.Unlock()
			}
		}
	}()
}
