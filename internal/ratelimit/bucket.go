package ratelimit

import (
	"context"
	"sync"
	"time"
)

type tokenBucket struct {
	tokens   float64
	lastTime time.Time
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64 // tokens per second
	burst   int
}

func NewLimiter(rate float64, burst int) *Limiter {
	return &Limiter{
		buckets: make(map[string]*tokenBucket),
		rate:    rate,
		burst:   burst,
	}
}

// Allow returns true if the IP has tokens available.
func (l *Limiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, exists := l.buckets[ip]
	if !exists {
		b = &tokenBucket{
			tokens:   float64(l.burst) - 1,
			lastTime: now,
		}
		l.buckets[ip] = b
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastTime = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// StartCleanup removes stale IP buckets every interval.
func (l *Limiter) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				l.mu.Lock()
				for ip, b := range l.buckets {
					// Remove if idle for more than 5 minutes
					if now.Sub(b.lastTime) > 5*time.Minute {
						delete(l.buckets, ip)
					}
				}
				l.mu.Unlock()
			}
		}
	}()
}
