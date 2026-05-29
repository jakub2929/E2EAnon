// Package ratelimit provides a minimal per-key fixed-window rate limiter for
// basic abuse protection (room creation, invite redemption). In-memory only.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter allows up to `limit` events per `window` per key.
type Limiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count int
	reset time.Time
}

// New returns a limiter allowing `perWindow` events per `window`. A non-positive
// limit disables limiting (Allow always returns true).
func New(perWindow int, window time.Duration) *Limiter {
	return &Limiter{
		limit:   perWindow,
		window:  window,
		now:     time.Now,
		buckets: make(map[string]*bucket),
	}
}

// Allow records an event for key and reports whether it is within the limit.
func (l *Limiter) Allow(key string) bool {
	if l.limit <= 0 {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok || now.After(b.reset) {
		l.buckets[key] = &bucket{count: 1, reset: now.Add(l.window)}
		return true
	}
	if b.count >= l.limit {
		return false
	}
	b.count++
	return true
}

// Cleanup drops expired buckets to bound memory. Safe to call periodically.
func (l *Limiter) Cleanup() {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if now.After(b.reset) {
			delete(l.buckets, k)
		}
	}
}
