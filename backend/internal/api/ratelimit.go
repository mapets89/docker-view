package api

import (
	"sync"
	"time"
)

type bucket struct {
	count int
	reset time.Time
}
type limiter struct {
	mu     sync.Mutex
	data   map[string]bucket
	max    int
	window time.Duration
}

type loginAttempt struct {
	failures     int
	blockedUntil time.Time
	lastSeen     time.Time
}

type loginThrottle struct {
	mu       sync.Mutex
	data     map[string]loginAttempt
	max      int
	cooldown time.Duration
	now      func() time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{data: map[string]bucket{}, max: max, window: window}
}

func newLoginThrottle(max int, cooldown time.Duration) *loginThrottle {
	return &loginThrottle{data: map[string]loginAttempt{}, max: max, cooldown: cooldown, now: time.Now}
}

func (l *loginThrottle) blocked(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	attempt, ok := l.data[key]
	if !ok {
		return 0
	}
	if attempt.blockedUntil.After(now) {
		return attempt.blockedUntil.Sub(now)
	}
	if !attempt.blockedUntil.IsZero() {
		delete(l.data, key)
	}
	return 0
}

func (l *loginThrottle) failed(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	attempt := l.data[key]
	if attempt.blockedUntil.After(now) {
		return attempt.blockedUntil.Sub(now)
	}
	if !attempt.blockedUntil.IsZero() {
		attempt = loginAttempt{}
	}
	attempt.failures++
	attempt.lastSeen = now
	if attempt.failures >= l.max {
		attempt.failures = 0
		attempt.blockedUntil = now.Add(l.cooldown)
	}
	l.data[key] = attempt
	l.prune(now)
	if attempt.blockedUntil.After(now) {
		return attempt.blockedUntil.Sub(now)
	}
	return 0
}

func (l *loginThrottle) clear(key string) {
	l.mu.Lock()
	delete(l.data, key)
	l.mu.Unlock()
}

func (l *loginThrottle) prune(now time.Time) {
	if len(l.data) <= 10000 {
		return
	}
	for key, attempt := range l.data {
		if !attempt.blockedUntil.After(now) && now.Sub(attempt.lastSeen) > 10*time.Minute {
			delete(l.data, key)
		}
	}
}
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.data[key]
	n := time.Now()
	if n.After(b.reset) {
		b = bucket{reset: n.Add(l.window)}
	}
	b.count++
	l.data[key] = b
	if len(l.data) > 10000 {
		for k, v := range l.data {
			if n.After(v.reset) {
				delete(l.data, k)
			}
		}
	}
	return b.count <= l.max
}
