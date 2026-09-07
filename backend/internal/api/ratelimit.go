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

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{data: map[string]bucket{}, max: max, window: window}
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
