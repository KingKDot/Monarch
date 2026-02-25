package ratelimit

import (
	"sync"
	"time"
)

type WindowCounter struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	items     map[string]*counter
}

type counter struct {
	resetAt time.Time
	count   int
}

func NewWindowCounter(window time.Duration, threshold int) *WindowCounter {
	return &WindowCounter{
		window:    window,
		threshold: threshold,
		items:     map[string]*counter{},
	}
}

func (w *WindowCounter) Increment(key string, now time.Time) (count int, over bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	c := w.items[key]
	if c == nil || now.After(c.resetAt) {
		c = &counter{resetAt: now.Add(w.window)}
		w.items[key] = c
	}
	c.count++
	return c.count, c.count > w.threshold
}

func (w *WindowCounter) Current(key string, now time.Time) (count int, over bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	c := w.items[key]
	if c == nil || now.After(c.resetAt) {
		if c != nil {
			delete(w.items, key)
		}
		return 0, false
	}
	return c.count, c.count > w.threshold
}
