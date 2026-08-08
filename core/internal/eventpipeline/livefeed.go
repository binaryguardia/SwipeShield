package eventpipeline

import (
	"context"
	"sync"
)

// LiveFeed is a bounded ring buffer of recent events with multi-subscriber
// fan-out. It implements Sink so it can be attached directly to a Pipeline;
// the Management API reads from it for the real-time traffic view and
// /events SSE stream. New subscribers receive the most recent buffered
// events before live updates, so a fresh dashboard connection is never blank.
type LiveFeed struct {
	mu     sync.Mutex
	events []Event // ring
	head   int
	size   int
	subs   map[chan Event]struct{}
	closed bool
}

// NewLiveFeed creates a feed retaining up to capacity events.
func NewLiveFeed(capacity int) *LiveFeed {
	if capacity <= 0 {
		capacity = 256
	}
	return &LiveFeed{
		events: make([]Event, 0, capacity),
		size:   capacity,
		subs:   map[chan Event]struct{}{},
	}
}

// Write appends an event to the ring and broadcasts to subscribers. It is
// never called on the request path (the pipeline drains async).
func (f *LiveFeed) Write(_ context.Context, e *Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	if len(f.events) < f.size {
		f.events = append(f.events, *e)
	} else {
		f.events[f.head] = *e
	}
	f.head = (f.head + 1) % f.size
	for ch := range f.subs {
		select {
		case ch <- *e:
		default: // slow subscriber: skip, never block the feed
		}
	}
	return nil
}

// Recent returns the last n events in chronological order.
func (f *LiveFeed) Recent(n int) []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n <= 0 || n > len(f.events) {
		n = len(f.events)
	}
	out := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		idx := (f.head - n + i) % f.size
		if idx < 0 {
			idx += f.size
		}
		if idx < len(f.events) {
			out = append(out, f.events[idx])
		}
	}
	return out
}

// Subscribe registers a new subscriber. It receives recent history (up to
// buf events) then live updates. Returns the channel and an unsubscribe func.
func (f *LiveFeed) Subscribe(buf int) (<-chan Event, func()) {
	if buf <= 0 {
		buf = 64
	}
	ch := make(chan Event, buf)
	f.mu.Lock()
	if !f.closed {
		n := len(f.events)
		if n > buf {
			n = buf
		}
		for i := 0; i < n; i++ {
			idx := (f.head - n + i) % f.size
			if idx < 0 {
				idx += f.size
			}
			if idx < len(f.events) {
				ch <- f.events[idx]
			}
		}
		f.subs[ch] = struct{}{}
	}
	f.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			f.mu.Lock()
			delete(f.subs, ch)
			// Close may have already shut this channel down; never close
			// twice.
			if !f.closed {
				close(ch)
			}
			f.mu.Unlock()
		})
	}
}

// Close shuts the feed down and closes all subscriber channels.
func (f *LiveFeed) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	for ch := range f.subs {
		close(ch)
	}
	f.subs = map[chan Event]struct{}{}
	return nil
}
