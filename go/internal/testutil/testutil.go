// Package testutil holds helpers shared by the session, transport and node
// tests: a fake clock and polling assertions.
package testutil

import (
	"sort"
	"sync"
	"testing"
	"time"
)

// Timer is what FakeClock.AfterFunc returns; it matches session.Timer.
type Timer = interface{ Stop() bool }

// FakeClock is a manually advanced clock. Timers fire, each in its own
// goroutine, when Advance moves the clock past their time.
type FakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
	seq    int
}

type fakeTimer struct {
	c       *FakeClock
	at      time.Time
	seq     int
	f       func()
	stopped bool
	fired   bool
}

// NewFakeClock returns a clock at a fixed instant.
func NewFakeClock() *FakeClock {
	return &FakeClock{now: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)}
}

// Now returns the fake time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// AfterFunc schedules f.
func (c *FakeClock) AfterFunc(d time.Duration, f func()) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	t := &fakeTimer{c: c, at: c.now.Add(d), seq: c.seq, f: f}
	c.timers = append(c.timers, t)
	return t
}

func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	if t.stopped || t.fired {
		return false
	}
	t.stopped = true
	return true
}

// Advance moves the clock forward, firing due timers in time order. Timers
// scheduled by fired timers are fired too if they fall within the step.
// Each fired function runs in its own goroutine; Advance waits briefly for
// them to start.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.now.Add(d)
	c.mu.Unlock()
	for {
		c.mu.Lock()
		sort.Slice(c.timers, func(i, j int) bool {
			if c.timers[i].at.Equal(c.timers[j].at) {
				return c.timers[i].seq < c.timers[j].seq
			}
			return c.timers[i].at.Before(c.timers[j].at)
		})
		var next *fakeTimer
		keep := c.timers[:0]
		for _, t := range c.timers {
			if t.stopped || t.fired {
				continue
			}
			keep = append(keep, t)
		}
		c.timers = keep
		if len(c.timers) > 0 && !c.timers[0].at.After(target) {
			next = c.timers[0]
			next.fired = true
			if next.at.After(c.now) {
				c.now = next.at
			}
		}
		if next == nil {
			c.now = target
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		done := make(chan struct{})
		go func() { close(done); next.f() }()
		<-done
		time.Sleep(time.Millisecond)
	}
}

// Pending returns the number of timers not yet fired or stopped.
func (c *FakeClock) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if !t.stopped && !t.fired {
			n++
		}
	}
	return n
}

// Eventually polls cond until it holds or the timeout passes.
func Eventually(t testing.TB, timeout time.Duration, cond func() bool, msg string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !cond() {
		t.Fatalf("condition not met within %v: "+msg, append([]any{timeout}, args...)...)
	}
}
