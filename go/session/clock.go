package session

import "time"

// Clock is the time source of a session: timeouts (Hello, schema ack,
// cancel give-up, idle, lease shrink, grace period) and call deadlines all
// run on it, so tests can drive them with a fake clock.
type Clock interface {
	Now() time.Time
	// AfterFunc calls f in its own goroutine after d.
	AfterFunc(d time.Duration, f func()) Timer
}

// Timer is a pending AfterFunc; Stop prevents the call and reports
// whether it did. It is an alias so that any clock package can implement
// Clock without importing this one.
type Timer = interface{ Stop() bool }

// RealClock is the wall clock.
type RealClock struct{}

// Now returns time.Now().
func (RealClock) Now() time.Time { return time.Now() }

// AfterFunc is time.AfterFunc.
func (RealClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

type nopTimer struct{}

func (nopTimer) Stop() bool { return false }

func stopTimer(t Timer) {
	if t != nil {
		t.Stop()
	}
}
