package session

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/wire"
	"sync"
)

// lane is one stream of the session: the shared lane or a leased stream.
type lane struct {
	s      *Session
	st     transport.Stream
	shared bool
	// opened is true for a leased stream this side opened (a member of
	// this side's pool); false for one the peer opened.
	opened bool

	wmu sync.Mutex

	// Guarded by s.mu.
	current     *call // leased: the call on the stream, nil when idle
	writeClosed bool
	readClosed  bool
	broken      bool // reset or failed: never reused
	counted     bool // still counted toward maxStreams
	idleSince   time.Time
	inPool      bool
	// awaitEnd is set on a stream this side opened and reset: its own
	// direction is aborted and it stays counted until the peer's direction
	// ends too (4.2 rule 5).
	awaitEnd bool
}

// write sends one encoded message on the lane, enforcing the peer's
// maxMessageSize and, for an optimistic client before Welcome, the 64 KiB
// budget (5.3).
func (l *lane) write(b []byte) error {
	s := l.s
	if max := s.peerLimitsSnapshot().MaxMessageSize; uint64(len(b)) > max {
		return &Error{Code: status.MessageTooLarge, Message: "message exceeds the peer's maxMessageSize"}
	}
	if l.shared && s.role == wire.Client {
		if err := s.preWelcomeBudget(len(b)); err != nil {
			return err
		}
	}
	l.wmu.Lock()
	err := l.st.WriteMessage(b)
	l.wmu.Unlock()
	if err != nil {
		if l.shared {
			s.lost(err)
		} else {
			s.laneBroken(l, err)
		}
		return s.wrapTransportErr(err)
	}
	if l.shared {
		s.lastSend.Store(s.clock.Now().UnixNano())
	}
	return nil
}

// readLoop reads every message of the lane until it ends (4.4: receivers
// always read).
func (l *lane) readLoop() {
	s := l.s
	for {
		b, err := l.st.ReadMessage()
		if err != nil {
			l.readEnded(err)
			return
		}
		s.lastRecv.Store(s.clock.Now().UnixNano())
		if l.shared {
			s.procMu.Lock()
			s.handleShared(l, b)
			s.procMu.Unlock()
		} else {
			s.mu.Lock()
			drop := l.broken
			s.mu.Unlock()
			if drop {
				// This side reset the stream: what the peer sent before it
				// saw the reset is discarded until its direction ends.
				continue
			}
			s.handleLeased(l, b)
		}
		if s.isClosed() && l.shared {
			// Keep draining until the transport is gone, so the peer is
			// never blocked on an unread stream.
			continue
		}
	}
}

func (l *lane) readEnded(err error) {
	s := l.s
	s.mu.Lock()
	awaiting := l.awaitEnd
	s.mu.Unlock()
	if awaiting {
		// This side reset the stream; the peer has now ended its own
		// direction, so both sides have sent and seen both ends.
		s.laneClosed(l)
		return
	}
	var tl *wire.TooLargeError
	if errors.As(err, &tl) {
		if l.shared {
			s.fail(status.MessageTooLarge, "message exceeds maxMessageSize")
			return
		}
		// Fail the call on the stream and drop the stream.
		s.resetLane(l, status.MessageTooLarge, true)
		return
	}
	if errors.Is(err, wire.ErrEmptyFrame) {
		if l.shared {
			s.fail(status.ProtocolError, "empty frame")
		} else {
			s.resetLane(l, status.ProtocolError, true)
		}
		return
	}
	var pe *transport.ProtocolError
	if errors.As(err, &pe) {
		s.fail(status.ProtocolError, pe.Msg)
		return
	}
	if l.shared {
		s.sharedEnded(err)
		return
	}
	var re *transport.ResetError
	if errors.As(err, &re) {
		s.mu.Lock()
		c := l.current
		l.readClosed, l.writeClosed, l.broken = true, true, true
		s.mu.Unlock()
		if c != nil {
			c.failLocal(&Error{Code: re.Code, Message: "stream reset", Remote: re.Remote})
		}
		// The peer reset its direction: end ours too (4.2 rule 5), never
		// with STOP_SENDING.
		resetWrite(l.st, re.Code)
		s.laneClosed(l)
		return
	}
	if errors.Is(err, transport.ErrClosed) {
		// The connection is gone: nothing to reset, and resetting could
		// discard data the peer has not read yet.
		s.mu.Lock()
		c := l.current
		l.readClosed, l.writeClosed, l.broken = true, true, true
		s.mu.Unlock()
		if c != nil {
			c.failLocal(&Error{Code: status.Unavailable, Message: "connection closed"})
		}
		s.laneClosed(l)
		return
	}
	// EOF: the peer finished its direction. A stream ends only when idle;
	// a call still running on it is broken.
	s.mu.Lock()
	c := l.current
	l.readClosed = true
	if c != nil {
		l.broken = true
	}
	needClose := !l.writeClosed
	l.writeClosed = true
	s.mu.Unlock()
	if c != nil {
		c.failLocal(&Error{Code: status.Unavailable, Message: "stream finished during the call"})
	}
	if needClose {
		if c != nil || err != io.EOF {
			resetWrite(l.st, status.Unavailable)
		} else {
			_ = l.st.CloseWrite()
		}
	}
	s.laneClosed(l)
}

// laneClosed is called once both directions are finished or reset.
func (s *Session) laneClosed(l *lane) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uncountLocked(l)
}

func (s *Session) uncountLocked(l *lane) {
	if !l.counted {
		return
	}
	l.counted = false
	if l.opened {
		s.pool.open--
		s.pool.removeIdle(l)
		s.signalPoolLocked()
	} else {
		s.inLeased--
	}
}

// laneBroken handles a write failure on a leased stream.
func (s *Session) laneBroken(l *lane, err error) {
	var re *transport.ResetError
	code := status.Unavailable
	if errors.As(err, &re) {
		code = re.Code
	}
	s.resetLane(l, code, false)
}

// resetLane resets a leased stream, fails its call and removes it from the
// pool (4.2 rule 5). A reset aborts only this side's sending direction
// (QUIC RESET_STREAM, never STOP_SENDING) where the binding allows it, and
// the session keeps reading, discarding what the peer sent, until the peer
// ends its own direction too. A stream this side opened stays counted
// until then (or until ResetWait passes), so a replacement stream never
// reaches a peer that still counts this one. On a stream the peer opened
// this side stops counting as soon as it has sent its end: QUIC does not
// order streams, so the peer's replacement may arrive before the old
// stream's end.
func (s *Session) resetLane(l *lane, code status.Code, failCall bool) {
	_, canHalf := l.st.(transport.WriteResetter)
	s.mu.Lock()
	c := l.current
	already := l.broken && l.readClosed && l.writeClosed
	wasWriteClosed := l.writeClosed
	l.broken, l.writeClosed = true, true
	l.current = nil
	half := canHalf && !already && !l.readClosed
	if half && l.opened {
		l.awaitEnd = true
	} else if !half {
		l.readClosed = true
	}
	if l.opened {
		s.pool.removeIdle(l)
	}
	s.mu.Unlock()
	switch {
	case half && !wasWriteClosed:
		resetWrite(l.st, code)
	case !half && !already:
		l.st.Reset(code)
	}
	if c != nil && failCall {
		c.failLocal(&Error{Code: code, Message: "stream reset"})
	}
	if half && l.opened {
		wait := dur(s.cfg.ResetWait, DefaultResetWait)
		s.clock.AfterFunc(wait, func() {
			// The peer did not end its direction in time: stop counting
			// the stream (the reader keeps discarding until it ends).
			s.laneClosed(l)
		})
		return
	}
	if l.opened && !canHalf {
		hold := dur(s.cfg.ResetWait, DefaultResetWait)
		s.clock.AfterFunc(hold, func() { s.laneClosed(l) })
		return
	}
	s.laneClosed(l)
}

// resetWrite aborts the sending direction of a stream only, where the
// binding allows it (4.2 rule 5).
func resetWrite(st transport.Stream, code status.Code) {
	if wr, ok := st.(transport.WriteResetter); ok {
		wr.ResetWrite(code)
		return
	}
	st.Reset(code)
}

// pool is this side's leased streams (4.2): it only leases streams it
// opened.
type pool struct {
	open int     // counted until both directions are finished or reset
	idle []*lane // most recently released last
	sig  chan struct{}
}

func (p *pool) removeIdle(l *lane) {
	if !l.inPool {
		return
	}
	for i, x := range p.idle {
		if x == l {
			p.idle = append(p.idle[:i], p.idle[i+1:]...)
			break
		}
	}
	l.inPool = false
}

func (s *Session) signalPoolLocked() {
	if s.pool.sig != nil {
		close(s.pool.sig)
		s.pool.sig = nil
	}
}

// leasesAllowed reports whether this side may use leased streams now: the
// binding has them, a client has Welcome, a server has Ready.
func (s *Session) leasesAllowedLocked() bool {
	if !s.conn.Leases() {
		return false
	}
	if s.role == wire.Client {
		return s.welcomeDone
	}
	return s.readyDone
}

// acquireLane returns an idle or new leased stream, or nil to use the
// shared lane. With WaitForLease it waits for one while the pool is full.
func (s *Session) acquireLane(ctx context.Context) (*lane, error) {
	for {
		s.mu.Lock()
		if !s.leasesAllowedLocked() || s.closed {
			s.mu.Unlock()
			return nil, nil
		}
		if n := len(s.pool.idle); n > 0 {
			l := s.pool.idle[n-1]
			s.pool.idle = s.pool.idle[:n-1]
			l.inPool = false
			s.mu.Unlock()
			return l, nil
		}
		if uint64(s.pool.open) < s.peerLimits.MaxStreams {
			s.pool.open++
			s.mu.Unlock()
			st, err := s.conn.OpenStream(ctx)
			if err != nil {
				s.mu.Lock()
				s.pool.open--
				s.signalPoolLocked()
				s.mu.Unlock()
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return nil, nil // fall back to the shared lane
			}
			l := &lane{s: s, st: st, opened: true, counted: true}
			go l.readLoop()
			return l, nil
		}
		if !s.cfg.WaitForLease {
			s.mu.Unlock()
			return nil, nil
		}
		if s.pool.sig == nil {
			s.pool.sig = make(chan struct{})
		}
		ch := s.pool.sig
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.done:
			return nil, s.closedError()
		}
	}
}

// releaseLaneLocked returns a leased stream to the pool (or marks a peer
// stream idle) after its call ended.
func (s *Session) releaseLaneLocked(l *lane) {
	if l == nil || l.shared {
		return
	}
	l.current = nil
	if !l.opened || l.broken || l.writeClosed || s.closed {
		return
	}
	l.idleSince = s.clock.Now()
	l.inPool = true
	s.pool.idle = append(s.pool.idle, l)
	s.signalPoolLocked()
	s.armShrinkLocked()
}

func (s *Session) armShrinkLocked() {
	if s.shrinkArmed || s.closed {
		return
	}
	s.shrinkArmed = true
	idle := dur(s.cfg.LeaseIdle, DefaultLeaseIdle)
	s.clock.AfterFunc(idle/2, s.shrink)
}

// shrink closes streams idle for LeaseIdle, keeping KeepIdle (4.2 rule 4).
func (s *Session) shrink() {
	idle := dur(s.cfg.LeaseIdle, DefaultLeaseIdle)
	keep := s.cfg.keepIdle()
	now := s.clock.Now()
	var closing []*lane
	s.mu.Lock()
	s.shrinkArmed = false
	if s.closed {
		s.mu.Unlock()
		return
	}
	// idle is ordered by release time; the oldest are first.
	for len(s.pool.idle) > keep {
		l := s.pool.idle[0]
		if now.Sub(l.idleSince) < idle {
			break
		}
		s.pool.idle = s.pool.idle[1:]
		l.inPool = false
		l.writeClosed = true
		closing = append(closing, l)
	}
	if len(s.pool.idle) > keep {
		s.armShrinkLocked()
	}
	s.mu.Unlock()
	for _, l := range closing {
		_ = l.st.CloseWrite()
	}
}

// acceptLoop takes leased streams the peer opens and enforces maxStreams
// (4.2 rule 2).
func (s *Session) acceptLoop() {
	for {
		st, err := s.conn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		s.mu.Lock()
		// The client may open leased streams once it has Welcome, which can
		// be before this side's write of it returns: only a stream that
		// arrives before Welcome went out is a violation.
		if s.role == wire.Server && !s.welcomeSending {
			s.mu.Unlock()
			st.Reset(status.ProtocolError)
			s.fail(status.ProtocolError, "leased stream opened before Welcome")
			return
		}
		if uint64(s.inLeased) >= s.localLimits.MaxStreams {
			s.mu.Unlock()
			// Only the sending direction (4.2 rule 5); what the peer sent
			// is read and discarded until it ends its direction.
			resetWrite(st, status.ResourceExhausted)
			go drainStream(st)
			s.logf("reset an extra leased stream (maxStreams %d)", s.localLimits.MaxStreams)
			continue
		}
		s.inLeased++
		l := &lane{s: s, st: st, counted: true}
		s.mu.Unlock()
		go l.readLoop()
	}
}

// drainStream reads and discards a stream until the peer ends it.
func drainStream(st transport.Stream) {
	for {
		if _, err := st.ReadMessage(); err != nil {
			return
		}
	}
}
