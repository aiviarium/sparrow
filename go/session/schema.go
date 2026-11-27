package session

import (
	"time"
	"bytes"
	"context"
	"errors"

	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/value"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// setLocal installs this side's schema state and records the flags of every
// method in it. Flags 0x2, 0x8 and 0x10 never change for a method, so the
// session can still end calls to a method that was removed (6.6 rule 2).
func (s *Session) setLocal(st *schema.State) {
	sc := st.Schema()
	s.mu.Lock()
	s.local = st
	s.localSc = sc
	for i := range sc.Facets {
		f := &sc.Facets[i]
		for j := range f.Services {
			for k := range f.Services[j].Methods {
				m := &f.Services[j].Methods[k]
				s.methodFlags[[2]uint64{f.ID, m.ID}] = m.Flags
			}
		}
	}
	s.mu.Unlock()
}

// LocalSchema returns this side's current schema state (nil for a client
// that published none).
func (s *Session) LocalSchema() *schema.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.local
}

// PeerSchema returns the peer's current schema state (nil if the peer
// published none, or before Welcome on a client).
func (s *Session) PeerSchema() *schema.State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peer
}

func codecFor(mu interface{ Lock(); Unlock() }, cache map[*schema.Facet]*value.Codec, f *schema.Facet) (*value.Codec, error) {
	mu.Lock()
	defer mu.Unlock()
	if c, ok := cache[f]; ok {
		return c, nil
	}
	c, err := value.New(f)
	if err != nil {
		return nil, err
	}
	cache[f] = c
	return c, nil
}

// setPeerLocked installs the peer's schema state.
func (s *Session) setPeerLocked(st *schema.State) {
	s.peer = st
	s.peerSc = nil
	if st != nil {
		s.peerSc = st.Schema()
	}
}

// lookupMethod finds a method in a (cached, canonical) schema.
func lookupMethod(sc *schema.Schema, facetID, methodID uint64) (*schema.Facet, *schema.Method) {
	if sc == nil {
		return nil, nil
	}
	f := sc.Facet(facetID)
	if f == nil {
		return nil, nil
	}
	m, _ := f.Method(methodID)
	if m == nil {
		return f, nil
	}
	return f, m
}

// SchemaUpdateOptions tune UpdateSchema.
type SchemaUpdateOptions struct {
	// AckTimeout replaces SchemaAckTimeout for this update. A hub relaying
	// a node's update gives each downstream session half of its own
	// remaining time (10.3).
	AckTimeout time.Duration
}

// PendingUpdate is a SchemaUpdate this side sent.
type PendingUpdate struct {
	Epoch uint64
	Hash  []byte
	Delta schema.Delta
	s     *Session
}

// Wait blocks until the peer acknowledged the update's epoch.
func (u *PendingUpdate) Wait(ctx context.Context) error {
	return u.s.waitEpoch(ctx, u.Epoch)
}

// UpdateSchema publishes a new version of this side's schema (6.6): it
// computes the delta, checks it as the peer will (compatibility, re-added
// facets, validity), sends SchemaUpdate at the next epoch, and holds back
// every later message of a call to a facet the delta adds or replaces
// until the peer acknowledges it (rule 1). Without an ack within the
// timeout the session closes with GoAway(schema_mismatch).
func (s *Session) UpdateSchema(nw *schema.Schema, o SchemaUpdateOptions) (*PendingUpdate, error) {
	s.updMu.Lock()
	defer s.updMu.Unlock()
	s.mu.Lock()
	cur := s.local
	ready := s.welcomeDone || s.role == wire.Client
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, s.closedError()
	}
	if cur == nil {
		return nil, errors.New("session: this side published no schema in the handshake")
	}
	if !ready {
		return nil, errors.New("session: the handshake is not complete")
	}
	d, err := schema.Diff(cur.Schema(), nw)
	if err != nil {
		return nil, err
	}
	next, err := cur.Apply(d)
	if err != nil {
		return nil, err
	}
	hash, err := next.Hash()
	if err != nil {
		return nil, err
	}
	raw, err := d.Encode()
	if err != nil {
		return nil, err
	}
	epoch := next.Epoch()
	s.setLocal(next)
	s.mu.Lock()
	for _, op := range d {
		if op.Op == schema.OpPut {
			s.pendingFacets[op.Facet.ID] = epoch
		}
	}
	s.mu.Unlock()
	if err := s.shared.write((&wire.SchemaUpdate{Epoch: epoch, Hash: hash, Delta: raw}).AppendTo(nil)); err != nil {
		return nil, err
	}
	timeout := o.AckTimeout
	if timeout <= 0 {
		timeout = dur(s.cfg.SchemaAckTimeout, DefaultSchemaAckTimeout)
	}
	s.clock.AfterFunc(timeout, func() {
		s.mu.Lock()
		late := s.localAcked < epoch && !s.closed
		s.mu.Unlock()
		if late {
			s.fail(status.SchemaMismatch, "SchemaAck did not arrive in time")
		}
	})
	return &PendingUpdate{Epoch: epoch, Hash: hash, Delta: d, s: s}, nil
}

// needsAck reports whether messages of calls to the facet must wait for a
// SchemaAck.
func (s *Session) needsAck(facet uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.pendingFacets[facet]
	return ok && e > s.localAcked
}

func (s *Session) waitAck(ctx context.Context, facet uint64) error {
	s.mu.Lock()
	e := s.pendingFacets[facet]
	s.mu.Unlock()
	return s.waitEpoch(ctx, e)
}

func (s *Session) waitEpoch(ctx context.Context, epoch uint64) error {
	for {
		s.mu.Lock()
		if s.localAcked >= epoch {
			s.mu.Unlock()
			return nil
		}
		if s.closed {
			s.mu.Unlock()
			return s.closedError()
		}
		if s.ackSig == nil {
			s.ackSig = make(chan struct{})
		}
		ch := s.ackSig
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *Session) onSchemaAck(a *wire.SchemaAck) {
	s.mu.Lock()
	if s.local == nil || a.Epoch > s.local.Epoch() {
		s.mu.Unlock()
		s.fail(status.ProtocolError, "SchemaAck for an epoch never sent")
		return
	}
	if a.Epoch > s.localAcked {
		s.localAcked = a.Epoch
		for f, e := range s.pendingFacets {
			if e <= a.Epoch {
				delete(s.pendingFacets, f)
			}
		}
	}
	if s.ackSig != nil {
		close(s.ackSig)
		s.ackSig = nil
	}
	s.mu.Unlock()
}

// onSchemaUpdate applies the peer's update (6.6 rule 3) and acks it, after
// Config.OnPeerSchemaUpdate if set.
func (s *Session) onSchemaUpdate(u *wire.SchemaUpdate) {
	s.mu.Lock()
	cur := s.peer
	s.mu.Unlock()
	if cur == nil {
		s.fail(status.SchemaMismatch, "SchemaUpdate from a peer that published no schema")
		return
	}
	d, err := schema.DecodeDelta(u.Delta)
	if err != nil {
		s.fail(status.SchemaMismatch, "malformed delta: "+err.Error())
		return
	}
	next, err := cur.ApplyUpdate(u.Epoch, u.Hash, d)
	if err != nil {
		s.fail(status.SchemaMismatch, err.Error())
		return
	}
	s.mu.Lock()
	s.setPeerLocked(next)
	s.mu.Unlock()
	ack := func() {
		if h := s.cfg.OnPeerSchemaUpdate; h != nil {
			if err := h(s.ctx, s, &PeerSchemaUpdate{Epoch: u.Epoch, Hash: u.Hash, Delta: d, RawDelta: u.Delta, Old: cur, New: next}); err != nil {
				code := status.SchemaMismatch
				var e *Error
				if errors.As(err, &e) {
					code = e.Code
				}
				s.fail(code, err.Error())
				return
			}
		}
		_ = s.shared.write((&wire.SchemaAck{Epoch: u.Epoch}).AppendTo(nil))
	}
	if s.cfg.OnPeerSchemaUpdate == nil {
		ack()
		return
	}
	select {
	case s.ackQ <- ack:
	case <-s.done:
	}
}

// PeerFacet returns the peer's facet with the given name.
func (s *Session) PeerFacet(name string) *schema.Facet {
	s.mu.Lock()
	sc := s.peerSc
	s.mu.Unlock()
	if sc == nil {
		return nil
	}
	for i := range sc.Facets {
		if sc.Facets[i].Name == name {
			return &sc.Facets[i]
		}
	}
	return nil
}

func hashEqual(a, b []byte) bool { return bytes.Equal(a, b) }
