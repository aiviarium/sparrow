package session

import (
	"context"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/transport/mem"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// rawPeer speaks the protocol by hand on one end of a mem connection.
type rawPeer struct {
	t    testing.TB
	conn *mem.Conn
	lane transport.Stream
	in   chan wire.Message
	errs chan error
}

func newRawPeer(t testing.TB, conn *mem.Conn, lane transport.Stream) *rawPeer {
	p := &rawPeer{t: t, conn: conn, lane: lane, in: make(chan wire.Message, 10000), errs: make(chan error, 1)}
	go p.read(lane, p.in)
	return p
}

func (p *rawPeer) read(st transport.Stream, ch chan wire.Message) {
	for {
		b, err := st.ReadMessage()
		if err != nil {
			select {
			case p.errs <- err:
			default:
			}
			close(ch)
			return
		}
		m, err := wire.Decode(b)
		if err != nil {
			p.t.Errorf("raw peer got a malformed message: %v", err)
			continue
		}
		ch <- m
	}
}

func (p *rawPeer) send(m wire.Message) { p.sendOn(p.lane, m) }

func (p *rawPeer) sendOn(st transport.Stream, m wire.Message) {
	if err := st.WriteMessage(m.AppendTo(nil)); err != nil {
		p.t.Fatalf("raw send: %v", err)
	}
}

// recv returns the next message, skipping Credit and Ping/Pong.
func (p *rawPeer) recv() wire.Message { return recvFrom(p.t, p.in) }

func recvFrom(t testing.TB, ch chan wire.Message) wire.Message {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				return nil
			}
			switch m.(type) {
			case *wire.Credit, *wire.Ping, *wire.Pong:
				continue
			}
			return m
		case <-timeout:
			t.Fatal("raw peer: no message")
			return nil
		}
	}
}

// expectClosed waits until the lane ends.
func (p *rawPeer) expectGoAway() *wire.GoAway {
	p.t.Helper()
	for {
		m := p.recv()
		if m == nil {
			p.t.Fatal("lane closed without GoAway")
		}
		if g, ok := m.(*wire.GoAway); ok {
			return g
		}
	}
}

// rawClient starts a server session on a mem pair and returns a raw client
// and a channel with the server's NewServer result.
func rawClient(t testing.TB, scfg Config, o mem.Options) (*rawPeer, chan *Session, chan error) {
	cc, sc := mem.Pipe(o)
	sch, ech := make(chan *Session, 1), make(chan error, 1)
	go func() {
		s, err := NewServer(context.Background(), sc, scfg)
		if s != nil {
			t.Cleanup(func() { s.Close(0, "") })
		}
		sch <- s
		ech <- err
	}()
	lane, err := cc.SharedLane(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return newRawPeer(t, cc, lane), sch, ech
}

func hello(known []byte) *wire.Hello {
	return &wire.Hello{Versions: []uint64{1}, KnownSchema: known}
}

// handshake runs Hello / Welcome / Ready and returns the Welcome.
func (p *rawPeer) handshake(h *wire.Hello) *wire.Welcome {
	p.t.Helper()
	if h == nil {
		h = hello(nil)
	}
	p.send(h)
	m := p.recv()
	w, ok := m.(*wire.Welcome)
	if !ok {
		p.t.Fatalf("want Welcome, got %#v", m)
	}
	p.send(&wire.Ready{SchemaHash: w.ServerSchema.Hash})
	return w
}

func reqMsg(id, facet, method uint64, input cbor.Raw) *wire.Request {
	if input == nil {
		input = cbor.Null
	}
	return &wire.Request{CallID: id, FacetID: facet, MethodID: method, Input: input}
}

func schemaHash(t testing.TB, s *schema.Schema) []byte {
	h, err := s.Canonical().Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}
