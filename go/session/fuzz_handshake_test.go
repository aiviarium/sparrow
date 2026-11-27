package session

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/fuzzseed"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/transport/mem"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// hangWatch panics with every goroutine's stack if an iteration runs for
// more than 10 s: the fuzzer then reports the input that hung.
func hangWatch(data []byte) *time.Timer {
	return time.AfterFunc(10*time.Second, func() {
		buf := make([]byte, 1<<22)
		n := runtime.Stack(buf, true)
		panic(fmt.Sprintf("fuzz iteration hung on %q\n%s", data, buf[:n]))
	})
}

// splitFrames cuts fuzz data into messages: [length, bytes...] each.
func splitFrames(data []byte) [][]byte {
	var out [][]byte
	for len(data) >= 1 {
		n := int(data[0])
		data = data[1:]
		if n > len(data) {
			n = len(data)
		}
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}

func joinFrames(msgs ...[]byte) []byte {
	var out []byte
	for _, m := range msgs {
		if len(m) > 255 {
			panic("seed message too long")
		}
		out = append(out, byte(len(m)))
		out = append(out, m...)
	}
	return out
}

// FuzzClientHandshake plays a server that answers Hello with arbitrary
// messages and then closes the connection: the client must return (a
// session or an error) without panicking or hanging, whatever it got.
func FuzzClientHandshake(f *testing.F) {
	srv := testSchema("server")
	h, _ := srv.Canonical().Hash()
	full, _ := srv.Canonical().Encode()
	enc := func(m wire.Message) []byte { return m.AppendTo(nil) }
	var p wire.Params
	p.Set(wire.ParamMaxMessageSize, 1<<14)
	welcome := func(o wire.SchemaOffer) []byte {
		return enc(&wire.Welcome{Version: 1, SessionID: []byte{1, 2}, ServerSchema: o, Params: p})
	}
	f.Add([]byte{0}, joinFrames(welcome(wire.SchemaOffer{Kind: wire.OfferUnchanged, Hash: h})))
	f.Add([]byte{1}, joinFrames(welcome(wire.SchemaOffer{Kind: wire.OfferOutOfBand, Hash: h, Location: "x"}), enc(&wire.Ping{Nonce: 1})))
	f.Add([]byte{0}, joinFrames(enc(&wire.GoAway{Status: 16, Reason: "no"})))
	f.Add([]byte{0}, joinFrames(welcome(wire.SchemaOffer{Kind: wire.OfferUnchanged, Hash: []byte{1}})))
	f.Add([]byte{0}, joinFrames(enc(&wire.AuthStatus{Status: 0}), enc(&wire.SchemaUpdate{Epoch: 1, Hash: h, Delta: cbor.AppendArrayHead(nil, 0)})))
	// full offers do not fit a 255-byte frame; the 2-byte length form:
	f.Add([]byte{2}, append([]byte{0xff}, welcome(wire.SchemaOffer{Kind: wire.OfferFull, Hash: h, Schema: full})[:255]...))
	for _, b := range fuzzseed.Hex("handshake.json") {
		if len(b) < 256 {
			f.Add([]byte{0}, joinFrames(b))
		}
	}
	f.Fuzz(func(t *testing.T, mode []byte, data []byte) {
		watch := hangWatch(data)
		defer watch.Stop()
		var m byte
		if len(mode) > 0 {
			m = mode[0]
		}
		cfg := Config{Linger: 10 * time.Millisecond, HelloTimeout: 50 * time.Millisecond,
			FetchSchema: func(ctx context.Context, loc string, hash []byte) (*schema.Schema, error) { return srv, nil }}
		if m&1 != 0 {
			cfg.KnownSchema = srv
		}
		if m&2 != 0 {
			cfg.Schema = testSchema("client")
		}
		cc, sc := mem.Pipe(mem.Options{NoLeases: m&4 != 0})
		go func() {
			lane, err := sc.SharedLane(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					if _, err := lane.ReadMessage(); err != nil {
						return
					}
				}
			}()
			for _, msg := range splitFrames(data) {
				if lane.WriteMessage(msg) != nil {
					break
				}
			}
			_ = sc.Close(0, "")
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := NewClient(ctx, cc, cfg)
		if s != nil {
			if err != nil {
				t.Fatal("session and error")
			}
			select {
			case <-s.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("session did not end after the connection closed")
			}
		}
		if ctx.Err() != nil {
			t.Fatal("NewClient waited for its context")
		}
	})
}

// FuzzServerHandshake sends arbitrary first messages to a server and then
// closes the connection: NewServer must return without panicking or
// hanging, and a session it returns must end.
func FuzzServerHandshake(f *testing.F) {
	enc := func(m wire.Message) []byte { return m.AppendTo(nil) }
	cs, _ := testSchema("client").Canonical().Encode()
	ch, _ := testSchema("client").Canonical().Hash()
	sh, _ := testSchema("s").Canonical().Hash()
	var p wire.Params
	p.Set(wire.ParamMaxMessageSize, 1<<14)
	f.Add(joinFrames(enc(hello(nil)), enc(&wire.Ready{SchemaHash: sh})))
	f.Add(joinFrames(enc(&wire.Hello{Versions: []uint64{1}, KnownSchema: sh, Optimistic: true, Params: p}), enc(&wire.Ready{SchemaHash: sh}),
		enc(reqMsg(2, tFacet, mEcho, cbor.AppendText(nil, "x")))))
	f.Add(joinFrames(enc(&wire.Hello{Versions: []uint64{2, 1}, Auth: &wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, "t")}})))
	if len(cs) < 200 {
		f.Add(joinFrames(enc(&wire.Hello{Versions: []uint64{1}, ClientSchema: &wire.InlineSchema{Hash: ch, Schema: cs}})))
	}
	f.Add(joinFrames(enc(&wire.Ping{Nonce: 1})))
	for _, b := range fuzzseed.Hex("handshake.json") {
		if len(b) < 256 {
			f.Add(joinFrames(b))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		watch := hangWatch(data)
		defer watch.Stop()
		h := newTestHandlers()
		close(h.block)
		cfg := Config{Schema: testSchema("s"), Handler: fuzzHandler(h), Linger: 10 * time.Millisecond, HelloTimeout: time.Second}
		cc, sc := mem.Pipe(mem.Options{})
		done := make(chan *Session, 1)
		go func() {
			s, _ := NewServer(context.Background(), sc, cfg)
			done <- s
		}()
		lane, err := cc.SharedLane(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				if _, err := lane.ReadMessage(); err != nil {
					return
				}
			}
		}()
		for _, msg := range splitFrames(data) {
			if lane.WriteMessage(msg) != nil {
				break
			}
		}
		_ = cc.Close(0, "")
		select {
		case s := <-done:
			if s != nil {
				select {
				case <-s.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("session did not end after the connection closed")
				}
			}
		case <-time.After(5 * time.Second):
			t.Fatal("NewServer did not return after the connection closed")
		}
	})
}
