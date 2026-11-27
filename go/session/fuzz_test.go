package session

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/transport/mem"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// fuzzFrames encodes messages for FuzzServerMessages: each frame is
// [lane, length, bytes...]; lane 0 is the shared lane, 1-3 leased streams.
func fuzzFrames(frames ...[]byte) []byte {
	var out []byte
	for i, f := range frames {
		out = append(out, byte(i%2), byte(len(f)))
		out = append(out, f...)
	}
	return out
}

// FuzzServerMessages feeds random and malformed frames to an established
// server session: it must not panic or hang, and either stay responsive
// (answer a Ping) or close the session.
func FuzzServerMessages(f *testing.F) {
	enc := func(m wire.Message) []byte { return m.AppendTo(nil) }
	f.Add(fuzzFrames(enc(reqMsg(2, tFacet, mEcho, cbor.AppendText(nil, "x")))))
	f.Add(fuzzFrames(enc(reqMsg(2, tFacet, mSum, nil)), enc(&wire.Item{CallID: 2, Value: cbor.AppendUint(nil, 5)}), enc(&wire.End{CallID: 2})))
	f.Add(fuzzFrames(enc(reqMsg(4, tFacet, mUpload, nil)), enc(&wire.Bytes{CallID: 4, Data: []byte("abc"), Fin: true}), enc(&wire.Cancel{CallID: 4, Status: 1})))
	f.Add(fuzzFrames(enc(reqMsg(6, tFacet, mCount, cbor.AppendUint(nil, 3))), enc(&wire.Credit{CallID: 6, Amount: 100})))
	f.Add(fuzzFrames(enc(&wire.SchemaAck{Epoch: 0}), enc(&wire.Ping{Nonce: 9}), enc(&wire.GoAway{Status: 21})))
	f.Add(fuzzFrames([]byte{0x83, 0x10, 0x02}, []byte{0x9f}, []byte{0x81, 0x18, 0x40}))
	f.Add([]byte{0, 3, 0x83, 0x12, 0x02, 0x01, 2, 0xff})
	f.Fuzz(fuzzOne)
}

func fuzzOne(t *testing.T, data []byte) {
	watch := time.AfterFunc(10*time.Second, func() {
		buf := make([]byte, 1<<22)
		n := runtime.Stack(buf, true)
		panic(fmt.Sprintf("fuzz iteration hung on %q\n%s", data, buf[:n]))
	})
	defer watch.Stop()
	{
		h := newTestHandlers()
		close(h.block)
		scfg := Config{Schema: testSchema("s"), Handler: fuzzHandler(h), Linger: 10 * time.Millisecond}
		cc, sc := mem.Pipe(mem.Options{})
		done := make(chan *Session, 1)
		go func() {
			s, _ := NewServer(context.Background(), sc, scfg)
			done <- s
		}()
		lane, _ := cc.SharedLane(context.Background())
		in := make(chan wire.Message, 1024)
		go func() {
			defer close(in)
			for {
				b, err := lane.ReadMessage()
				if err != nil {
					return
				}
				if m, err := wire.Decode(b); err == nil {
					select {
					case in <- m:
					default:
					}
				}
			}
		}()
		_ = lane.WriteMessage(hello(nil).AppendTo(nil))
		var w *wire.Welcome
		for w == nil {
			m, ok := <-in
			if !ok {
				t.Fatal("no Welcome")
			}
			w, _ = m.(*wire.Welcome)
		}
		_ = lane.WriteMessage((&wire.Ready{SchemaHash: w.ServerSchema.Hash}).AppendTo(nil))
		srv := <-done
		if srv == nil {
			t.Fatal("no session")
		}
		defer srv.Close(0, "")
		streams := map[byte]transport.Stream{0: lane}
		for len(data) >= 2 {
			ln, n := data[0]%4, int(data[1])
			data = data[2:]
			if n > len(data) {
				n = len(data)
			}
			msg := data[:n]
			data = data[n:]
			st, ok := streams[ln]
			if !ok {
				var err error
				if st, err = cc.OpenStream(context.Background()); err != nil {
					break
				}
				streams[ln] = st
				go func() {
					for {
						if _, err := st.ReadMessage(); err != nil {
							return
						}
					}
				}()
			}
			if err := st.WriteMessage(msg); err != nil {
				break
			}
		}
		_ = lane.WriteMessage((&wire.Ping{Nonce: 77}).AppendTo(nil))
		deadline := time.After(3 * time.Second)
		for {
			select {
			case m, ok := <-in:
				if !ok {
					return // closed
				}
				if pong, isPong := m.(*wire.Pong); isPong && pong.Nonce == 77 {
					return
				}
			case <-srv.Done():
				return
			case <-deadline:
				t.Fatal("server neither answered Ping nor closed")
			}
		}
	}
}

// fuzzHandler serves the test facet but refuses inputs that would make a
// handler itself produce unbounded output (count, download, big), which
// would only measure the test handlers.
func fuzzHandler(h *testHandlers) Handler {
	m := h.mux(tFacet)
	return rawHandler(func(ctx context.Context, c *ServerCall) {
		switch c.MethodID() {
		case mCount, mDownload, mWatch:
			if v, err := c.Input(); err != nil || v.(uint64) > 1000 {
				_ = c.Fail(Errorf(3, "too large"))
				return
			}
		case mBig, mSlow:
			_ = c.Fail(Errorf(3, "not in the fuzz harness"))
			return
		}
		m.ServeCall(ctx, c)
	})
}
