package session

import (
	"context"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/transport/mem"
	"github.com/aiviarium/sparrow/go/wire"
)

func TestUnaryAllBindings(t *testing.T) {
	t.Parallel()
	for _, b := range allBindings() {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHandlers()
			cli, _ := stdPair(t, b, h, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			out, err := cli.Unary(ctx, tFacet, mEcho, "hello", nil)
			if err != nil {
				t.Fatal(err)
			}
			if out != "hello" {
				t.Fatalf("got %v", out)
			}
		})
	}
}

// TestIntegerBeyondBound: an integer a message defines itself beyond
// 2^53 - 1 (a call ID, a nonce, a credit amount, the deadline key) makes the
// message malformed, and the session closes with GoAway(protocol_error)
// (3.1).
func TestIntegerBeyondBound(t *testing.T) {
	t.Parallel()
	const big = cbor.MaxSafeInt + 1
	var deadline wire.Metadata
	deadline.SetUint(wire.KeyDeadline, big)
	for name, m := range map[string]wire.Message{
		"call ID":      reqMsg(big, tFacet, mEcho, cbor.AppendText(nil, "x")),
		"ping nonce":   &wire.Ping{Nonce: big},
		"credit":       &wire.Credit{CallID: 2, Amount: big},
		"deadline key": &wire.Request{CallID: 2, FacetID: tFacet, MethodID: mEcho, Metadata: deadline, Input: cbor.AppendText(nil, "x")},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newTestHandlers()
			p, _, _ := rawClient(t, Config{Schema: testSchema("s"), Handler: h.mux(tFacet)}, mem.Options{NoLeases: true})
			p.handshake(nil)
			p.send(m)
			if g := p.expectGoAway(); status.Code(g.Status) != status.ProtocolError {
				t.Fatalf("got %+v", g)
			}
		})
	}
}
