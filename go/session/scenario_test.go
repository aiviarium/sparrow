package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/value"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// The behaviour scenarios of test-vectors/scenarios, executed against a
// real server session: a scripted raw client sends the client's messages
// and checks every message and expectation of the server side.

func vectorsDir() string {
	if d := os.Getenv("SPARROW_VECTORS"); d != "" {
		return d
	}
	return filepath.Join("..", "..", "test-vectors")
}

type scenario struct {
	Name  string `json:"name"`
	Given struct {
		Schema       string                     `json:"schema"`
		Session      string                     `json:"session"`
		ServerParams map[string]uint64          `json:"server_params"`
		ClientParams map[string]uint64          `json:"client_params"`
		Delta        string                     `json:"delta"`
		ClientCache  json.RawMessage            `json:"client_cache"`
		Extra        map[string]json.RawMessage `json:"-"`
	} `json:"given"`
	Steps []scenarioStep `json:"steps"`
}

type scenarioStep struct {
	Step      int    `json:"step"`
	From      string `json:"from"`
	Stream    string `json:"stream"`
	Kind      string `json:"kind_name"`
	CBOR      string `json:"cbor"`
	Compare   string `json:"compare"`
	Crossed   bool   `json:"crossed"`
	Expect    string `json:"expect"`
	By        string `json:"by"`
	CallID    uint64 `json:"call_id"`
	Half      string `json:"half"`
	Reason    string `json:"reason"`
	Count     int    `json:"count"`
	Note      string `json:"note"`
	raw       []byte
	sentEarly bool
}

func loadSchemaVector(t *testing.T, name string) *schema.Schema {
	b, err := os.ReadFile(filepath.Join(vectorsDir(), "schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Name      string `json:"name"`
			Canonical string `json:"canonical_cbor"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Vectors {
		if v.Name == name {
			raw, _ := hex.DecodeString(v.Canonical)
			s, err := schema.DecodeSchema(raw)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
	}
	t.Fatalf("no schema vector %q", name)
	return nil
}

// scenarioHost implements the scenario server's methods (see the README of
// test-vectors/scenarios).
type scenarioHost struct {
	mu         sync.Mutex
	dispatched map[uint64]bool
	logs       []string
	events     chan cbor.Raw // nil value ends the subscription
}

func (h *scenarioHost) mux() *Mux {
	m := NewMux()
	rec := func(f HandlerFunc) HandlerFunc {
		return func(ctx context.Context, c *ServerCall) (any, error) {
			h.mu.Lock()
			h.dispatched[c.ID()] = true
			h.mu.Unlock()
			return f(ctx, c)
		}
	}
	m.HandleFunc(16, 0, rec(func(ctx context.Context, c *ServerCall) (any, error) { return c.Input() }))
	m.HandleFunc(16, 1, rec(func(ctx context.Context, c *ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		for i := uint64(1); i <= in.(uint64); i++ {
			if err := c.Send(ctx, i); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}))
	m.HandleFunc(16, 2, rec(func(ctx context.Context, c *ServerCall) (any, error) {
		var sum uint64
		for {
			v, err := c.Recv(ctx)
			if err == io.EOF {
				return sum, nil
			}
			if err != nil {
				return nil, err
			}
			if v.(uint64) > 1000 {
				return nil, Errorf(status.OutOfRange, "item %d exceeds 1000", v)
			}
			sum += v.(uint64)
		}
	}))
	m.HandleFunc(16, 3, rec(func(ctx context.Context, c *ServerCall) (any, error) {
		in, err := c.Input()
		if err != nil {
			return nil, err
		}
		tok := uint64(in.(value.Struct)[1].(value.Token))
		// The scenarios count credit without grants in between, so the
		// data is read only once the caller's half is finished.
		if err := c.waitCallerHalf(ctx); err != nil {
			return nil, err
		}
		n, err := io.Copy(io.Discard, c.Reader(tok))
		if err != nil {
			return nil, err
		}
		return uint64(n), nil
	}))
	m.HandleFunc(16, 4, rec(func(ctx context.Context, c *ServerCall) (any, error) {
		v, _ := c.Input()
		h.mu.Lock()
		h.logs = append(h.logs, fmt.Sprint(v))
		h.mu.Unlock()
		return nil, nil
	}))
	m.HandleFunc(16, 5, rec(func(ctx context.Context, c *ServerCall) (any, error) {
		for {
			select {
			case v := <-h.events:
				if v == nil {
					return nil, nil
				}
				if err := c.sendItem(ctx, v); err != nil {
					return nil, err
				}
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
		}
	}))
	m.HandleFunc(16, 6, rec(func(ctx context.Context, c *ServerCall) (any, error) {
		v, err := c.Input()
		if err != nil {
			return nil, err
		}
		return value.Struct{0: v}, nil
	}))
	return m
}

// waitCallerHalf waits until the caller's half is finished (test helper).
func (sc *ServerCall) waitCallerHalf(ctx context.Context) error {
	c := sc.c
	for {
		c.mu.Lock()
		done := c.h.callerDone || c.ended
		ch := c.waitCh()
		c.mu.Unlock()
		if done {
			return nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
}

// sendItem sends an encoded Item on a server call (test helper).
func (sc *ServerCall) sendItem(ctx context.Context, v cbor.Raw) error { return sc.c.sendItem(ctx, v) }

type scenarioRun struct {
	t       *testing.T
	b       binding
	sc      *scenario
	host    *scenarioHost
	conn    transport.Conn
	srv     *Session
	srvErr  error
	srvDone chan struct{}
	streams map[string]transport.Stream
	ins     map[string]chan wire.Message
	raws    map[string]chan []byte
	opened  int
	calls   map[uint64]uint64 // call ID -> method ID
	update  *schema.Schema
}

func TestScenarios(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(vectorsDir(), "scenarios", "*.json"))
	if len(files) == 0 {
		t.Skip("no scenarios")
	}
	sort.Strings(files)
	for _, b := range allBindings() {
		t.Run(b.name, func(t *testing.T) {
			for _, f := range files {
				raw, err := os.ReadFile(f)
				if err != nil {
					t.Fatal(err)
				}
				var sc scenario
				if err := json.Unmarshal(raw, &sc); err != nil {
					t.Fatal(err)
				}
				t.Run(sc.Name, func(t *testing.T) { runScenario(t, b, &sc) })
			}
		})
	}
}

func runScenario(t *testing.T, b binding, sc *scenario) {
	r := &scenarioRun{t: t, b: b, sc: sc, host: &scenarioHost{dispatched: map[uint64]bool{}, events: make(chan cbor.Raw, 16)},
		streams: map[string]transport.Stream{}, ins: map[string]chan wire.Message{}, raws: map[string]chan []byte{},
		calls: map[uint64]uint64{}, srvDone: make(chan struct{})}
	for i := range sc.Steps {
		if sc.Steps[i].CBOR != "" {
			sc.Steps[i].raw, _ = hex.DecodeString(sc.Steps[i].CBOR)
		}
	}
	host := loadSchemaVector(t, sc.Given.Schema)
	if sc.Given.Delta != "" {
		r.update = loadSchemaVector(t, sc.Given.Delta)
	}
	cfg := Config{Schema: host, Handler: r.host.mux()}
	for k, v := range sc.Given.ServerParams {
		cfg.Params.Set(k, v)
	}
	cc, scn := b.connect(t)
	r.conn = cc
	go func() {
		r.srv, r.srvErr = NewServer(context.Background(), scn, cfg)
		if r.srv != nil {
			t.Cleanup(func() { r.srv.Close(0, "") })
		}
		close(r.srvDone)
	}()
	if !strings.HasPrefix(sc.Given.Session, "none") {
		r.handshake(host)
	}
	for i := range sc.Steps {
		st := &sc.Steps[i]
		switch {
		case st.From == "client":
			if st.sentEarly {
				continue
			}
			r.clientSend(st)
		case st.From == "server":
			// Messages that crossed this one are already in flight.
			for j := i + 1; j < len(sc.Steps); j++ {
				nx := &sc.Steps[j]
				if nx.Expect != "" {
					continue
				}
				if nx.From != "client" || !nx.Crossed {
					break
				}
				r.trigger(st)
				r.clientSend(nx)
				nx.sentEarly = true
			}
			r.trigger(st)
			r.serverRecv(st)
		case st.Expect != "":
			r.expect(i, st)
		}
	}
}

func (r *scenarioRun) lane(name string) string {
	if !r.b.leases {
		return "shared"
	}
	return name
}

func (r *scenarioRun) stream(name string) transport.Stream {
	name = r.lane(name)
	if s, ok := r.streams[name]; ok {
		return s
	}
	var s transport.Stream
	var err error
	if name == "shared" {
		s, err = r.conn.SharedLane(context.Background())
	} else {
		s, err = r.conn.OpenStream(context.Background())
		r.opened++
	}
	if err != nil {
		r.t.Fatal(err)
	}
	r.streams[name] = s
	ch := make(chan wire.Message, 1000)
	rch := make(chan []byte, 1000)
	r.ins[name], r.raws[name] = ch, rch
	go func() {
		for {
			b, err := s.ReadMessage()
			if err != nil {
				close(rch)
				return
			}
			rch <- b
		}
	}()
	return s
}

func (r *scenarioRun) handshake(host *schema.Schema) {
	r.send("shared", (&wire.Hello{Versions: []uint64{1}}).AppendTo(nil))
	m := r.recv("shared", wire.KindWelcome)
	w := m.(*wire.Welcome)
	if !bytes.Equal(w.ServerSchema.Hash, schemaHash(r.t, host)) {
		r.t.Fatal("Welcome hash")
	}
	r.send("shared", (&wire.Ready{SchemaHash: w.ServerSchema.Hash}).AppendTo(nil))
	<-r.srvDone
	if r.srvErr != nil {
		r.t.Fatal(r.srvErr)
	}
}

func (r *scenarioRun) send(lane string, b []byte) {
	s := r.stream(lane)
	if err := s.WriteMessage(b); err != nil {
		r.t.Fatalf("send: %v", err)
	}
}

func (r *scenarioRun) clientSend(st *scenarioStep) {
	if k, id, _ := wire.PeekCall(st.raw); k == wire.KindRequest {
		m, _ := wire.Decode(st.raw)
		r.calls[id] = m.(*wire.Request).MethodID
	}
	r.send(st.Stream, st.raw)
}

// recvRaw returns the next message on a lane other than Ping/Pong and
// (unless want is Credit) Credit.
func (r *scenarioRun) recvRaw(lane string, want wire.Kind) []byte {
	r.stream(lane)
	ch := r.raws[r.lane(lane)]
	timeout := time.After(5 * time.Second)
	for {
		select {
		case b, ok := <-ch:
			if !ok {
				r.t.Fatalf("%s: lane closed, want %v", lane, want)
			}
			k, _, _ := wire.PeekCall(b)
			if k == wire.KindPing || k == wire.KindPong || (k == wire.KindCredit && want != wire.KindCredit) {
				continue
			}
			return b
		case <-timeout:
			r.t.Fatalf("%s: no %v from the server", lane, want)
			return nil
		}
	}
}

func (r *scenarioRun) recv(lane string, want wire.Kind) wire.Message {
	b := r.recvRaw(lane, want)
	m, err := wire.Decode(b)
	if err != nil {
		r.t.Fatal(err)
	}
	if m.Kind() != want {
		r.t.Fatalf("got %v %x, want %v", m.Kind(), b, want)
	}
	return m
}

// trigger makes the server send a message it would send on its own.
func (r *scenarioRun) trigger(st *scenarioStep) {
	if st.sentEarly {
		return
	}
	st.sentEarly = true // reused as "triggered" for server steps
	m, err := wire.Decode(st.raw)
	if err != nil {
		r.t.Fatal(err)
	}
	switch x := m.(type) {
	case *wire.Welcome:
		<-time.After(0)
	case *wire.SchemaUpdate:
		if _, err := r.srv.UpdateSchema(r.update, SchemaUpdateOptions{}); err != nil {
			r.t.Fatal(err)
		}
	case *wire.GoAway:
		if status.Code(x.Status) == status.GoingAway {
			r.srv.GoAway(status.GoingAway, x.Reason, x.RetryAfterMs)
		}
	case *wire.Item:
		if r.calls[x.CallID] == 5 {
			r.host.events <- x.Value
		}
	case *wire.End:
		if r.calls[x.CallID] == 5 {
			r.host.events <- nil
		}
	}
}

func canonical(t *testing.T, b []byte) []byte {
	c, err := cbor.Canonical(b, cbor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (r *scenarioRun) serverRecv(st *scenarioStep) {
	t := r.t
	want, _ := wire.Decode(st.raw)
	got := r.recvRaw(st.Stream, want.Kind())
	gm, err := wire.Decode(got)
	if err != nil {
		t.Fatalf("step %d: %v", st.Step, err)
	}
	if gm.Kind() != want.Kind() {
		t.Fatalf("step %d: got %v %x, want %v %s", st.Step, gm.Kind(), got, want.Kind(), st.CBOR)
	}
	switch {
	case st.Compare == "status":
		gs, ws := statusOf(gm), statusOf(want)
		if gs != ws {
			t.Fatalf("step %d: status %v, want %v", st.Step, gs, ws)
		}
		if gc, ok := gm.(wire.CallMessage); ok && gc.Call() != want.(wire.CallMessage).Call() {
			t.Fatalf("step %d: call ID", st.Step)
		}
	case want.Kind() == wire.KindWelcome:
		// session_id is random; everything else must match.
		g, w := *gm.(*wire.Welcome), *want.(*wire.Welcome)
		g.SessionID, w.SessionID = nil, nil
		if !bytes.Equal(canonical(t, g.AppendTo(nil)), canonical(t, w.AppendTo(nil))) {
			t.Fatalf("step %d: Welcome %x, want %x", st.Step, g.AppendTo(nil), w.AppendTo(nil))
		}
	default:
		if !bytes.Equal(canonical(t, got), canonical(t, st.raw)) {
			t.Fatalf("step %d: got %x, want %s", st.Step, got, st.CBOR)
		}
	}
}

func statusOf(m wire.Message) uint64 {
	switch x := m.(type) {
	case *wire.Error:
		return x.Status
	case *wire.GoAway:
		return x.Status
	case *wire.Cancel:
		return x.Status
	}
	return 0
}

// quietFor checks that nothing but Credit, Ping or Pong arrives for a while
// on the call's lane for that call.
func (r *scenarioRun) quietFor(lane string, callID uint64, d time.Duration) {
	r.stream(lane)
	ch := r.raws[r.lane(lane)]
	timer := time.After(d)
	for {
		select {
		case b, ok := <-ch:
			if !ok {
				return
			}
			k, id, _ := wire.PeekCall(b)
			if k == wire.KindPing || k == wire.KindPong || k == wire.KindCredit {
				continue
			}
			if !k.IsCall() || id == callID {
				r.t.Fatalf("unexpected %v %x", k, b)
			}
			// Another call's message: put it back.
			go func() { ch <- b }()
		case <-timer:
			return
		}
	}
}

func (r *scenarioRun) laneOf(callID uint64, upto int) string {
	for i := 0; i < upto && i < len(r.sc.Steps); i++ {
		st := r.sc.Steps[i]
		if st.raw == nil {
			continue
		}
		if k, id, _ := wire.PeekCall(st.raw); k.IsCall() && id == callID {
			return st.Stream
		}
	}
	return "shared"
}

func (r *scenarioRun) serverCall(id uint64) *call {
	r.srv.mu.Lock()
	defer r.srv.mu.Unlock()
	return r.srv.calls[id]
}

func (r *scenarioRun) expect(i int, st *scenarioStep) {
	t := r.t
	switch st.Expect {
	case "session_ready":
		<-r.srvDone
		if r.srvErr != nil {
			t.Fatal(r.srvErr)
		}
	case "dispatched", "not_dispatched":
		want := st.Expect == "dispatched"
		ok := func() bool {
			r.host.mu.Lock()
			defer r.host.mu.Unlock()
			return r.host.dispatched[st.CallID] == want
		}
		if want {
			testutil.Eventually(t, 5*time.Second, ok, "step %d: call %d not dispatched", st.Step, st.CallID)
		} else {
			time.Sleep(20 * time.Millisecond)
			if !ok() {
				t.Fatalf("step %d: call %d dispatched", st.Step, st.CallID)
			}
		}
	case "call_ended":
		<-r.srvDone
		if r.srv == nil {
			return
		}
		testutil.Eventually(t, 5*time.Second, func() bool { return r.serverCall(st.CallID) == nil }, "step %d: call %d still open", st.Step, st.CallID)
	case "half_finished":
		<-r.srvDone
		testutil.Eventually(t, 5*time.Second, func() bool {
			c := r.serverCall(st.CallID)
			if c == nil {
				return true
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if st.Half == "caller" {
				return c.h.callerDone
			}
			return c.h.calleeDone
		}, "step %d: %s half of call %d not finished", st.Step, st.Half, st.CallID)
	case "stream_idle":
		if !r.b.leases {
			return
		}
		testutil.Eventually(t, 5*time.Second, func() bool {
			r.srv.mu.Lock()
			defer r.srv.mu.Unlock()
			for _, c := range r.srv.calls {
				if !c.ln.shared {
					return false
				}
			}
			return true
		}, "step %d: a leased stream is still busy", st.Step)
	case "streams_open":
		if !r.b.leases {
			return
		}
		if st.By == "client" && r.opened != st.Count {
			t.Fatalf("step %d: client opened %d streams, want %d", st.Step, r.opened, st.Count)
		}
		testutil.Eventually(t, 5*time.Second, func() bool { return r.srv.Stats().PeerLeased == st.Count }, "step %d: server counts %d streams", st.Step, r.srv.Stats().PeerLeased)
	case "held_back":
		lane := r.laneOf(st.CallID, i)
		if st.Reason == "schema_ack" {
			// Hand the next item to the handler now: it must still wait.
			for j := i + 1; j < len(r.sc.Steps); j++ {
				nx := &r.sc.Steps[j]
				if nx.From == "server" && nx.raw != nil {
					if k, id, _ := wire.PeekCall(nx.raw); k == wire.KindItem && id == st.CallID {
						r.trigger(nx)
						break
					}
				}
			}
		}
		r.quietFor(lane, st.CallID, 100*time.Millisecond)
	case "no_reply":
		r.quietFor("shared", st.CallID, 50*time.Millisecond)
	case "discarded":
		r.quietFor(r.laneOf(st.CallID, i), st.CallID, 50*time.Millisecond)
	case "session_closed", "transport_closed":
		<-r.srvDone
		if r.srv == nil {
			if r.srvErr == nil {
				t.Fatal("no server session and no error")
			}
			return
		}
		testutil.Eventually(t, 5*time.Second, func() bool { return r.srv.Stats().Closed }, "step %d: server session still open", st.Step)
	case "violation", "client_retries":
		// Nothing to check on the server: the next steps show the answer.
	default:
		t.Fatalf("step %d: unknown expectation %q", st.Step, st.Expect)
	}
}
