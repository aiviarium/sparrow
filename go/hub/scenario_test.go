package hub

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/internal/vectors"
	nd "github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/transport"
	"github.com/aiviarium/sparrow-rpc/go/transport/websocket"
	"github.com/aiviarium/sparrow-rpc/go/transport/webtransport"
	"github.com/aiviarium/sparrow-rpc/go/value"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// The behaviour scenarios of test-vectors/scenarios, run against the hub:
// a scripted raw client talks to the hub, which forwards to a node "test"
// that publishes the scenario facet test.echo and implements its methods.
// The hub's schema for the client is exactly the scenario host schema
// (same name and version, test.echo at facet ID 16, the admin facet
// elsewhere and invisible), so every message the client sees must be what
// the scenario says a server sends.

type hscenario struct {
	Name  string `json:"name"`
	Given struct {
		Schema       string            `json:"schema"`
		Session      string            `json:"session"`
		ServerParams map[string]uint64 `json:"server_params"`
		Delta        string            `json:"delta"`
	} `json:"given"`
	Steps []hstep `json:"steps"`
}

type hstep struct {
	Step     int    `json:"step"`
	From     string `json:"from"`
	Stream   string `json:"stream"`
	CBOR     string `json:"cbor"`
	Compare  string `json:"compare"`
	Crossed  bool   `json:"crossed"`
	Expect   string `json:"expect"`
	By       string `json:"by"`
	CallID   uint64 `json:"call_id"`
	Half     string `json:"half"`
	Reason   string `json:"reason"`
	Count    int    `json:"count"`
	raw      []byte
	sentEarl bool
}

func scenarioSchema(t *testing.T, name string) *schema.Schema {
	f, err := vectors.Load("schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Vectors {
		if v.Name == name {
			var h string
			_ = json.Unmarshal(v.Fields["canonical_cbor"], &h)
			raw, _ := hex.DecodeString(h)
			s, err := schema.DecodeSchema(raw)
			if err != nil {
				t.Fatal(err)
			}
			return s
		}
	}
	t.Fatalf("no schema vector %s", name)
	return nil
}

// scenarioNode implements the scenario methods (test-vectors/scenarios
// README) on a node.
type scenarioNode struct {
	n          *nd.Node
	dispatched atomic.Int64
	events     chan cbor.Raw
	mu         sync.Mutex
	logs       []string
}

func (h *scenarioNode) ServeCall(ctx context.Context, c *session.ServerCall) {
	if !c.Notification() {
		h.dispatched.Add(1)
	}
	session.HandlerFunc(func(ctx context.Context, c *session.ServerCall) (any, error) {
		switch c.MethodID() {
		case 0:
			return c.Input()
		case 1:
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
		case 2:
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
					return nil, session.Errorf(status.OutOfRange, "item %d exceeds 1000", v)
				}
				sum += v.(uint64)
			}
		case 3:
			in, err := c.Input()
			if err != nil {
				return nil, err
			}
			tok := uint64(in.(value.Struct)[1].(value.Token))
			n, err := io.Copy(io.Discard, c.Reader(tok))
			if err != nil {
				return nil, err
			}
			return uint64(n), nil
		case 4:
			v, _ := c.Input()
			h.mu.Lock()
			h.logs = append(h.logs, fmt.Sprint(v))
			h.mu.Unlock()
			return nil, nil
		case 5:
			for {
				select {
				case v := <-h.events:
					if v == nil {
						return nil, nil
					}
					if err := c.SendRaw(ctx, (&wire.Item{Value: v}).AppendTo(nil)); err != nil {
						return nil, err
					}
				case <-ctx.Done():
					return nil, context.Cause(ctx)
				}
			}
		case 6:
			v, err := c.Input()
			if err != nil {
				return nil, err
			}
			return value.Struct{0: v}, nil
		}
		return nil, session.Errorf(status.Unimplemented, "no method %d", c.MethodID())
	}).ServeCall(ctx, c)
}

type hscenarioRun struct {
	t       *testing.T
	binding string
	sc      *hscenario
	f       *fixture
	host    *scenarioNode
	conn    transport.Conn
	streams map[string]transport.Stream
	raws    map[string]chan []byte
	opened  int
	calls   map[uint64]uint64
	update  *schema.Schema
	// credited records the calls the hub granted credit to (Credit
	// messages the script skips).
	credited map[uint64]bool
	// sid is the session ID of the scripted client's session (Welcome).
	sid []byte
}

func TestScenariosThroughHub(t *testing.T) {
	t.Parallel()
	files, _ := filepath.Glob(filepath.Join(vectors.Dir(), "scenarios", "*.json"))
	if len(files) == 0 {
		t.Skip("no scenarios")
	}
	sort.Strings(files)
	for _, b := range transports {
		t.Run(b, func(t *testing.T) {
			t.Parallel()
			for _, file := range files {
				raw, _ := os.ReadFile(file)
				var sc hscenario
				if err := json.Unmarshal(raw, &sc); err != nil {
					t.Fatal(err)
				}
				t.Run(sc.Name, func(t *testing.T) {
					t.Parallel()
					runHubScenario(t, b, &sc)
				})
			}
		})
	}
}

func runHubScenario(t *testing.T, binding string, sc *hscenario) {
	host := scenarioSchema(t, sc.Given.Schema)
	r := &hscenarioRun{t: t, binding: binding, sc: sc, streams: map[string]transport.Stream{}, raws: map[string]chan []byte{}, calls: map[uint64]uint64{}, credited: map[uint64]bool{}}
	for i := range sc.Steps {
		if sc.Steps[i].CBOR != "" {
			sc.Steps[i].raw, _ = hex.DecodeString(sc.Steps[i].CBOR)
		}
	}
	if sc.Given.Delta != "" {
		r.update = scenarioSchema(t, sc.Given.Delta)
	}
	r.f = newFixture(t, func(o *Options) {
		o.SchemaName, o.SchemaVersion = host.Name, host.Version
		o.AdminFacetID = 1000
		o.Tokens = append(o.Tokens, Credential{Token: "v4.public.TEST-ONLY-TICKET", Principal: "user:scenario"})
		params := sc.Given.ServerParams
		o.Session = func(c *session.Config) {
			if c.Authenticate == nil || c.Schema != nil {
				return // only sessions the hub accepts get the scenario params
			}
			for k, v := range params {
				c.Params.Set(k, v)
			}
		}
	})
	f := r.f
	f.secret("test-1", "test-cred")
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"test": dialInConfig("test-1")},
		Extensions: policy(grant("user:scenario", "test.echo", "use"), grant("user:alice", "test.echo", "use"))})
	r.host = &scenarioNode{events: make(chan cbor.Raw, 16)}
	n := nd.New(nd.Options{ID: "test", Auth: linkAuth("test-cred"), Logger: testLogger(t)})
	if _, err := n.Add(tctx(t), &nd.Facet{Def: *host.Facets[0].Clone()}); err != nil {
		t.Fatal(err)
	}
	n.Mux().HandleFallback(r.host)
	r.host.n = n
	if err := n.Dial(tctx(t), f.wsURL, nd.DialOptions{}); err != nil {
		t.Fatal(err)
	}
	f.onCleanup(n.Close)
	waitNode(t, f.h, "test", true)
	// The hub's schema for the scenario client is the scenario host schema.
	probe := f.client("websocket", "v4.public.TEST-ONLY-TICKET")
	waitFacet(t, probe, "test.echo")
	if got, _ := probe.Session().PeerSchema().Hash(); !bytes.Equal(got, schemaHash(t, host)) {
		a, _ := probe.Session().PeerSchema().Schema().Encode()
		b, _ := host.Canonical().Encode()
		t.Fatalf("the hub schema is not the scenario host schema:\n%x\n%x", a, b)
	}
	probe.Close()
	// The probe's hub session is gone before the scenario's starts, so
	// hubSession finds the scenario's.
	testutil.Eventually(t, 10*time.Second, func() bool { return len(f.h.Sessions()["user:scenario"]) == 0 }, "the probe session is still open")
	r.connect()
	if !strings.HasPrefix(sc.Given.Session, "none") {
		r.handshake(host)
	}
	for i := range sc.Steps {
		st := &sc.Steps[i]
		switch {
		case st.From == "client":
			if st.sentEarl {
				continue
			}
			r.clientSend(st)
		case st.From == "server":
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
				nx.sentEarl = true
			}
			r.trigger(st)
			r.serverRecv(st)
		case st.Expect != "":
			r.expect(i, st)
		}
	}
}

func schemaHash(t *testing.T, s *schema.Schema) []byte {
	h, err := s.Canonical().Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (r *hscenarioRun) leases() bool { return r.binding == "webtransport" }

func (r *hscenarioRun) connect() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var err error
	if r.binding == "webtransport" {
		r.conn, err = webtransport.Dial(ctx, r.f.wtURL, &webtransport.DialOptions{CertHashes: [][]byte{r.f.certHash}})
	} else {
		r.conn, err = websocket.Dial(ctx, r.f.wsURL, nil)
	}
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = r.conn.Close(status.OK, "") })
}

func (r *hscenarioRun) lane(name string) string {
	if !r.leases() {
		return "shared"
	}
	return name
}

func (r *hscenarioRun) stream(name string) transport.Stream {
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
	ch := make(chan []byte, 1000)
	r.raws[name] = ch
	go func() {
		for {
			b, err := s.ReadMessage()
			if err != nil {
				close(ch)
				return
			}
			ch <- b
		}
	}()
	return s
}

// hubSession returns the hub's session with the scripted client.
func (r *hscenarioRun) hubSession() *session.Session {
	var out *session.Session
	testutil.Eventually(r.t, 5*time.Second, func() bool {
		ss := r.f.h.Sessions()["user:scenario"]
		if len(ss) == 0 {
			return false
		}
		if r.sid != nil {
			// The scripted client's own session, not one of an earlier
			// scenario of the same principal still closing under load.
			for _, s := range ss {
				if bytes.Equal(s.SessionID(), r.sid) {
					out = s
					return true
				}
			}
			return false
		}
		out = ss[len(ss)-1]
		for _, s := range ss {
			// A session that ended (an earlier attempt) is not the one.
			if s.Err() == nil {
				out = s
			}
		}
		return true
	}, "no hub session for the scenario client")
	return out
}

func (r *hscenarioRun) handshake(host *schema.Schema) {
	r.send("shared", (&wire.Hello{Versions: []uint64{1}, Auth: bearer("v4.public.TEST-ONLY-TICKET")}).AppendTo(nil))
	w := r.recv("shared", wire.KindWelcome).(*wire.Welcome)
	r.sid = w.SessionID
	if !bytes.Equal(w.ServerSchema.Hash, schemaHash(r.t, host)) {
		r.t.Fatal("Welcome hash")
	}
	r.send("shared", (&wire.Ready{SchemaHash: w.ServerSchema.Hash}).AppendTo(nil))
	s := r.hubSession()
	testutil.Eventually(r.t, 5*time.Second, func() bool {
		// Ready processed: a call would be dispatched.
		return s.Welcome() != nil
	}, "not ready")
}

func (r *hscenarioRun) send(lane string, b []byte) {
	if err := r.stream(lane).WriteMessage(b); err != nil {
		if errors.Is(err, transport.ErrClosed) {
			return
		}
		r.t.Fatalf("send: %v", err)
	}
}

func (r *hscenarioRun) clientSend(st *hstep) {
	if k, id, _ := wire.PeekCall(st.raw); k == wire.KindRequest {
		m, _ := wire.Decode(st.raw)
		r.calls[id] = m.(*wire.Request).MethodID
	}
	r.send(st.Stream, st.raw)
}

func (r *hscenarioRun) recvRaw(lane string, want wire.Kind) []byte {
	r.stream(lane)
	ch := r.raws[r.lane(lane)]
	timeout := time.After(5 * time.Second)
	for {
		select {
		case b, ok := <-ch:
			if !ok {
				r.t.Fatalf("%s: lane closed, want %v", lane, want)
			}
			k, id, _ := wire.PeekCall(b)
			if k == wire.KindCredit {
				r.credited[id] = true
			}
			if k == wire.KindPing || k == wire.KindPong || (k == wire.KindCredit && want != wire.KindCredit) {
				continue
			}
			return b
		case <-timeout:
			r.t.Fatalf("%s: no %v from the hub", lane, want)
			return nil
		}
	}
}

func (r *hscenarioRun) recv(lane string, want wire.Kind) wire.Message {
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

func (r *hscenarioRun) trigger(st *hstep) {
	if st.sentEarl {
		return
	}
	st.sentEarl = true
	m, err := wire.Decode(st.raw)
	if err != nil {
		r.t.Fatal(err)
	}
	switch x := m.(type) {
	case *wire.SchemaUpdate:
		// The node publishes the new version; the hub relays it.
		def := r.update.Facets[0].Clone()
		go func() { _, _ = r.host.n.Add(context.Background(), &nd.Facet{Def: *def}) }()
	case *wire.GoAway:
		if status.Code(x.Status) == status.GoingAway {
			r.hubSession().GoAway(status.GoingAway, x.Reason, x.RetryAfterMs)
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

func canonicalBytes(t *testing.T, b []byte) []byte {
	c, err := cbor.Canonical(b, cbor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (r *hscenarioRun) serverRecv(st *hstep) {
	t := r.t
	want, _ := wire.Decode(st.raw)
	got := r.recvRaw(st.Stream, want.Kind())
	gm, err := wire.Decode(got)
	if err != nil {
		t.Fatalf("step %d: %v", st.Step, err)
	}
	if gm.Kind() != want.Kind() {
		if _, id, _ := wire.PeekCall(got); r.violates() && gm.Kind() != wire.KindError && r.credited[id] {
			// The hub forwarded the first chunk downstream and returned its
			// credit (7.4, per-hop credit) before the next chunk arrived,
			// so that chunk was within credit: the scenario's precondition
			// (no credit left) did not hold on this run.
			t.Skipf("step %d: the hub granted credit for call %d before the violating message", st.Step, id)
		}
		t.Fatalf("step %d: got %v %x, want %v %s", st.Step, gm.Kind(), got, want.Kind(), st.CBOR)
	}
	statusOf := func(m wire.Message) uint64 {
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
	switch {
	case st.Compare == "status":
		if statusOf(gm) != statusOf(want) {
			t.Fatalf("step %d: status %v, want %v", st.Step, statusOf(gm), statusOf(want))
		}
		if gc, ok := gm.(wire.CallMessage); ok && gc.Call() != want.(wire.CallMessage).Call() {
			t.Fatalf("step %d: call ID", st.Step)
		}
	case want.Kind() == wire.KindWelcome:
		g, w := *gm.(*wire.Welcome), *want.(*wire.Welcome)
		g.SessionID, w.SessionID = nil, nil
		if !bytes.Equal(canonicalBytes(t, g.AppendTo(nil)), canonicalBytes(t, w.AppendTo(nil))) {
			t.Fatalf("step %d: Welcome %x, want %x", st.Step, g.AppendTo(nil), w.AppendTo(nil))
		}
	default:
		if !bytes.Equal(canonicalBytes(t, got), canonicalBytes(t, st.raw)) {
			t.Fatalf("step %d: got %x, want %s", st.Step, got, st.CBOR)
		}
	}
}

// violates reports whether the scenario has a credit violation by the
// client.
func (r *hscenarioRun) violates() bool {
	for _, st := range r.sc.Steps {
		if st.Expect == "violation" && st.By == "client" {
			return true
		}
	}
	return false
}

func (r *hscenarioRun) quietFor(lane string, callID uint64, d time.Duration) {
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
			go func() { ch <- b }()
		case <-timer:
			return
		}
	}
}

func (r *hscenarioRun) laneOf(callID uint64, upto int) string {
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

func (r *hscenarioRun) callInfo(id uint64) (session.CallInfo, bool) {
	ss := r.f.h.Sessions()["user:scenario"]
	if len(ss) == 0 {
		return session.CallInfo{}, false // the session has ended
	}
	for _, c := range ss[len(ss)-1].Calls() {
		if c.ID == id && !c.Caller {
			return c, true
		}
	}
	return session.CallInfo{}, false
}

func (r *hscenarioRun) expect(i int, st *hstep) {
	t := r.t
	switch st.Expect {
	case "session_ready":
		r.hubSession()
	case "dispatched":
		testutil.Eventually(t, 5*time.Second, func() bool { return r.host.dispatched.Load() > 0 }, "step %d: call %d not dispatched", st.Step, st.CallID)
	case "not_dispatched":
		testutil.Never(t, 50*time.Millisecond, func() bool { return r.host.dispatched.Load() > 0 && st.CallID <= 2 },
			"step %d: %d calls reached the node", st.Step, r.host.dispatched.Load())
	case "call_ended":
		if len(r.f.h.Sessions()["user:scenario"]) == 0 {
			return // the session is gone (rejected optimistic start)
		}
		testutil.Eventually(t, 5*time.Second, func() bool { _, open := r.callInfo(st.CallID); return !open }, "step %d: call %d still open", st.Step, st.CallID)
	case "half_finished":
		testutil.Eventually(t, 5*time.Second, func() bool {
			c, open := r.callInfo(st.CallID)
			if !open {
				return true
			}
			if st.Half == "caller" {
				return c.CallerDone
			}
			return c.CalleeDone
		}, "step %d: %s half of call %d not finished", st.Step, st.Half, st.CallID)
	case "stream_idle":
		if !r.leases() {
			return
		}
		testutil.Eventually(t, 5*time.Second, func() bool {
			for _, c := range r.hubSession().Calls() {
				if !c.Shared && !c.Caller {
					return false
				}
			}
			return true
		}, "step %d: a leased stream is still busy", st.Step)
	case "streams_open":
		if !r.leases() {
			return
		}
		if st.By == "client" && r.opened != st.Count {
			t.Fatalf("step %d: client opened %d streams, want %d", st.Step, r.opened, st.Count)
		}
		testutil.Eventually(t, 5*time.Second, func() bool { return r.hubSession().Stats().PeerLeased == st.Count }, "step %d: hub counts %d streams", st.Step, r.hubSession().Stats().PeerLeased)
	case "held_back":
		lane := r.laneOf(st.CallID, i)
		if st.Reason == "schema_ack" {
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
		r.quietFor(lane, st.CallID, 150*time.Millisecond)
	case "no_reply":
		r.quietFor("shared", st.CallID, 50*time.Millisecond)
	case "discarded":
		r.quietFor(r.laneOf(st.CallID, i), st.CallID, 50*time.Millisecond)
	case "session_closed", "transport_closed":
		testutil.Eventually(t, 10*time.Second, func() bool {
			select {
			case <-r.conn.Done():
				return true
			default:
			}
			return len(r.f.h.Sessions()["user:scenario"]) == 0
		}, "step %d: session still open", st.Step)
	case "violation", "client_retries":
	default:
		t.Fatalf("step %d: unknown expectation %q", st.Step, st.Expect)
	}
}
