package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/internal/vectors"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

// Behaviour scenarios (test-vectors/scenarios). This test checks that every
// scenario message encodes and decodes as stated and that the scripted
// sequence is consistent (call-ID parity, stream headers, credit counts,
// schema epochs). Running the behaviour against real sessions is the job of
// the session tests.

type scenarioStep struct {
	Step        int             `json:"step"`
	From        string          `json:"from"`
	Stream      string          `json:"stream"`
	OpensStream bool            `json:"opens_stream"`
	Header      string          `json:"header"`
	KindName    string          `json:"kind_name"`
	Message     json.RawMessage `json:"message"`
	CBOR        string          `json:"cbor"`
	Counted     *uint64         `json:"counted_bytes"`
	CreditAfter *int64          `json:"credit_after"`
	CreditBefor *int64          `json:"credit_before"`
	Violation   bool            `json:"violation"`
	Compare     string          `json:"compare"`
	Expect      string          `json:"expect"`
	CallID      *uint64         `json:"call_id"`
}

type scenarioDoc struct {
	Format int    `json:"format"`
	Name   string `json:"name"`
	Given  struct {
		Schema        string           `json:"schema"`
		Session       string           `json:"session"`
		Delta         string           `json:"delta"`
		InitialCredit map[string]int64 `json:"initial_credit"`
	} `json:"given"`
	Steps []scenarioStep `json:"steps"`
}

var scenarioOutcomes = map[string]bool{
	"session_ready": true, "dispatched": true, "not_dispatched": true, "call_ended": true, "stream_idle": true,
	"streams_open": true, "half_finished": true, "held_back": true, "no_reply": true, "discarded": true,
	"violation": true, "session_closed": true, "transport_closed": true, "client_retries": true,
}

var streamName = regexp.MustCompile(`^(shared|lease:[1-9][0-9]*)$`)

func TestScenarios(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(vectors.Dir(), "scenarios", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no scenarios: %v", err)
	}
	for _, p := range paths {
		p := p
		t.Run(strings.TrimSuffix(filepath.Base(p), ".json"), func(t *testing.T) {
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var sc scenarioDoc
			if err := json.Unmarshal(raw, &sc); err != nil {
				t.Fatal(err)
			}
			if sc.Format != 1 || sc.Name+".json" != filepath.Base(p) {
				t.Fatalf("format %d, name %q", sc.Format, sc.Name)
			}
			checkScenario(t, &sc)
		})
	}
}

func checkScenario(t *testing.T, sc *scenarioDoc) {
	state := stateOf(t, sc.Given.Schema)
	var pending *schema.State
	opened := map[string]bool{}
	if strings.HasPrefix(sc.Given.Session, "established") {
		opened["shared"] = true
	}
	credit := map[string]*wire.CreditWindow{}
	for k, n := range sc.Given.InitialCredit {
		credit[k] = wire.NewCreditWindow(uint64(n))
	}
	answeredUnimplemented := map[uint64]bool{}
	for _, st := range sc.Steps {
		if st.Message != nil {
			if m, err := tjsonMessage(st.Message); err == nil {
				if e, ok := m.(*wire.Error); ok && e.Status == uint64(status.Unimplemented) {
					answeredUnimplemented[e.CallID] = true
				}
			}
		}
	}
	for i, st := range sc.Steps {
		at := fmt.Sprintf("step %d", st.Step)
		if st.Step != i+1 {
			t.Fatalf("%s: numbering", at)
		}
		if st.Expect != "" {
			if !scenarioOutcomes[st.Expect] {
				t.Fatalf("%s: unknown outcome %q", at, st.Expect)
			}
			continue
		}
		if st.From != "client" && st.From != "server" || !streamName.MatchString(st.Stream) {
			t.Fatalf("%s: from %q stream %q", at, st.From, st.Stream)
		}
		cb := vectors.MustHex(st.CBOR)
		m := checkMessageBytes(t, at, st.Message, cb)
		if name := kindName(m); name != st.KindName {
			t.Fatalf("%s: kind %s, vector says %s", at, name, st.KindName)
		}
		opens := st.From == "client" && !opened[st.Stream]
		opened[st.Stream] = opened[st.Stream] || opens
		if st.OpensStream != opens {
			t.Fatalf("%s: opens_stream %v, want %v", at, st.OpensStream, opens)
		}
		if opens {
			want := wire.HeaderLeased
			if st.Stream == "shared" {
				want = wire.HeaderSharedLane
			}
			if st.Header != fmt.Sprintf("%02x", want) {
				t.Fatalf("%s: header %s", at, st.Header)
			}
		}
		switch x := m.(type) {
		case *wire.Request:
			if x.CallID == 0 {
				if st.Stream != "shared" {
					t.Fatalf("%s: a notification off the shared lane", at)
				}
			} else if (x.CallID%2 == 0) != (st.From == "client") {
				t.Fatalf("%s: call ID %d has the wrong parity for the %s", at, x.CallID, st.From)
			}
			f := state.Schema().Facet(x.FacetID)
			var meth *schema.Method
			if f != nil {
				meth, _ = f.Method(x.MethodID)
			}
			switch {
			case meth == nil && !answeredUnimplemented[x.CallID]:
				t.Fatalf("%s: facet %d method %d does not exist and is not answered with unimplemented", at, x.FacetID, x.MethodID)
			case meth != nil && (x.CallID == 0) != meth.IsNotification():
				t.Fatalf("%s: call ID 0 is for notifications only", at)
			}
		case *wire.Welcome:
			h, _ := state.Hash()
			if !bytes.Equal(x.ServerSchema.Hash, h) {
				t.Fatalf("%s: Welcome offers %x, scenario schema is %x", at, x.ServerSchema.Hash, h)
			}
			if x.ServerSchema.Kind == wire.OfferFull {
				checkInlineSchema(t, x.ServerSchema.Hash, x.ServerSchema.Schema)
			}
		case *wire.SchemaUpdate:
			d, err := schema.DecodeDelta(x.Delta)
			if err != nil {
				t.Fatal(err)
			}
			if pending, err = state.ApplyUpdate(x.Epoch, x.Hash, d); err != nil {
				t.Fatalf("%s: %v", at, err)
			}
			if !bytes.Equal(x.Hash, schemaHashOf(t, sc.Given.Delta)) {
				t.Fatalf("%s: hash differs from given.delta", at)
			}
		case *wire.SchemaAck:
			if pending == nil || pending.Epoch() != x.Epoch {
				t.Fatalf("%s: ack without a matching update", at)
			}
			state, pending = pending, nil
		case *wire.Credit:
			to := "client"
			if st.From == "client" {
				to = "server"
			}
			w := credit[fmt.Sprintf("%d/%s", x.CallID, to)]
			w.Grant(x.Amount)
			if st.CreditAfter == nil || w.Remaining() != *st.CreditAfter {
				t.Fatalf("%s: credit after grant %d", at, w.Remaining())
			}
		}
		if st.Counted != nil {
			cm := m.(wire.CallMessage)
			n := wire.CountedBytes(m, len(cb))
			w := credit[fmt.Sprintf("%d/%s", cm.Call(), st.From)]
			if n != *st.Counted || w == nil {
				t.Fatalf("%s: counted %d, want %d (window %v)", at, n, *st.Counted, w)
			}
			if st.Violation {
				if w.CanSendCounted(n) || w.Remaining() != *st.CreditBefor || w.Consume(n) == nil {
					t.Fatalf("%s: not a credit violation", at)
				}
				continue
			}
			if !w.CanSendCounted(n) {
				t.Fatalf("%s: sent with no credit", at)
			}
			if err := w.Consume(n); err != nil || w.Remaining() != *st.CreditAfter {
				t.Fatalf("%s: remaining %d, want %d (%v)", at, w.Remaining(), *st.CreditAfter, err)
			}
		}
	}
}

func kindName(m wire.Message) string {
	return strings.TrimPrefix(fmt.Sprintf("%T", m), "*wire.")
}
