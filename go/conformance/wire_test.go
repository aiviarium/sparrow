package conformance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/internal/vectors"
	"github.com/aiviarium/sparrow/go/schema"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/wire"
)

// checkMessageBytes checks one encoded message against its typed JSON:
// the vector bytes equal the canonical encoding of the JSON, the message
// decodes, has the expected kind, and re-encodes to the same bytes.
func checkMessageBytes(t *testing.T, name string, msgJSON json.RawMessage, cb []byte) wire.Message {
	t.Helper()
	want, err := vectors.TJSONToCBOR(msgJSON)
	if err != nil {
		t.Fatalf("%s: typed JSON: %v", name, err)
	}
	if !bytes.Equal(want, cb) {
		t.Fatalf("%s: cbor field differs from typed JSON message\n got %x\nwant %x", name, cb, want)
	}
	m, err := wire.Decode(cb)
	if err != nil {
		t.Fatalf("%s: decode: %v", name, err)
	}
	if got := wire.Encode(m); !bytes.Equal(got, cb) {
		t.Fatalf("%s: re-encoding differs\n got %x\nwant %x", name, got, cb)
	}
	return m
}

func checkMessageVector(t *testing.T, v vectors.Vector) wire.Message {
	t.Helper()
	cb := v.Hex("cbor")
	m := checkMessageBytes(t, v.Name, v.Fields["message"], cb)
	if uint64(m.Kind()) != uint64(v.Int("kind")) || m.Kind().String() != v.String("kind_name") {
		t.Fatalf("kind %v, want %d %s", m.Kind(), v.Int("kind"), v.String("kind_name"))
	}
	if int64(len(cb)) != v.Int("length") {
		t.Fatalf("length %d, want %d", len(cb), v.Int("length"))
	}
	framed := v.Hex("framed")
	if got := wire.AppendFrame(nil, cb); !bytes.Equal(got, framed) {
		t.Fatalf("framed %x, want %x", got, framed)
	}
	fr := wire.NewFrameReader(bytes.NewReader(framed), wire.DefaultMaxMessageSize)
	got, err := fr.ReadFrame()
	if err != nil || !bytes.Equal(got, cb) {
		t.Fatalf("ReadFrame = %x, %v", got, err)
	}
	if _, err := fr.ReadFrame(); err != io.EOF {
		t.Fatalf("second ReadFrame: %v, want EOF", err)
	}
	if v.Has("spec_framed") {
		if v.Bool("matches_spec") != bytes.Equal(v.Hex("spec_framed"), framed) {
			t.Fatalf("spec_framed / matches_spec inconsistent")
		}
	}
	return m
}

func TestFraming(t *testing.T) {
	each(t, "framing.json", func(t *testing.T, v vectors.Vector) {
		tv, err := vectors.TJSON(v.Fields["value"])
		if err != nil {
			t.Fatal(err)
		}
		u := tv.(uint64)
		enc := v.Hex("encoded")
		decodeOnly := v.Has("decode_only") && v.Bool("decode_only")
		if !decodeOnly {
			if got := wire.AppendVarint(nil, u); !bytes.Equal(got, enc) {
				t.Fatalf("AppendVarint(%d) = %x, want %x", u, got, enc)
			}
			if wire.VarintLen(u) != len(enc) {
				t.Fatalf("VarintLen")
			}
		} else if got := wire.AppendVarint(nil, u); bytes.Equal(got, enc) {
			t.Fatalf("decode-only form is the shortest form")
		}
		got, k, err := wire.ParseVarint(enc)
		if err != nil || got != u || k != len(enc) {
			t.Fatalf("ParseVarint = %d, %d, %v", got, k, err)
		}
		rv, err := wire.ReadVarint(bufio.NewReader(bytes.NewReader(enc)))
		if err != nil || rv != u {
			t.Fatalf("ReadVarint = %d, %v", rv, err)
		}
	}, "quic_varint")

	each(t, "framing.json", func(t *testing.T, v vectors.Vector) {
		var entries []struct {
			Byte   string `json:"byte"`
			Open   bool   `json:"shared_lane_open"`
			Opener string `json:"opener"`
			Result string `json:"result"`
		}
		v.Into("entries", &entries)
		for _, e := range entries {
			role := wire.Client
			if e.Opener == "server" {
				role = wire.Server
			}
			k, err := wire.ClassifyStreamHeader(vectors.MustHex(e.Byte)[0], role, e.Open)
			got := map[wire.StreamKind]string{wire.SharedLane: "shared_lane", wire.LeasedStream: "leased_stream",
				wire.ProfileStream: "profile_reserved"}[k]
			if err != nil {
				got = "protocol_error"
			}
			if got != e.Result {
				t.Errorf("header %s opener %s open %v: %s, want %s", e.Byte, e.Opener, e.Open, got, e.Result)
			}
		}
	}, "stream_header_table")

	each(t, "framing.json", func(t *testing.T, v vectors.Vector) {
		var entries []struct {
			Kind   uint64 `json:"kind"`
			Owner  string `json:"owner"`
			Action string `json:"if_unknown"`
		}
		v.Into("entries", &entries)
		for _, e := range entries {
			o, a := wire.KindRange(e.Kind)
			if o.String() != e.Owner || a.String() != e.Action {
				t.Errorf("kind %d: %v/%v, want %s/%s", e.Kind, o, a, e.Owner, e.Action)
			}
			// a message of an unknown kind is reported with that action
			if !wire.Kind(e.Kind).Known() {
				_, err := wire.Decode(cbor.AppendUint(cbor.AppendArrayHead(nil, 1), e.Kind))
				var uk *wire.UnknownKindError
				if !asUnknown(err, &uk) || uk.Action.String() != e.Action {
					t.Errorf("kind %d: decode error %v", e.Kind, err)
				}
			}
		}
	}, "kind_range_table")

	each(t, "framing.json", func(t *testing.T, v vectors.Vector) { checkMessageVector(t, v) }, "message")

	each(t, "framing.json", func(t *testing.T, v vectors.Vector) {
		var parts []struct {
			What string `json:"what"`
			Hex  string `json:"hex"`
			Ref  string `json:"ref"`
		}
		v.Into("parts", &parts)
		var concat []byte
		for _, p := range parts {
			concat = append(concat, vectors.MustHex(p.Hex)...)
		}
		stream := v.Hex("bytes")
		if !bytes.Equal(concat, stream) {
			t.Fatalf("parts do not add up to bytes")
		}
		fr := wire.NewFrameReader(bytes.NewReader(stream), wire.DefaultMaxMessageSize)
		var msgs [][]byte
		if strings.HasPrefix(parts[0].What, "stream header") {
			h, err := fr.ReadHeader()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wire.ClassifyStreamHeader(h, wire.Client, false); err != nil {
				t.Fatal(err)
			}
		}
		for {
			m, err := fr.ReadFrame()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wire.Decode(m); err != nil {
				t.Fatal(err)
			}
			msgs = append(msgs, m)
		}
		// every message facet with a ref equals that vector's cbor
		i := 0
		for _, p := range parts {
			if p.Ref == "" {
				continue
			}
			ref := vector(t, p.Ref)
			if i >= len(msgs) || !bytes.Equal(msgs[i], ref.Hex("cbor")) ||
				!(bytes.Equal(msgs[i], vectors.MustHex(p.Hex)) || bytes.Equal(wire.AppendFrame(nil, msgs[i]), vectors.MustHex(p.Hex))) {
				t.Fatalf("message %d differs from %s", i, p.Ref)
			}
			i++
		}
		if i != len(msgs) {
			t.Fatalf("%d messages, %d refs", len(msgs), i)
		}
		if !(v.Has("decode_only") && v.Bool("decode_only")) {
			// a sender writes exactly these bytes
			var out []byte
			if strings.HasPrefix(parts[0].What, "stream header") {
				out = append(out, vectors.MustHex(parts[0].Hex)...)
			}
			for _, m := range msgs {
				out = wire.AppendFrame(out, m)
			}
			if !bytes.Equal(out, stream) {
				t.Fatalf("re-framed stream differs")
			}
		}
		if v.Has("reverse_bytes") {
			rb := v.Hex("reverse_bytes")
			fr := wire.NewFrameReader(bytes.NewReader(rb), wire.DefaultMaxMessageSize)
			m, err := fr.ReadFrame()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fr.ReadFrame(); err != io.EOF {
				t.Fatalf("reverse direction holds more than one message")
			}
			if v.Has("reverse_ref") {
				if !bytes.Equal(m, vector(t, v.String("reverse_ref")).Hex("cbor")) {
					t.Fatalf("reverse message differs from %s", v.String("reverse_ref"))
				}
			} else if _, err := wire.Decode(m); err != nil {
				t.Fatal(err)
			}
		}
	}, "stream")

	each(t, "framing.json", func(t *testing.T, v vectors.Vector) {
		var ms []string
		v.Into("ws_messages", &ms)
		refs := []string{"example-7.7/request", "example-7.7/response"}
		for i, h := range ms {
			b := vectors.MustHex(h)
			if _, err := wire.Decode(b); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b, vector(t, refs[i]).Hex("cbor")) {
				t.Fatalf("ws message %d differs from %s", i, refs[i])
			}
		}
	}, "websocket")
}

func asUnknown(err error, out **wire.UnknownKindError) bool {
	u, ok := err.(*wire.UnknownKindError)
	if ok {
		*out = u
	}
	return ok
}

func tjsonMessage(raw json.RawMessage) (wire.Message, error) {
	b, err := vectors.TJSONToCBOR(raw)
	if err != nil {
		return nil, err
	}
	return wire.Decode(b)
}

// schemaHashOf returns the hash field of a schema or delta vector.
func schemaHashOf(t *testing.T, name string) []byte {
	t.Helper()
	return vector(t, name).Hex("hash")
}

// stateOf returns the schema state a schema or valid delta vector ends in.
func stateOf(t *testing.T, name string) *schema.State {
	t.Helper()
	v := vector(t, name)
	if v.Type == "schema" {
		s, err := schema.DecodeSchema(v.CBOR("input"))
		if err != nil {
			t.Fatal(err)
		}
		st, err := schema.NewState(s)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	from := stateOf(t, v.String("from"))
	d, err := schema.DecodeDelta(v.CBOR("delta"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := from.Apply(d)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func checkInlineSchema(t *testing.T, hash []byte, raw cbor.Raw) {
	t.Helper()
	s, err := schema.DecodeSchema(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	h, err := s.Hash()
	if err != nil || !bytes.Equal(h, hash) {
		t.Fatalf("inline schema hash %x, message says %x (%v)", h, hash, err)
	}
}

func checkRefs(t *testing.T, v vectors.Vector, m wire.Message) {
	t.Helper()
	if !v.Has("refs") {
		return
	}
	var refs map[string]string
	v.Into("refs", &refs)
	eq := func(field string, got []byte) {
		t.Helper()
		if want := schemaHashOf(t, refs[field]); !bytes.Equal(got, want) {
			t.Fatalf("%s = %x, want hash of %s %x", field, got, refs[field], want)
		}
	}
	switch x := m.(type) {
	case *wire.Hello:
		if _, ok := refs["known_schema"]; ok {
			eq("known_schema", x.KnownSchema)
		}
		if _, ok := refs["client_schema"]; ok {
			eq("client_schema", x.ClientSchema.Hash)
			checkInlineSchema(t, x.ClientSchema.Hash, x.ClientSchema.Schema)
		}
		if x.Optimistic {
			if err := x.CheckOptimistic(); err != nil {
				t.Fatal(err)
			}
		}
	case *wire.Welcome:
		eq("hash", x.ServerSchema.Hash)
		if _, ok := refs["from"]; ok {
			eq("from", x.ServerSchema.From)
		}
	case *wire.Ready:
		eq("schema_hash", x.SchemaHash)
	case *wire.SchemaUpdate:
		eq("hash", x.Hash)
		from := stateOf(t, vector(t, refs["hash"]).String("from"))
		d, err := schema.DecodeDelta(x.Delta)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := from.ApplyUpdate(x.Epoch, x.Hash, d); err != nil {
			t.Fatalf("applying the update: %v", err)
		}
	case *wire.Request:
		// forward/node-call-with-context: checked in the hub tests
	default:
		t.Fatalf("unexpected refs on %v", m.Kind())
	}
}

func TestParams(t *testing.T) {
	each(t, "handshake.json", func(t *testing.T, v vectors.Vector) {
		var entries []struct {
			SentIn    string            `json:"sent_in"`
			Params    json.RawMessage   `json:"params"`
			CBOR      string            `json:"params_cbor"`
			Expected  string            `json:"expected"`
			Status    uint64            `json:"status"`
			Key       string            `json:"key"`
			Effective map[string]uint64 `json:"effective"`
		}
		v.Into("entries", &entries)
		for _, e := range entries {
			cb := vectors.MustHex(e.CBOR)
			if tb, err := vectors.TJSONToCBOR(e.Params); err != nil || !bytes.Equal(tb, cb) {
				t.Fatalf("params_cbor differs from params")
			}
			// Decode the params inside a Hello, as a receiver would.
			p := paramsOf(t, cb)
			err := p.Validate()
			if e.Expected == "goaway" {
				var pe *wire.ParamError
				if !errors.As(err, &pe) || pe.Key != e.Key || e.Status != uint64(status.InvalidArgument) {
					t.Fatalf("%s: Validate = %v, want key %s", e.CBOR, err, e.Key)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s: %v", e.CBOR, err)
			}
			sender := wire.Server
			if e.SentIn == "Hello" {
				sender = wire.Client
			}
			l := p.Limits(sender)
			got := map[string]uint64{
				wire.ParamMaxMessageSize: l.MaxMessageSize, wire.ParamMaxInlineBytes: l.MaxInlineBytes,
				wire.ParamMaxConcurrentCalls: l.MaxConcurrentCalls, wire.ParamMaxStreams: l.MaxStreams,
				wire.ParamSharedCredit: l.SharedCredit, wire.ParamLeaseCredit: l.LeaseCredit, wire.ParamIdleTimeoutMs: l.IdleTimeoutMs,
			}
			if fmt.Sprint(got) != fmt.Sprint(e.Effective) {
				t.Fatalf("%s: limits %v, want %v", e.CBOR, got, e.Effective)
			}
		}
	}, "params_table")
}

func TestHandshake(t *testing.T) {
	each(t, "handshake.json", func(t *testing.T, v vectors.Vector) {
		m := checkMessageVector(t, v)
		checkRefs(t, v, m)
		if w, ok := m.(*wire.Welcome); ok {
			switch w.ServerSchema.Kind {
			case wire.OfferFull:
				checkInlineSchema(t, w.ServerSchema.Hash, w.ServerSchema.Schema)
			case wire.OfferDelta:
				st := stateOf(t, "schema/server-base")
				if h, _ := st.Hash(); !bytes.Equal(h, w.ServerSchema.From) {
					t.Fatalf("delta from %x, client named %x", w.ServerSchema.From, h)
				}
				d, err := schema.DecodeDelta(w.ServerSchema.Delta)
				if err != nil {
					t.Fatal(err)
				}
				n, err := st.Apply(d)
				if err != nil {
					t.Fatal(err)
				}
				if h, _ := n.Hash(); !bytes.Equal(h, w.ServerSchema.Hash) {
					t.Fatalf("delta result %x, offer says %x", h, w.ServerSchema.Hash)
				}
			}
			l := w.Params.Limits(wire.Server)
			if l.MaxStreams == 0 {
				t.Fatalf("limits")
			}
			if err := w.Params.Validate(); err != nil {
				t.Fatal(err)
			}
		}
		if h, ok := m.(*wire.Hello); ok {
			if err := h.Params.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	}, "message")
}

func TestCalls(t *testing.T) {
	each(t, "calls.json", func(t *testing.T, v vectors.Vector) {
		m := checkMessageVector(t, v)
		checkRefs(t, v, m)
		switch x := m.(type) {
		case *wire.Request:
			if _, _, err := x.Metadata.Deadline(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := x.Metadata.Trace(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := x.Metadata.Credit(); err != nil {
				t.Fatal(err)
			}
			if !wire.ValidCallID(wire.CallerOf(x.CallID), x.CallID) {
				t.Fatal("call id")
			}
		}
	}, "message")

	each(t, "calls.json", func(t *testing.T, v vectors.Vector) {
		var req, errm struct {
			Message json.RawMessage `json:"message"`
			CBOR    string          `json:"cbor"`
		}
		v.Into("request", &req)
		v.Into("error", &errm)
		r := checkMessageBytes(t, "request", req.Message, vectors.MustHex(req.CBOR)).(*wire.Request)
		e := checkMessageBytes(t, "error", errm.Message, vectors.MustHex(errm.CBOR)).(*wire.Error)
		st := stateOf(t, v.String("schema"))
		s := st.Schema()
		f := s.Facet(r.FacetID)
		missing := f == nil
		if f != nil {
			m, _ := f.Method(r.MethodID)
			missing = m == nil
		}
		if !missing {
			t.Fatalf("facet %d method %d exists", r.FacetID, r.MethodID)
		}
		if e.CallID != r.CallID || e.Status != 12 {
			t.Fatalf("answer is %+v, want Error(unimplemented) for call %d", e, r.CallID)
		}
	}, "unimplemented")
}

func TestCredit(t *testing.T) {
	each(t, "credit.json", func(t *testing.T, v vectors.Vector) {
		cb := v.Hex("cbor")
		m := checkMessageBytes(t, v.Name, v.Fields["message"], cb)
		want := uint64(v.Int("counted_bytes"))
		if got := wire.CountedBytes(m, len(cb)); got != want {
			t.Fatalf("CountedBytes = %d, want %d", got, want)
		}
		if got, err := wire.CountedBytesRaw(cb); err != nil || got != want {
			t.Fatalf("CountedBytesRaw = %d, %v", got, err)
		}
		if int64(len(wire.AppendFrame(nil, cb))) != v.Int("framed_length") {
			t.Fatalf("framed_length")
		}
	}, "credit_count")

	each(t, "credit.json", func(t *testing.T, v vectors.Vector) {
		var steps []struct {
			Action    string          `json:"action"`
			Message   json.RawMessage `json:"message"`
			CBOR      string          `json:"cbor"`
			Counted   uint64          `json:"counted_bytes"`
			After     int64           `json:"remaining_after"`
			MaySend   bool            `json:"may_send"`
			Remaining int64           `json:"remaining"`
			Amount    uint64          `json:"amount"`
			Answer    json.RawMessage `json:"answer"`
		}
		v.Into("steps", &steps)
		w := wire.NewCreditWindow(uint64(v.Int("initial_credit")))
		for i, s := range steps {
			switch s.Action {
			case "send":
				cb := vectors.MustHex(s.CBOR)
				m := checkMessageBytes(t, "step", s.Message, cb)
				n := wire.CountedBytes(m, len(cb))
				if n != s.Counted {
					t.Fatalf("step %d: counted %d, want %d", i, n, s.Counted)
				}
				if !w.CanSendCounted(n) {
					t.Fatalf("step %d: may not send", i)
				}
				if n == 0 && !w.CanSend() && w.Consume(0) != nil {
					t.Fatalf("step %d: a message counting zero bytes is a violation", i)
				}
				if err := w.Consume(n); err != nil {
					t.Fatal(err)
				}
				if w.Remaining() != s.After {
					t.Fatalf("step %d: remaining %d, want %d", i, w.Remaining(), s.After)
				}
			case "check":
				if w.CanSend() != s.MaySend || w.Remaining() != s.Remaining {
					t.Fatalf("step %d: CanSend %v remaining %d", i, w.CanSend(), w.Remaining())
				}
				if !s.MaySend {
					if err := w.Consume(1); err == nil {
						t.Fatalf("step %d: receiver accepted data with no credit", i)
					}
				}
			case "violation":
				cb := vectors.MustHex(s.CBOR)
				m := checkMessageBytes(t, "step", s.Message, cb)
				n := wire.CountedBytes(m, len(cb))
				if n != s.Counted || n == 0 || w.CanSendCounted(n) || w.Remaining() != s.Remaining {
					t.Fatalf("step %d: not a violation (counted %d, remaining %d)", i, n, w.Remaining())
				}
				if err := w.Consume(n); !errors.Is(err, wire.ErrNoCredit) {
					t.Fatalf("step %d: Consume = %v, want ErrNoCredit", i, err)
				}
				var ans struct {
					Message json.RawMessage `json:"message"`
					CBOR    string          `json:"cbor"`
				}
				_ = json.Unmarshal(s.Answer, &ans)
				c, ok := checkMessageBytes(t, "answer", ans.Message, vectors.MustHex(ans.CBOR)).(*wire.Cancel)
				if !ok || c.CallID != m.(wire.CallMessage).Call() || c.Status != uint64(status.ProtocolError) {
					t.Fatalf("step %d: answer %+v, want Cancel(protocol_error)", i, c)
				}
			case "receive_credit":
				m, err := tjsonMessage(s.Message)
				if err != nil {
					t.Fatal(err)
				}
				c := m.(*wire.Credit)
				if c.Amount != s.Amount {
					t.Fatalf("amount")
				}
				w.Grant(c.Amount)
				if w.Remaining() != s.After {
					t.Fatalf("step %d: remaining %d, want %d", i, w.Remaining(), s.After)
				}
			default:
				t.Fatalf("unknown step %q", s.Action)
			}
		}
	}, "credit_sequence")
}
