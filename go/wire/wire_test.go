package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/fuzzseed"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func u64(v uint64) *uint64 { return &v }
func str(s string) *string { return &s }

func TestVarint(t *testing.T) {
	tests := []struct {
		v   uint64
		enc string
	}{
		{0, "00"}, {63, "3f"}, {64, "4040"}, {16383, "7fff"}, {16384, "80004000"},
		{1<<30 - 1, "bfffffff"}, {1 << 30, "c000000040000000"}, {MaxVarint, "ffffffffffffffff"},
	}
	for _, tc := range tests {
		if got := AppendVarint(nil, tc.v); hex.EncodeToString(got) != tc.enc {
			t.Errorf("AppendVarint(%d) = %x, want %s", tc.v, got, tc.enc)
		}
		if VarintLen(tc.v) != len(tc.enc)/2 {
			t.Errorf("VarintLen(%d)", tc.v)
		}
		v, n, err := ParseVarint(unhex(tc.enc + "ff"))
		if err != nil || v != tc.v || n != len(tc.enc)/2 {
			t.Errorf("ParseVarint(%s) = %d, %d, %v", tc.enc, v, n, err)
		}
	}
	if _, err := PutVarint(nil, MaxVarint+1); err != ErrVarintRange {
		t.Errorf("PutVarint(2^62) err = %v", err)
	}
	if _, _, err := ParseVarint(unhex("80 00")); err != io.ErrUnexpectedEOF {
		t.Errorf("truncated varint: %v", err)
	}
	if _, _, err := ParseVarint(nil); err != io.ErrUnexpectedEOF {
		t.Errorf("empty varint: %v", err)
	}
	defer func() {
		if recover() == nil {
			t.Error("AppendVarint(2^62) did not panic")
		}
	}()
	AppendVarint(nil, MaxVarint+1)
}

func TestFrameReader(t *testing.T) {
	msg := unhex("820401")
	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)
	if err := fw.WriteHeader(HeaderLeased); err != nil {
		t.Fatal(err)
	}
	if err := fw.WriteFrame(msg); err != nil {
		t.Fatal(err)
	}
	buf.Write(unhex("4003 820401")) // non-minimal prefix
	fr := NewFrameReader(&buf, 16)
	if h, err := fr.ReadHeader(); err != nil || h != HeaderLeased {
		t.Fatalf("header %x %v", h, err)
	}
	for i := 0; i < 2; i++ {
		got, err := fr.ReadFrame()
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("frame %d = %x, %v", i, got, err)
		}
	}
	if _, err := fr.ReadFrame(); err != io.EOF {
		t.Fatalf("at end: %v", err)
	}

	tests := []struct {
		name string
		in   string
		max  uint64
		want error
	}{
		{"too large", "11" + strings.Repeat("00", 17), 16, &TooLargeError{}},
		{"too large before body arrives", "c0000000ffffffff", 1 << 20, &TooLargeError{}},
		{"empty frame", "00", 16, ErrEmptyFrame},
		{"cut body", "05 0102", 16, io.ErrUnexpectedEOF},
		{"cut prefix", "40", 16, io.ErrUnexpectedEOF},
	}
	for _, tc := range tests {
		_, err := NewFrameReader(bytes.NewReader(unhex(tc.in)), tc.max).ReadFrame()
		var tl *TooLargeError
		if _, isTL := tc.want.(*TooLargeError); isTL {
			if !errors.As(err, &tl) {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestClassifyStreamHeader(t *testing.T) {
	tests := []struct {
		h      byte
		opener Role
		open   bool
		want   StreamKind
		ok     bool
	}{
		{0x00, Client, false, SharedLane, true},
		{0x00, Client, true, 0, false},
		{0x00, Server, false, 0, false},
		{0x01, Server, true, LeasedStream, true},
		{0x40, Client, false, ProfileStream, true},
		{0x7f, Server, false, ProfileStream, true},
		{0x02, Client, false, 0, false},
		{0x3f, Client, false, 0, false},
		{0x80, Client, false, 0, false},
	}
	for _, tc := range tests {
		k, err := ClassifyStreamHeader(tc.h, tc.opener, tc.open)
		if (err == nil) != tc.ok || (tc.ok && k != tc.want) {
			t.Errorf("%02x %v %v: %v %v", tc.h, tc.opener, tc.open, k, err)
		}
		if err != nil && !errors.Is(err, ErrStreamHeader) {
			t.Errorf("error does not wrap ErrStreamHeader")
		}
	}
}

func TestKindRange(t *testing.T) {
	for k := uint64(0); k < 300; k++ {
		o, a := KindRange(k)
		var wo Owner
		var wa Action
		switch {
		case k < 48:
			wo, wa = OwnerCore, CloseProtocolError
		case k < 64:
			wo, wa = OwnerCore, Ignore
		case k < 112:
			wo, wa = OwnerProfile, CloseProtocolError
		case k < 128:
			wo, wa = OwnerProfile, Ignore
		default:
			wo, wa = OwnerInvalid, CloseProtocolError
		}
		if o != wo || a != wa {
			t.Errorf("kind %d: %v %v", k, o, a)
		}
	}
	_, err := Decode(unhex("83 1830 01 02"))
	if !IsIgnorable(err) {
		t.Errorf("kind 48: %v", err)
	}
	_, err = Decode(unhex("81 181a"))
	var uk *UnknownKindError
	if !errors.As(err, &uk) || uk.Action != CloseProtocolError || IsIgnorable(err) || uk.Kind != 26 {
		t.Errorf("kind 26: %v, want must-close unknown kind", err)
	}
}

func sampleMessages() []Message {
	var md Metadata
	md.SetDeadline(5000)
	md.SetCredit(1 << 18)
	_ = md.SetTrace(make([]byte, TraceLen))
	md.SetContext([]byte{1, 2, 3})
	md.SetPrincipal("user:alice")
	md[TextKey("x-tenant")] = cbor.AppendText(nil, "acme")
	var p Params
	p.Set(ParamMaxStreams, 2)
	p.Extra = map[string]cbor.Raw{"future": cbor.AppendText(nil, "x")}
	exp := cbor.Unix(1795766400)
	return []Message{
		&Hello{Versions: []uint64{2, 1}, Caps: TextMap{"datagrams": cbor.AppendBool(nil, true)},
			Auth: &Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, "t")}, KnownSchema: []byte{1, 2},
			ClientSchema: &InlineSchema{Hash: []byte{3}, Schema: unhex("8502 60 60 80 a0")}, Params: p, Optimistic: true},
		&Hello{Versions: []uint64{1}},
		&Welcome{Version: 1, SessionID: make([]byte, 16), Props: TextMap{"a": cbor.Null},
			ServerSchema: SchemaOffer{Kind: OfferUnchanged, Hash: []byte{9}}},
		&Welcome{Version: 1, SessionID: []byte{}, ServerSchema: SchemaOffer{Kind: OfferDelta, Hash: []byte{9}, From: []byte{8}, Delta: unhex("80")}},
		&Welcome{Version: 1, SessionID: []byte{}, ServerSchema: SchemaOffer{Kind: OfferFull, Hash: []byte{9}, Schema: unhex("8502 60 60 80 a0")}},
		&Welcome{Version: 1, SessionID: []byte{}, ServerSchema: SchemaOffer{Kind: OfferOutOfBand, Hash: []byte{9}, Location: "/s"}},
		&Ready{SchemaHash: []byte{1}},
		&SchemaUpdate{Epoch: 3, Hash: []byte{1}, Delta: unhex("80")},
		&SchemaAck{Epoch: 3},
		&AuthRefresh{Auth: Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, "t")}},
		&AuthStatus{Status: 0, ExpiresAt: &exp},
		&AuthStatus{Status: 16},
		&Ping{Nonce: 42},
		&Pong{Nonce: 42},
		&GoAway{Status: 19, Reason: "no", Versions: []uint64{1}},
		&GoAway{Status: 21, Reason: "", RetryAfterMs: u64(0), Versions: []uint64{}},
		&Request{CallID: 2, FacetID: 16, MethodID: 1042, Metadata: md, Input: unhex("826873657474696e6773f5")},
		&Request{CallID: 0, FacetID: 1, MethodID: 0, Input: cbor.Null},
		&Response{CallID: 2, Output: cbor.Null},
		&Item{CallID: 4, Value: unhex("8201 00")},
		&End{CallID: 4, Trailers: Metadata{TextKey("rows"): cbor.AppendUint(nil, 3)}},
		&Error{CallID: 4, Status: 66, Message: "bad", Details: unhex("82 1840 00")},
		&Error{CallID: 4, Status: 12, Message: "x"},
		&Progress{CallID: 4, Done: 1, Total: u64(10), Note: str("x")},
		&Progress{CallID: 4, Done: 1},
		&Headers{CallID: 4},
		&Cancel{CallID: 4, Status: 1},
		&Credit{CallID: 4, Amount: 1 << 20},
		&Bytes{CallID: 4, Token: 1, Data: []byte("abc"), Fin: true},
		&Bytes{CallID: 4, Token: 0, Data: []byte{}, Fin: false},
	}
}

func TestRoundTrip(t *testing.T) {
	for _, m := range sampleMessages() {
		b := Encode(m)
		if !cbor.IsCanonical(b, cbor.Options{}) {
			t.Errorf("%v: encoding %x is not deterministic", m.Kind(), b)
		}
		got, err := Decode(b)
		if err != nil {
			t.Fatalf("%v: %v (%x)", m.Kind(), err, b)
		}
		if got.Kind() != m.Kind() {
			t.Fatalf("kind %v != %v", got.Kind(), m.Kind())
		}
		if b2 := Encode(got); !bytes.Equal(b, b2) {
			t.Errorf("%v: %x != %x", m.Kind(), b2, b)
		}
		if cm, ok := got.(CallMessage); ok {
			k, id, err := PeekCall(b)
			if err != nil || k != m.Kind() || id != cm.Call() {
				t.Errorf("PeekCall(%v) = %v %d %v", m.Kind(), k, id, err)
			}
			if k != KindRequest {
				r, err := RewriteCallID(b, 1001)
				if err != nil {
					t.Fatal(err)
				}
				rm, err := Decode(r)
				if err != nil || rm.(CallMessage).Call() != 1001 {
					t.Errorf("RewriteCallID(%v): %v", k, err)
				}
			}
		}
	}
	// a nil Metadata and an empty Params encode as {}
	if b := Encode(&Headers{CallID: 1}); !bytes.Equal(b, unhex("83 16 01 a0")) {
		t.Errorf("Headers = %x", b)
	}
}

func TestDecodeTyped(t *testing.T) {
	m, err := Decode(Encode(sampleMessages()[0]))
	if err != nil {
		t.Fatal(err)
	}
	h := m.(*Hello)
	if !reflect.DeepEqual(h.Versions, []uint64{2, 1}) || h.Auth.Scheme != "bearer" || !h.Optimistic ||
		!bytes.Equal(h.KnownSchema, []byte{1, 2}) || h.ClientSchema == nil {
		t.Errorf("Hello = %+v", h)
	}
	if v, ok := h.Params.Get(ParamMaxStreams); !ok || v != 2 || h.Params.Extra["future"] == nil {
		t.Errorf("params %+v", h.Params)
	}
	if l := h.Params.Limits(Client); l.MaxStreams != 2 || l.LeaseCredit != DefaultLeaseCredit || !l.BelowDefaults(Client) {
		t.Errorf("limits %+v", l)
	}
	if err := h.CheckOptimistic(); err == nil {
		t.Error("optimistic Hello with two versions accepted")
	}
	r := sampleMessages()[16].(*Request)
	rm, _ := Decode(Encode(r))
	md := rm.(*Request).Metadata
	if d, ok, err := md.Deadline(); d != 5000 || !ok || err != nil {
		t.Errorf("deadline %d %v %v", d, ok, err)
	}
	if c, _, _ := md.Credit(); c != 1<<18 {
		t.Error("credit")
	}
	if tr, _, err := md.Trace(); len(tr) != TraceLen || err != nil {
		t.Error("trace")
	}
	if p, _, _ := md.Principal(); p != "user:alice" {
		t.Error("principal")
	}
	if c, _, _ := md.Context(); !bytes.Equal(c, []byte{1, 2, 3}) {
		t.Error("context")
	}
	a, _ := Decode(Encode(&AuthStatus{Status: 0, ExpiresAt: &cbor.Time{IsFloat: true, Float: 1.5}}))
	if e := a.(*AuthStatus).ExpiresAt; e == nil || !e.IsFloat || e.Float != 1.5 {
		t.Errorf("expires %+v", e)
	}
	g, _ := Decode(unhex("85 09 15 60 f6 f6"))
	if ga := g.(*GoAway); ga.Versions != nil || ga.RetryAfterMs != nil {
		t.Errorf("null versions decoded as %+v", ga)
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct{ name, in string }{
		{"not an array", "a0"},
		{"empty envelope", "80"},
		{"kind not uint", "8120"},
		{"kind text", "816161"},
		{"invalid cbor", "9f00ff"},
		{"undefined payload", "83 11 02 f7"},
		{"unknown tag in payload", "83 11 02 c2 41 00"},
		{"trailing bytes", "820401 00"},
		{"too few fields", "82 11 02"},
		{"too many fields", "84 11 02 f6 f6"},
		{"call id negative", "83 11 20 f6"},
		{"ping nonce null", "82 07 f6"},
		{"hello no versions", "88 00 80 a0 f6 f6 f6 a0 f4"},
		{"hello versions null", "88 00 f6 a0 f6 f6 f6 a0 f4"},
		{"hello optimistic null", "88 00 8101 a0 f6 f6 f6 a0 f6"},
		{"hello caps non-text key", "88 00 8101 a1 01 01 f6 f6 f6 a0 f4"},
		{"hello auth 1 element", "88 00 8101 a0 81 6161 f6 f6 a0 f4"},
		{"hello client schema form 1", "88 00 8101 a0 f6 f6 83 01 40 80 a0 f4"},
		{"hello params non-uint", "88 00 8101 a0 f6 f6 f6 a1 6a6d617853747265616d73 20 f4"},
		{"welcome unknown offer", "87 01 01 a0 40 a0 82 04 40 a0"},
		{"welcome offer wrong length", "87 01 01 a0 40 a0 83 00 40 40 a0"},
		{"goaway app status", "85 09 1840 60 f6 f6"},
		{"cancel app status", "83 17 02 1840"},
		{"authstatus app status", "83 06 20 f6"},
		{"authstatus expires not tag", "83 06 00 00"},
		{"request metadata key not symbol", "86 10 02 10 01 a1 20 00 f6"},
		{"request metadata not map", "86 10 02 10 01 80 f6"},
		{"bytes data text", "85 19 02 00 6161 f5"},
		{"bytes fin null", "85 19 02 00 41 00 f6"},
		{"progress note int", "85 15 02 00 f6 00"},
		{"error message null", "85 14 02 0c f6 f6"},
	}
	for _, tc := range tests {
		_, err := Decode(unhex(tc.in))
		if err == nil {
			t.Errorf("%s: accepted %s", tc.name, tc.in)
			continue
		}
		var de *DecodeError
		var uk *UnknownKindError
		if !errors.As(err, &de) && !errors.As(err, &uk) {
			t.Errorf("%s: error type %T", tc.name, err)
		}
	}
	// nesting limit applies to the whole message, whose own array is level 1
	ok := append(unhex("83 11 02"), append(bytes.Repeat([]byte{0x81}, 63), 0x00)...)
	if _, err := Decode(ok); err != nil {
		t.Errorf("message nested 64 levels rejected: %v", err)
	}
	deep := append(unhex("83 11 02"), append(bytes.Repeat([]byte{0x81}, 64), 0x00)...)
	if _, err := Decode(deep); err == nil {
		t.Error("message nested 65 levels accepted")
	}
	if _, err := (DecodeOptions{CBOR: cbor.Options{MaxDepth: 100}}).Decode(deep); err != nil {
		t.Errorf("MaxDepth option: %v", err)
	}
}

func TestMetadataAccessorErrors(t *testing.T) {
	md := Metadata{
		SigilKey(KeyDeadline):  cbor.AppendText(nil, "soon"),
		SigilKey(KeyTrace):     cbor.AppendBytes(nil, []byte{1}),
		SigilKey(KeyCredit):    cbor.AppendInt(nil, -1),
		SigilKey(KeyContext):   cbor.AppendUint(nil, 1),
		SigilKey(KeyPrincipal): cbor.AppendUint(nil, 1),
	}
	if _, ok, err := md.Deadline(); !ok || !errors.Is(err, ErrMetadataValue) {
		t.Error("deadline")
	}
	if _, _, err := md.Trace(); err == nil {
		t.Error("trace length")
	}
	if _, _, err := md.Credit(); err == nil {
		t.Error("credit")
	}
	if _, _, err := md.Context(); err == nil {
		t.Error("context")
	}
	if _, _, err := md.Principal(); err == nil {
		t.Error("principal")
	}
	var empty Metadata
	if _, ok, err := empty.Deadline(); ok || err != nil {
		t.Error("absent deadline")
	}
	if err := empty.SetTrace([]byte{1}); err == nil {
		t.Error("SetTrace accepted 1 byte")
	}
	c := md.Clone()
	c.Delete(SigilKey(KeyDeadline))
	if _, ok := md[SigilKey(KeyDeadline)]; !ok || len(c) != 4 {
		t.Error("Clone/Delete")
	}
	// keys in deterministic order: uints before text, shorter text first
	m := Metadata{TextKey("bb"): cbor.Null, TextKey("a"): cbor.Null, SigilKey(300): cbor.Null, SigilKey(32): cbor.Null}
	if got := m.AppendTo(nil); !bytes.Equal(got, unhex("a4 1820 f6 19012c f6 6161 f6 626262 f6")) {
		t.Errorf("order %x", got)
	}
}

func TestParamsLimits(t *testing.T) {
	var p Params
	if l := p.Limits(Server); l != DefaultLimits(Server) || l.MaxStreams != 16 || l.BelowDefaults(Server) {
		t.Errorf("welcome defaults %+v", l)
	}
	if l := p.Limits(Client); l.MaxStreams != 4 {
		t.Errorf("hello defaults %+v", l)
	}
	for _, k := range paramKeys {
		p.Set(k, 7)
	}
	l := p.Limits(Server)
	if l.MaxMessageSize != 7 || l.MaxInlineBytes != 7 || l.MaxConcurrentCalls != 7 || l.MaxStreams != 7 ||
		l.SharedCredit != 7 || l.LeaseCredit != 7 || l.IdleTimeoutMs != 7 {
		t.Errorf("limits %+v", l)
	}
	if IdleTimeout(l, DefaultLimits(Client)) != 7 || IdleTimeout(DefaultLimits(Client), l) != 7 {
		t.Error("IdleTimeout")
	}
	p.Unset(ParamMaxStreams)
	if _, ok := p.Get(ParamMaxStreams); ok || p.Len() != 6 {
		t.Error("Unset")
	}
}

func TestCreditWindow(t *testing.T) {
	w := NewCreditWindow(100)
	steps := []struct {
		op      string
		n       uint64
		wantErr bool
		after   int64
	}{
		{"consume", 59, false, 41},
		{"consume", 59, false, -18},
		{"consume", 1, true, -18},
		{"consume", 0, false, -18}, // messages that count nothing always pass
		{"grant", 50, false, 32},
		{"consume", 59, false, -27},
		{"grant", 27, false, 0},
		{"consume", 1, true, 0},
		{"grant", 1 << 63, false, 1<<63 - 1},
		{"grant", 1 << 63, false, 1<<63 - 1},
		{"consume", 1 << 63, false, -1},
	}
	for i, s := range steps {
		var err error
		if s.op == "grant" {
			w.Grant(s.n)
		} else {
			err = w.Consume(s.n)
		}
		if (err != nil) != s.wantErr || w.Remaining() != s.after {
			t.Fatalf("step %d: err %v remaining %d, want %v %d", i, err, w.Remaining(), s.wantErr, s.after)
		}
		if err != nil && !errors.Is(err, ErrNoCredit) {
			t.Fatal("error does not wrap ErrNoCredit")
		}
	}
	if InitialCredit(DefaultLimits(Server), true, nil) != DefaultLeaseCredit ||
		InitialCredit(DefaultLimits(Server), false, nil) != DefaultSharedCredit ||
		InitialCredit(DefaultLimits(Server), true, u64(5)) != 5 {
		t.Error("InitialCredit")
	}
}

func TestCountedBytes(t *testing.T) {
	for _, m := range sampleMessages() {
		b := Encode(m)
		want := uint64(0)
		switch x := m.(type) {
		case *Item, *Progress:
			want = uint64(len(b))
		case *Bytes:
			want = uint64(len(x.Data))
		}
		if got := CountedBytes(m, len(b)); got != want {
			t.Errorf("%v: %d, want %d", m.Kind(), got, want)
		}
		if got, err := CountedBytesRaw(b); err != nil || got != want {
			t.Errorf("%v raw: %d %v", m.Kind(), got, err)
		}
	}
}

func TestRelayErrors(t *testing.T) {
	if _, err := RewriteCallID(Encode(&Request{CallID: 2}), 3); err == nil {
		t.Error("RewriteCallID on a Request")
	}
	if _, err := RewriteCallID(Encode(&Ping{Nonce: 1}), 3); err == nil {
		t.Error("RewriteCallID on Ping")
	}
	if _, err := RewriteCallID(unhex("81 11"), 3); err == nil {
		t.Error("RewriteCallID without call id")
	}
	if k, id, err := PeekCall(Encode(&Ping{Nonce: 9})); err != nil || k != KindPing || id != 0 {
		t.Error("PeekCall on Ping")
	}
	if _, _, err := PeekCall(unhex("80")); err == nil {
		t.Error("PeekCall on []")
	}
	r := &Request{CallID: 2, FacetID: 17, MethodID: 5, Input: unhex("8218406553616c6573")}
	f, _ := Decode(ForwardRequest(r, 1, 16, nil))
	fr := f.(*Request)
	if fr.CallID != 1 || fr.FacetID != 16 || fr.MethodID != 5 || !bytes.Equal(fr.Input, r.Input) {
		t.Errorf("forwarded %+v", fr)
	}
}

func TestCallIDs(t *testing.T) {
	if CallerOf(2) != Client || CallerOf(3) != Server || !ValidCallID(Server, 0) || ValidCallID(Client, 3) {
		t.Error("call id parity")
	}
	h := &Hello{Versions: []uint64{1}, Optimistic: true}
	if h.CheckOptimistic() == nil {
		t.Error("optimistic without known schema")
	}
	h.KnownSchema = []byte{1}
	if h.CheckOptimistic() != nil {
		t.Error("valid optimistic Hello rejected")
	}
}

func TestStrings(t *testing.T) {
	if KindHello.String() != "Hello" || Kind(99).String() != "Kind(99)" || Kind(26).Known() {
		t.Error("Kind.String")
	}
	if Client.String() != "client" || Server.String() != "server" || OwnerProfile.String() != "profile" {
		t.Error("Role/Owner String")
	}
	if SigilKey(32).String() != "32" || TextKey("a").String() != `"a"` {
		t.Error("Key.String")
	}
	e := &UnknownKindError{Kind: 26}
	de := &DecodeError{Err: io.EOF}
	if e.Error() == "" || de.Error() == "" || (&TooLargeError{1, 2}).Error() == "" {
		t.Error("errors")
	}
}

func FuzzDecode(f *testing.F) {
	for _, m := range sampleMessages() {
		f.Add(Encode(m))
	}
	f.Add(unhex("86100210190412a0826873657474696e6773f5"))
	f.Add(unhex("831102f6"))
	for _, b := range fuzzseed.Hex("framing.json", "handshake.json", "calls.json", "credit.json", "hub.json") {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = PeekCall(b)
		_, _ = CountedBytesRaw(b)
		_, _, _ = ParseVarint(b)
		_, _ = NewFrameReader(bytes.NewReader(b), 1<<16).ReadFrame()
		m, err := Decode(b)
		if err != nil {
			if m != nil {
				t.Fatal("message with error")
			}
			return
		}
		e1 := Encode(m)
		m2, err := Decode(e1)
		if err != nil {
			t.Fatalf("re-encoding %x of %x does not decode: %v", e1, b, err)
		}
		if e2 := Encode(m2); !bytes.Equal(e1, e2) {
			t.Fatalf("encoding not stable: %x vs %x", e1, e2)
		}
		checkFields(t, m)
		if cm, ok := m.(CallMessage); ok {
			if n, err := CountedBytesRaw(b); err != nil || n != CountedBytes(m, len(b)) {
				t.Fatalf("CountedBytesRaw %d %v", n, err)
			}
			if m.Kind() != KindRequest {
				r, err := RewriteCallID(b, cm.Call()+1)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Decode(r); err != nil {
					t.Fatalf("rewritten message invalid: %v", err)
				}
			}
		}
	})
}

func TestParamsValidate(t *testing.T) {
	var p Params
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.Set(ParamMaxStreams, 0)
	p.Set(ParamIdleTimeoutMs, 0)
	p.Extra = map[string]cbor.Raw{"x-future": cbor.AppendUint(nil, 1)}
	if err := ValidateParams(p); err != nil {
		t.Fatalf("keys without a minimum: %v", err)
	}
	for _, k := range []string{ParamMaxMessageSize, ParamMaxInlineBytes, ParamSharedCredit, ParamLeaseCredit, ParamMaxConcurrentCalls} {
		min, ok := ParamMinimum(k)
		if !ok {
			t.Fatalf("%s has no minimum", k)
		}
		q := Params{}
		q.Set(k, min)
		if err := q.Validate(); err != nil {
			t.Fatalf("%s = %d: %v", k, min, err)
		}
		q.Set(k, min-1)
		var pe *ParamError
		if err := q.Validate(); !errors.As(err, &pe) || pe.Key != k || pe.Min != min || pe.Error() == "" {
			t.Fatalf("%s = %d: %v", k, min-1, err)
		}
	}
	if _, ok := ParamMinimum(ParamMaxStreams); ok {
		t.Fatal("maxStreams has no minimum")
	}
}

func TestCanSendCounted(t *testing.T) {
	w := NewCreditWindow(10)
	if err := w.Consume(15); err != nil {
		t.Fatal(err)
	}
	if w.CanSend() || w.CanSendCounted(1) || !w.CanSendCounted(0) || w.Consume(0) != nil {
		t.Fatalf("zero-byte messages are never held back (remaining %d)", w.Remaining())
	}
}
