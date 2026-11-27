package wire

import (
	"errors"
	"fmt"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
)

// Message is one Sparrow message. Every message is a fixed CBOR array whose
// first element is its kind; every field is present, null when empty.
type Message interface {
	Kind() Kind
	// AppendTo appends the message's CBOR encoding.
	AppendTo(dst []byte) []byte
}

// Encode returns the CBOR encoding of m.
func Encode(m Message) []byte { return m.AppendTo(nil) }

// CallMessage is a call message (kinds 16-25).
type CallMessage interface {
	Message
	Call() uint64
}

// Auth is a credential: [scheme, credentials].
type Auth struct {
	Scheme      string
	Credentials cbor.Raw
}

// InlineSchema is the client schema in Hello: [2, hash, schema].
type InlineSchema struct {
	Hash   []byte
	Schema cbor.Raw
}

// OfferKind selects a schema offer (section 5.4).
type OfferKind uint64

const (
	OfferUnchanged  OfferKind = 0 // [0, hash]
	OfferDelta      OfferKind = 1 // [1, hash, from, delta]
	OfferFull       OfferKind = 2 // [2, hash, schema]
	OfferOutOfBand  OfferKind = 3 // [3, hash, location]
	offerKindsCount           = 4
)

// SchemaOffer is Welcome.server_schema.
type SchemaOffer struct {
	Kind     OfferKind
	Hash     []byte
	From     []byte   // OfferDelta
	Delta    cbor.Raw // OfferDelta
	Schema   cbor.Raw // OfferFull
	Location string   // OfferOutOfBand
}

// Hello = [0, versions, caps, auth / null, known_schema / null,
// client_schema / null, params, optimistic].
type Hello struct {
	Versions     []uint64
	Caps         TextMap
	Auth         *Auth
	KnownSchema  []byte // nil = null
	ClientSchema *InlineSchema
	Params       Params
	Optimistic   bool
}

// Welcome = [1, version, caps, session_id, props, server_schema, params].
type Welcome struct {
	Version      uint64
	Caps         TextMap
	SessionID    []byte
	Props        TextMap
	ServerSchema SchemaOffer
	Params       Params
}

// Ready = [2, schema_hash].
type Ready struct{ SchemaHash []byte }

// SchemaUpdate = [3, epoch, hash, delta].
type SchemaUpdate struct {
	Epoch uint64
	Hash  []byte
	Delta cbor.Raw
}

// SchemaAck = [4, epoch].
type SchemaAck struct{ Epoch uint64 }

// AuthRefresh = [5, auth].
type AuthRefresh struct{ Auth Auth }

// AuthStatus = [6, status, expires_at: timestamp / null].
type AuthStatus struct {
	Status    uint64
	ExpiresAt *cbor.Time
}

// Ping = [7, nonce].
type Ping struct{ Nonce uint64 }

// Pong = [8, nonce].
type Pong struct{ Nonce uint64 }

// GoAway = [9, status, reason, retry_after_ms / null, versions / null].
type GoAway struct {
	Status       uint64
	Reason       string
	RetryAfterMs *uint64
	Versions     []uint64 // nil = null
}

// Request = [16, call_id, facet_id, method_id, metadata, input].
type Request struct {
	CallID, FacetID, MethodID uint64
	Metadata                  Metadata
	Input                     cbor.Raw
}

// Response = [17, call_id, output].
type Response struct {
	CallID uint64
	Output cbor.Raw
}

// Item = [18, call_id, value].
type Item struct {
	CallID uint64
	Value  cbor.Raw
}

// End = [19, call_id, trailers].
type End struct {
	CallID   uint64
	Trailers Metadata
}

// Error = [20, call_id, status, message, details / null].
type Error struct {
	CallID  uint64
	Status  uint64
	Message string
	Details cbor.Raw // nil = null
}

// Progress = [21, call_id, done, total / null, note / null].
type Progress struct {
	CallID uint64
	Done   uint64
	Total  *uint64
	Note   *string
}

// Headers = [22, call_id, metadata].
type Headers struct {
	CallID   uint64
	Metadata Metadata
}

// Cancel = [23, call_id, status].
type Cancel struct {
	CallID uint64
	Status uint64
}

// Credit = [24, call_id, amount].
type Credit struct {
	CallID uint64
	Amount uint64
}

// Bytes = [25, call_id, token, data, fin].
type Bytes struct {
	CallID uint64
	Token  uint64
	Data   []byte
	Fin    bool
}

func (*Hello) Kind() Kind        { return KindHello }
func (*Welcome) Kind() Kind      { return KindWelcome }
func (*Ready) Kind() Kind        { return KindReady }
func (*SchemaUpdate) Kind() Kind { return KindSchemaUpdate }
func (*SchemaAck) Kind() Kind    { return KindSchemaAck }
func (*AuthRefresh) Kind() Kind  { return KindAuthRefresh }
func (*AuthStatus) Kind() Kind   { return KindAuthStatus }
func (*Ping) Kind() Kind         { return KindPing }
func (*Pong) Kind() Kind         { return KindPong }
func (*GoAway) Kind() Kind       { return KindGoAway }
func (*Request) Kind() Kind      { return KindRequest }
func (*Response) Kind() Kind     { return KindResponse }
func (*Item) Kind() Kind         { return KindItem }
func (*End) Kind() Kind          { return KindEnd }
func (*Error) Kind() Kind        { return KindError }
func (*Progress) Kind() Kind     { return KindProgress }
func (*Headers) Kind() Kind      { return KindHeaders }
func (*Cancel) Kind() Kind       { return KindCancel }
func (*Credit) Kind() Kind       { return KindCredit }
func (*Bytes) Kind() Kind        { return KindBytes }

func (m *Request) Call() uint64  { return m.CallID }
func (m *Response) Call() uint64 { return m.CallID }
func (m *Item) Call() uint64     { return m.CallID }
func (m *End) Call() uint64      { return m.CallID }
func (m *Error) Call() uint64    { return m.CallID }
func (m *Progress) Call() uint64 { return m.CallID }
func (m *Headers) Call() uint64  { return m.CallID }
func (m *Cancel) Call() uint64   { return m.CallID }
func (m *Credit) Call() uint64   { return m.CallID }
func (m *Bytes) Call() uint64    { return m.CallID }

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

func env(dst []byte, k Kind, n int) []byte {
	return cbor.AppendUint(cbor.AppendArrayHead(dst, n), uint64(k))
}

func appendBytesOrNull(dst, b []byte) []byte {
	if b == nil {
		return cbor.AppendNull(dst)
	}
	return cbor.AppendBytes(dst, b)
}

func appendUints(dst []byte, xs []uint64) []byte {
	dst = cbor.AppendArrayHead(dst, len(xs))
	for _, x := range xs {
		dst = cbor.AppendUint(dst, x)
	}
	return dst
}

func appendUintOrNull(dst []byte, p *uint64) []byte {
	if p == nil {
		return cbor.AppendNull(dst)
	}
	return cbor.AppendUint(dst, *p)
}

func (a *Auth) appendTo(dst []byte) []byte {
	dst = cbor.AppendText(cbor.AppendArrayHead(dst, 2), a.Scheme)
	return cbor.AppendRaw(dst, a.Credentials)
}

func (m *Hello) AppendTo(dst []byte) []byte {
	dst = env(dst, KindHello, 8)
	dst = appendUints(dst, m.Versions)
	dst = m.Caps.AppendTo(dst)
	if m.Auth == nil {
		dst = cbor.AppendNull(dst)
	} else {
		dst = m.Auth.appendTo(dst)
	}
	dst = appendBytesOrNull(dst, m.KnownSchema)
	if m.ClientSchema == nil {
		dst = cbor.AppendNull(dst)
	} else {
		dst = cbor.AppendUint(cbor.AppendArrayHead(dst, 3), 2)
		dst = cbor.AppendBytes(dst, m.ClientSchema.Hash)
		dst = cbor.AppendRaw(dst, m.ClientSchema.Schema)
	}
	dst = m.Params.AppendTo(dst)
	return cbor.AppendBool(dst, m.Optimistic)
}

func (o *SchemaOffer) appendTo(dst []byte) []byte {
	switch o.Kind {
	case OfferUnchanged:
		dst = cbor.AppendUint(cbor.AppendArrayHead(dst, 2), 0)
		return cbor.AppendBytes(dst, o.Hash)
	case OfferDelta:
		dst = cbor.AppendUint(cbor.AppendArrayHead(dst, 4), 1)
		dst = cbor.AppendBytes(cbor.AppendBytes(dst, o.Hash), o.From)
		return cbor.AppendRaw(dst, o.Delta)
	case OfferFull:
		dst = cbor.AppendUint(cbor.AppendArrayHead(dst, 3), 2)
		return cbor.AppendRaw(cbor.AppendBytes(dst, o.Hash), o.Schema)
	default:
		dst = cbor.AppendUint(cbor.AppendArrayHead(dst, 3), uint64(o.Kind))
		return cbor.AppendText(cbor.AppendBytes(dst, o.Hash), o.Location)
	}
}

func (m *Welcome) AppendTo(dst []byte) []byte {
	dst = env(dst, KindWelcome, 7)
	dst = cbor.AppendUint(dst, m.Version)
	dst = m.Caps.AppendTo(dst)
	dst = cbor.AppendBytes(dst, m.SessionID)
	dst = m.Props.AppendTo(dst)
	dst = m.ServerSchema.appendTo(dst)
	return m.Params.AppendTo(dst)
}

func (m *Ready) AppendTo(dst []byte) []byte {
	return cbor.AppendBytes(env(dst, KindReady, 2), m.SchemaHash)
}

func (m *SchemaUpdate) AppendTo(dst []byte) []byte {
	dst = cbor.AppendUint(env(dst, KindSchemaUpdate, 4), m.Epoch)
	return cbor.AppendRaw(cbor.AppendBytes(dst, m.Hash), m.Delta)
}

func (m *SchemaAck) AppendTo(dst []byte) []byte {
	return cbor.AppendUint(env(dst, KindSchemaAck, 2), m.Epoch)
}

func (m *AuthRefresh) AppendTo(dst []byte) []byte {
	return m.Auth.appendTo(env(dst, KindAuthRefresh, 2))
}

func (m *AuthStatus) AppendTo(dst []byte) []byte {
	dst = cbor.AppendUint(env(dst, KindAuthStatus, 3), m.Status)
	if m.ExpiresAt == nil {
		return cbor.AppendNull(dst)
	}
	return cbor.AppendTime(dst, *m.ExpiresAt)
}

func (m *Ping) AppendTo(dst []byte) []byte { return cbor.AppendUint(env(dst, KindPing, 2), m.Nonce) }
func (m *Pong) AppendTo(dst []byte) []byte { return cbor.AppendUint(env(dst, KindPong, 2), m.Nonce) }

func (m *GoAway) AppendTo(dst []byte) []byte {
	dst = cbor.AppendUint(env(dst, KindGoAway, 5), m.Status)
	dst = cbor.AppendText(dst, m.Reason)
	dst = appendUintOrNull(dst, m.RetryAfterMs)
	if m.Versions == nil {
		return cbor.AppendNull(dst)
	}
	return appendUints(dst, m.Versions)
}

func (m *Request) AppendTo(dst []byte) []byte {
	dst = cbor.AppendUint(env(dst, KindRequest, 6), m.CallID)
	dst = cbor.AppendUint(cbor.AppendUint(dst, m.FacetID), m.MethodID)
	return cbor.AppendRaw(m.Metadata.AppendTo(dst), m.Input)
}

func (m *Response) AppendTo(dst []byte) []byte {
	return cbor.AppendRaw(cbor.AppendUint(env(dst, KindResponse, 3), m.CallID), m.Output)
}

func (m *Item) AppendTo(dst []byte) []byte {
	return cbor.AppendRaw(cbor.AppendUint(env(dst, KindItem, 3), m.CallID), m.Value)
}

func (m *End) AppendTo(dst []byte) []byte {
	return m.Trailers.AppendTo(cbor.AppendUint(env(dst, KindEnd, 3), m.CallID))
}

func (m *Error) AppendTo(dst []byte) []byte {
	dst = cbor.AppendUint(cbor.AppendUint(env(dst, KindError, 5), m.CallID), m.Status)
	return cbor.AppendRaw(cbor.AppendText(dst, m.Message), m.Details)
}

func (m *Progress) AppendTo(dst []byte) []byte {
	dst = cbor.AppendUint(cbor.AppendUint(env(dst, KindProgress, 5), m.CallID), m.Done)
	dst = appendUintOrNull(dst, m.Total)
	if m.Note == nil {
		return cbor.AppendNull(dst)
	}
	return cbor.AppendText(dst, *m.Note)
}

func (m *Headers) AppendTo(dst []byte) []byte {
	return m.Metadata.AppendTo(cbor.AppendUint(env(dst, KindHeaders, 3), m.CallID))
}

func (m *Cancel) AppendTo(dst []byte) []byte {
	return cbor.AppendUint(cbor.AppendUint(env(dst, KindCancel, 3), m.CallID), m.Status)
}

func (m *Credit) AppendTo(dst []byte) []byte {
	return cbor.AppendUint(cbor.AppendUint(env(dst, KindCredit, 3), m.CallID), m.Amount)
}

func (m *Bytes) AppendTo(dst []byte) []byte {
	dst = cbor.AppendUint(cbor.AppendUint(env(dst, KindBytes, 5), m.CallID), m.Token)
	return cbor.AppendBool(cbor.AppendBytes(dst, m.Data), m.Fin)
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

// DecodeError is a malformed message; it maps to status protocol_error.
type DecodeError struct {
	Kind Kind // valid if KindKnown
	// KindKnown is false when the envelope itself could not be read.
	KindKnown bool
	Err       error
}

func (e *DecodeError) Error() string {
	if e.KindKnown {
		return fmt.Sprintf("wire: malformed %v: %v", e.Kind, e.Err)
	}
	return fmt.Sprintf("wire: malformed message: %v", e.Err)
}

func (e *DecodeError) Unwrap() error { return e.Err }

// UnknownKindError is returned for a kind this revision does not define.
// Action says whether to ignore the message or close the session with
// protocol_error (section 3.3). Raw is the whole message.
type UnknownKindError struct {
	Kind   uint64
	Owner  Owner
	Action Action
	Raw    cbor.Raw
}

func (e *UnknownKindError) Error() string {
	return fmt.Sprintf("wire: unknown message kind %d (%v range, %v)", e.Kind, e.Owner, e.Action)
}

// IsIgnorable reports whether err is an UnknownKindError whose kind falls
// in an ignorable range.
func IsIgnorable(err error) bool {
	var u *UnknownKindError
	return errors.As(err, &u) && u.Action == Ignore
}

// DecodeOptions tune Decode.
type DecodeOptions struct {
	// CBOR selects the CBOR rules (depth limit, extra profile tags, strict
	// preferred serialization). The zero value is the section 3.1 profile.
	CBOR cbor.Options
}

// Decode validates b against the CBOR rules of section 3.1 and decodes it.
// Raw fields of the result are views into b.
func Decode(b []byte) (Message, error) { return DecodeOptions{}.Decode(b) }

// Decode decodes one message with these options.
func (o DecodeOptions) Decode(b []byte) (Message, error) {
	if err := cbor.Validate(b, o.CBOR); err != nil {
		return nil, &DecodeError{Err: err}
	}
	d := cbor.NewDecoder(b)
	n, err := d.ArrayHead()
	if err != nil {
		return nil, &DecodeError{Err: fmt.Errorf("message is not an array: %w", err)}
	}
	if n == 0 {
		return nil, &DecodeError{Err: errors.New("empty envelope")}
	}
	k, err := d.Uint()
	if err != nil {
		return nil, &DecodeError{Err: fmt.Errorf("kind: %w", err)}
	}
	kind := Kind(k)
	dec, ok := decoders[kind]
	if !ok {
		owner, action := KindRange(k)
		return nil, &UnknownKindError{Kind: k, Owner: owner, Action: action, Raw: b}
	}
	f := &fields{d: d}
	m := dec(f)
	if f.err == nil && n != f.n+1 {
		f.err = fmt.Errorf("envelope has %d elements, want %d", n, f.n+1)
	}
	if f.err != nil {
		return nil, &DecodeError{Kind: kind, KindKnown: true, Err: f.err}
	}
	return m, nil
}

// fields reads envelope fields in order and records the first error.
type fields struct {
	d   *cbor.Decoder
	n   int // fields read after the kind
	err error
}

func (f *fields) fail(name string, err error) {
	if f.err == nil && err != nil {
		f.err = fmt.Errorf("%s: %w", name, err)
	}
}

func (f *fields) ok() bool {
	if f.err != nil {
		return false
	}
	if f.d.Done() {
		f.err = errors.New("envelope has too few elements")
		return false
	}
	f.n++
	return true
}

func (f *fields) uint(name string) uint64 {
	if !f.ok() {
		return 0
	}
	v, err := f.d.Uint()
	f.fail(name, err)
	return v
}

func (f *fields) coreStatus(name string) uint64 {
	v := f.uint(name)
	if f.err == nil && v > 31 {
		f.err = fmt.Errorf("%s: %d is not a core status code", name, v)
	}
	return v
}

func (f *fields) uintOrNull(name string) *uint64 {
	if !f.ok() {
		return nil
	}
	if f.d.PeekNull() {
		_ = f.d.Null()
		return nil
	}
	v, err := f.d.Uint()
	f.fail(name, err)
	return &v
}

func (f *fields) bool(name string) bool {
	if !f.ok() {
		return false
	}
	v, err := f.d.Bool()
	f.fail(name, err)
	return v
}

func (f *fields) text(name string) string {
	if !f.ok() {
		return ""
	}
	v, err := f.d.Text()
	f.fail(name, err)
	return v
}

func (f *fields) textOrNull(name string) *string {
	if !f.ok() {
		return nil
	}
	if f.d.PeekNull() {
		_ = f.d.Null()
		return nil
	}
	v, err := f.d.Text()
	f.fail(name, err)
	return &v
}

func (f *fields) bytes(name string) []byte {
	if !f.ok() {
		return nil
	}
	v, err := f.d.Bytes()
	f.fail(name, err)
	return v
}

func (f *fields) bytesOrNull(name string) []byte {
	if !f.ok() {
		return nil
	}
	if f.d.PeekNull() {
		_ = f.d.Null()
		return nil
	}
	v, err := f.d.Bytes()
	f.fail(name, err)
	return v
}

func (f *fields) raw(name string) cbor.Raw {
	if !f.ok() {
		return nil
	}
	v, err := f.d.Raw()
	f.fail(name, err)
	return v
}

func (f *fields) rawOrNull(name string) cbor.Raw {
	if !f.ok() {
		return nil
	}
	v, err := f.d.RawOrNull()
	f.fail(name, err)
	return v
}

func (f *fields) metadata(name string) Metadata {
	if !f.ok() {
		return nil
	}
	v, err := readMetadata(f.d)
	f.fail(name, err)
	return v
}

func (f *fields) textMap(name string) TextMap {
	if !f.ok() {
		return nil
	}
	v, err := readTextMap(f.d)
	f.fail(name, err)
	return v
}

func (f *fields) params(name string) Params {
	if !f.ok() {
		return Params{}
	}
	v, err := readParams(f.d)
	f.fail(name, err)
	return v
}

func (f *fields) uints(name string, nullable, nonEmpty bool) []uint64 {
	if !f.ok() {
		return nil
	}
	if nullable && f.d.PeekNull() {
		_ = f.d.Null()
		return nil
	}
	n, err := f.d.ArrayHead()
	if err != nil {
		f.fail(name, err)
		return nil
	}
	if nonEmpty && n == 0 {
		f.fail(name, errors.New("must not be empty"))
		return nil
	}
	out := make([]uint64, n)
	for i := range out {
		if out[i], err = f.d.Uint(); err != nil {
			f.fail(name, err)
			return nil
		}
	}
	return out
}

func (f *fields) auth(name string, nullable bool) *Auth {
	if !f.ok() {
		return nil
	}
	if nullable && f.d.PeekNull() {
		_ = f.d.Null()
		return nil
	}
	n, err := f.d.ArrayHead()
	if err == nil && n != 2 {
		err = fmt.Errorf("auth has %d elements, want 2", n)
	}
	if err != nil {
		f.fail(name, err)
		return nil
	}
	a := &Auth{}
	if a.Scheme, err = f.d.Text(); err != nil {
		f.fail(name, err)
		return nil
	}
	a.Credentials, err = f.d.Raw()
	f.fail(name, err)
	return a
}

func (f *fields) inlineSchema(name string) *InlineSchema {
	if !f.ok() {
		return nil
	}
	if f.d.PeekNull() {
		_ = f.d.Null()
		return nil
	}
	n, err := f.d.ArrayHead()
	if err == nil && n != 3 {
		err = fmt.Errorf("has %d elements, want 3", n)
	}
	var tag uint64
	if err == nil {
		tag, err = f.d.Uint()
	}
	if err == nil && tag != 2 {
		err = fmt.Errorf("form %d, want 2 (inline)", tag)
	}
	s := &InlineSchema{}
	if err == nil {
		s.Hash, err = f.d.Bytes()
	}
	if err == nil {
		s.Schema, err = f.d.Raw()
	}
	if err != nil {
		f.fail(name, err)
		return nil
	}
	return s
}

func (f *fields) offer(name string) SchemaOffer {
	var o SchemaOffer
	if !f.ok() {
		return o
	}
	n, err := f.d.ArrayHead()
	var k uint64
	if err == nil && n == 0 {
		err = errors.New("empty schema offer")
	}
	if err == nil {
		k, err = f.d.Uint()
	}
	want := map[uint64]int{0: 2, 1: 4, 2: 3, 3: 3}
	if err == nil {
		if w, known := want[k]; !known {
			err = fmt.Errorf("unknown schema offer %d", k)
		} else if n != w {
			err = fmt.Errorf("offer %d has %d elements, want %d", k, n, w)
		}
	}
	if err == nil {
		o.Kind = OfferKind(k)
		o.Hash, err = f.d.Bytes()
	}
	if err == nil {
		switch o.Kind {
		case OfferDelta:
			if o.From, err = f.d.Bytes(); err == nil {
				o.Delta, err = f.d.Raw()
			}
		case OfferFull:
			o.Schema, err = f.d.Raw()
		case OfferOutOfBand:
			o.Location, err = f.d.Text()
		}
	}
	f.fail(name, err)
	return o
}

func (f *fields) timeOrNull(name string) *cbor.Time {
	if !f.ok() {
		return nil
	}
	if f.d.PeekNull() {
		_ = f.d.Null()
		return nil
	}
	t, err := f.d.Time()
	f.fail(name, err)
	return &t
}

var decoders = map[Kind]func(f *fields) Message{
	KindHello: func(f *fields) Message {
		return &Hello{
			Versions:     f.uints("versions", false, true),
			Caps:         f.textMap("caps"),
			Auth:         f.auth("auth", true),
			KnownSchema:  f.bytesOrNull("known_schema"),
			ClientSchema: f.inlineSchema("client_schema"),
			Params:       f.params("params"),
			Optimistic:   f.bool("optimistic"),
		}
	},
	KindWelcome: func(f *fields) Message {
		return &Welcome{
			Version:      f.uint("version"),
			Caps:         f.textMap("caps"),
			SessionID:    f.bytes("session_id"),
			Props:        f.textMap("props"),
			ServerSchema: f.offer("server_schema"),
			Params:       f.params("params"),
		}
	},
	KindReady: func(f *fields) Message { return &Ready{SchemaHash: f.bytes("schema_hash")} },
	KindSchemaUpdate: func(f *fields) Message {
		return &SchemaUpdate{Epoch: f.uint("epoch"), Hash: f.bytes("hash"), Delta: f.raw("delta")}
	},
	KindSchemaAck: func(f *fields) Message { return &SchemaAck{Epoch: f.uint("epoch")} },
	KindAuthRefresh: func(f *fields) Message {
		a := f.auth("auth", false)
		if a == nil {
			return &AuthRefresh{}
		}
		return &AuthRefresh{Auth: *a}
	},
	KindAuthStatus: func(f *fields) Message {
		return &AuthStatus{Status: f.coreStatus("status"), ExpiresAt: f.timeOrNull("expires_at")}
	},
	KindPing: func(f *fields) Message { return &Ping{Nonce: f.uint("nonce")} },
	KindPong: func(f *fields) Message { return &Pong{Nonce: f.uint("nonce")} },
	KindGoAway: func(f *fields) Message {
		return &GoAway{
			Status:       f.coreStatus("status"),
			Reason:       f.text("reason"),
			RetryAfterMs: f.uintOrNull("retry_after_ms"),
			Versions:     f.uints("versions", true, false),
		}
	},
	KindRequest: func(f *fields) Message {
		return &Request{
			CallID:   f.uint("call_id"),
			FacetID:  f.uint("facet_id"),
			MethodID: f.uint("method_id"),
			Metadata: f.metadata("metadata"),
			Input:    f.raw("input"),
		}
	},
	KindResponse: func(f *fields) Message { return &Response{CallID: f.uint("call_id"), Output: f.raw("output")} },
	KindItem:     func(f *fields) Message { return &Item{CallID: f.uint("call_id"), Value: f.raw("value")} },
	KindEnd: func(f *fields) Message {
		return &End{CallID: f.uint("call_id"), Trailers: f.metadata("trailers")}
	},
	KindError: func(f *fields) Message {
		return &Error{
			CallID:  f.uint("call_id"),
			Status:  f.uint("status"),
			Message: f.text("message"),
			Details: f.rawOrNull("details"),
		}
	},
	KindProgress: func(f *fields) Message {
		return &Progress{
			CallID: f.uint("call_id"),
			Done:   f.uint("done"),
			Total:  f.uintOrNull("total"),
			Note:   f.textOrNull("note"),
		}
	},
	KindHeaders: func(f *fields) Message {
		return &Headers{CallID: f.uint("call_id"), Metadata: f.metadata("metadata")}
	},
	KindCancel: func(f *fields) Message {
		return &Cancel{CallID: f.uint("call_id"), Status: f.coreStatus("status")}
	},
	KindCredit: func(f *fields) Message { return &Credit{CallID: f.uint("call_id"), Amount: f.uint("amount")} },
	KindBytes: func(f *fields) Message {
		return &Bytes{
			CallID: f.uint("call_id"),
			Token:  f.uint("token"),
			Data:   f.bytes("data"),
			Fin:    f.bool("fin"),
		}
	},
}
