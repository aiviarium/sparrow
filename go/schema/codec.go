package schema

import (
	"errors"
	"fmt"

	"github.com/aiviarium/sparrow/go/cbor"
)

// DecodeOptions limit what a decoder accepts.
type DecodeOptions struct {
	// MaxBytes rejects larger documents; 0 means no limit. Clients SHOULD
	// cap server schemas at 8 MiB and servers client schemas at 64 KiB.
	MaxBytes int
	// MaxDepth is the CBOR nesting limit; 0 means 64.
	MaxDepth int
}

// Client-side and server-side limits recommended by sections 5.4 and 11.
var (
	ServerSchemaLimits = DecodeOptions{MaxBytes: 8 << 20, MaxDepth: 64}
	ClientSchemaLimits = DecodeOptions{MaxBytes: 64 << 10, MaxDepth: 32}
)

func (o DecodeOptions) check(b []byte) error {
	if o.MaxBytes > 0 && len(b) > o.MaxBytes {
		return errorf(CodeTooLarge, "document of %d bytes exceeds the limit of %d", len(b), o.MaxBytes)
	}
	if err := cbor.Validate(b, cbor.Options{MaxDepth: o.MaxDepth}); err != nil {
		return wrapMalformed(err)
	}
	return nil
}

func wrapMalformed(err error) error {
	var se *Error
	if errors.As(err, &se) {
		return err
	}
	return &Error{Code: CodeMalformed, Detail: err.Error()}
}

// DecodeSchema decodes a schema document. A leading self-described CBOR tag
// (55799), allowed for stored schema files, is skipped. It does not
// validate the schema's rules; call Validate.
func DecodeSchema(b []byte) (*Schema, error) { return DecodeOptions{}.DecodeSchema(b) }

// DecodeSchema decodes a schema document with these limits.
func (o DecodeOptions) DecodeSchema(b []byte) (*Schema, error) {
	b = cbor.StripSelfDescribed(b)
	if err := o.check(b); err != nil {
		return nil, err
	}
	r := &reader{d: cbor.NewDecoder(b)}
	s := r.schema()
	return s, r.finish()
}

// DecodeFacet decodes a single facet.
func DecodeFacet(b []byte) (*Facet, error) {
	if err := (DecodeOptions{}).check(b); err != nil {
		return nil, err
	}
	r := &reader{d: cbor.NewDecoder(b)}
	f := r.facet()
	return f, r.finish()
}

// DecodeInterface decodes an interface.
func DecodeInterface(b []byte) (*Interface, error) {
	if err := (DecodeOptions{}).check(b); err != nil {
		return nil, err
	}
	r := &reader{d: cbor.NewDecoder(b)}
	i := r.iface()
	return i, r.finish()
}

// DecodeDelta decodes a delta.
func DecodeDelta(b []byte) (Delta, error) {
	if err := (DecodeOptions{}).check(b); err != nil {
		return nil, err
	}
	r := &reader{d: cbor.NewDecoder(b)}
	dl := r.delta()
	return dl, r.finish()
}

// DecodeTypeRef decodes a type reference.
func DecodeTypeRef(b []byte) (TypeRef, error) {
	if err := (DecodeOptions{}).check(b); err != nil {
		return TypeRef{}, err
	}
	r := &reader{d: cbor.NewDecoder(b)}
	t := r.typeRef()
	return t, r.finish()
}

// reader decodes schema structures and records the first error.
type reader struct {
	d   *cbor.Decoder
	err error
}

func (r *reader) finish() error {
	if r.err == nil && !r.d.Done() {
		r.err = errorf(CodeMalformed, "trailing data")
	}
	return r.err
}

func (r *reader) fail(err error, what string) {
	if r.err == nil && err != nil {
		r.err = &Error{Code: CodeMalformed, Detail: fmt.Sprintf("%s: %v", what, err)}
	}
}

func (r *reader) array(what string, want ...int) int {
	if r.err != nil {
		return 0
	}
	n, err := r.d.ArrayHead()
	if err != nil {
		r.fail(err, what)
		return 0
	}
	if len(want) > 0 {
		for _, w := range want {
			if n == w {
				return n
			}
		}
		r.fail(fmt.Errorf("array of %d elements, want %v", n, want), what)
		return 0
	}
	return n
}

func (r *reader) uint(what string) uint64 {
	if r.err != nil {
		return 0
	}
	v, err := r.d.Uint()
	r.fail(err, what)
	return v
}

func (r *reader) text(what string) string {
	if r.err != nil {
		return ""
	}
	v, err := r.d.Text()
	r.fail(err, what)
	return v
}

func (r *reader) bytesOrNull(what string) []byte {
	if r.err != nil {
		return nil
	}
	if r.d.PeekNull() {
		_ = r.d.Null()
		return nil
	}
	v, err := r.d.Bytes()
	r.fail(err, what)
	return append([]byte{}, v...)
}

func (r *reader) annotations(what string) Annotations {
	if r.err != nil {
		return nil
	}
	n, err := r.d.MapHead()
	if err != nil {
		r.fail(err, what)
		return nil
	}
	a := make(Annotations, n)
	for i := 0; i < n; i++ {
		k, err := r.d.Text()
		if err != nil {
			r.fail(err, what+" key")
			return nil
		}
		v, err := r.d.Raw()
		if err != nil {
			r.fail(err, what)
			return nil
		}
		a[k] = append(cbor.Raw{}, v...)
	}
	return a
}

func (r *reader) uints(what string) []uint64 {
	n := r.array(what)
	out := make([]uint64, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		out = append(out, r.uint(what))
	}
	return out
}

func (r *reader) schema() *Schema {
	s := &Schema{}
	r.array("schema", 5)
	s.Format = r.uint("schema format")
	if r.err == nil && s.Format != Format {
		r.err = errorf(CodeUnsupportedFormat, "schema format %d, want %d", s.Format, Format)
	}
	s.Name = r.text("schema name")
	s.Version = r.text("schema version")
	n := r.array("facets")
	s.Facets = make([]Facet, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		s.Facets = append(s.Facets, *r.facet())
	}
	s.Annotations = r.annotations("schema annotations")
	return s
}

func (r *reader) facet() *Facet {
	f := &Facet{}
	r.array("facet", 9)
	f.ID = r.uint("facet id")
	f.Name = r.text("facet name")
	f.Version = r.text("facet version")
	f.Types = r.types()
	f.Services = r.services()
	f.Sigils = r.sigils()
	f.Implements = r.bytesOrNull("implements")
	n := r.array("retired")
	f.Retired = make([]Retired, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		r.array("retired entry", 2)
		sp := r.uint("retired space")
		id := r.uint("retired id")
		f.Retired = append(f.Retired, Retired{Space(sp), id})
	}
	f.Annotations = r.annotations("facet annotations")
	return f
}

func (r *reader) iface() *Interface {
	i := &Interface{}
	r.array("interface", 5)
	i.Name = r.text("interface name")
	i.Version = r.text("interface version")
	i.Types = r.types()
	i.Services = r.services()
	i.Sigils = r.sigils()
	return i
}

func (r *reader) types() []TypeDef {
	n := r.array("types")
	out := make([]TypeDef, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		out = append(out, r.typeDef())
	}
	return out
}

func (r *reader) typeDef() TypeDef {
	var t TypeDef
	n := r.array("type-def", 5, 6)
	t.Kind = TypeKind(r.uint("type-def kind"))
	if r.err != nil {
		return t
	}
	want := 5
	if t.Kind == KindStruct {
		want = 6
	}
	if t.Kind > KindAlias {
		r.err = errorf(CodeMalformed, "unknown type-def kind %d", t.Kind)
		return t
	}
	if n != want {
		r.err = errorf(CodeMalformed, "%v type-def has %d elements, want %d", t.Kind, n, want)
		return t
	}
	t.ID = r.uint("type id")
	t.Name = r.text("type name")
	switch t.Kind {
	case KindStruct, KindUnion:
		t.Fields = r.fields()
		if t.Kind == KindStruct {
			t.Flags = r.uint("struct flags")
		}
	case KindEnum:
		t.Values = r.uints("enum values")
	case KindAlias:
		t.Target = r.typeRef()
	}
	t.Annotations = r.annotations("type annotations")
	return t
}

func (r *reader) fields() []Field {
	n := r.array("fields")
	out := make([]Field, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		var f Field
		r.array("field", 5)
		f.Tag = r.uint("field tag")
		f.Name = r.text("field name")
		f.Type = r.typeRef()
		f.Flags = r.uint("field flags")
		f.Annotations = r.annotations("field annotations")
		out = append(out, f)
	}
	return out
}

func (r *reader) typeRef() TypeRef {
	if r.err != nil {
		return TypeRef{}
	}
	maj, err := r.d.PeekMajor()
	if err != nil {
		r.fail(err, "type-ref")
		return TypeRef{}
	}
	if maj == cbor.MajorUint {
		return Named(r.uint("type-ref"))
	}
	n := r.array("type-ref")
	if r.err == nil && n == 0 {
		r.err = errorf(CodeBadTypeRef, "empty type-ref")
	}
	op := r.uint("type-ref form")
	if r.err != nil {
		return TypeRef{}
	}
	arity := map[uint64]int{0: 2, 1: 3, 2: 2, 3: 2, 4: 1}
	if w, ok := arity[op]; !ok || w != n {
		r.err = errorf(CodeBadTypeRef, "type-ref form %d with %d elements", op, n)
		return TypeRef{}
	}
	switch op {
	case 0:
		return List(r.typeRef())
	case 1:
		k := r.typeRef()
		return MapOf(k, r.typeRef())
	case 2:
		return Optional(r.typeRef())
	case 3:
		return Stream(r.typeRef())
	}
	return ByteStream()
}

func (r *reader) services() []Service {
	n := r.array("services")
	out := make([]Service, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		var s Service
		r.array("service", 4)
		s.ID = r.uint("service id")
		s.Name = r.text("service name")
		m := r.array("methods")
		s.Methods = make([]Method, 0, m)
		for j := 0; j < m && r.err == nil; j++ {
			var md Method
			r.array("method", 7)
			md.ID = r.uint("method id")
			md.Name = r.text("method name")
			md.Input = r.typeRef()
			md.Output = r.typeRef()
			md.Errors = r.uints("method errors")
			md.Flags = r.uint("method flags")
			md.Annotations = r.annotations("method annotations")
			s.Methods = append(s.Methods, md)
		}
		s.Annotations = r.annotations("service annotations")
		out = append(out, s)
	}
	return out
}

func (r *reader) sigils() []Sigil {
	n := r.array("sigils")
	out := make([]Sigil, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		var s Sigil
		r.array("sigil", 4)
		s.ID = r.uint("sigil id")
		s.Name = r.text("sigil name")
		s.Kind = r.uint("sigil kind")
		s.Annotations = r.annotations("sigil annotations")
		out = append(out, s)
	}
	return out
}

func (r *reader) delta() Delta {
	n := r.array("delta")
	out := make(Delta, 0, n)
	for i := 0; i < n && r.err == nil; i++ {
		m := r.array("delta-op", 2)
		_ = m
		op := DeltaOpKind(r.uint("delta-op kind"))
		if r.err != nil {
			break
		}
		d := DeltaOp{Op: op}
		switch op {
		case OpPut:
			d.Facet = r.facet()
		case OpRemove:
			d.FacetID = r.uint("removed facet id")
		case OpAnnotations:
			d.Annotations = r.annotations("delta annotations")
		case OpVersion:
			d.Version = r.text("delta version")
		default:
			r.err = errorf(CodeUnknownDeltaOp, "delta op %d", op)
		}
		out = append(out, d)
	}
	return out
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

// writer encodes schema structures. With canonical set, annotation maps
// and their values are written in Core Deterministic Encoding; the caller
// sorts the lists (see Canonical).
type writer struct {
	b         []byte
	canonical bool
	err       error
}

func (w *writer) annotations(a Annotations) {
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	cbor.SortTextKeys(keys)
	w.b = cbor.AppendMapHead(w.b, len(keys))
	for _, k := range keys {
		w.b = cbor.AppendText(w.b, k)
		v := a[k]
		if w.canonical && len(v) > 0 {
			c, err := cbor.Canonical(v, cbor.Options{MaxDepth: 1 << 10})
			if err != nil && w.err == nil {
				w.err = &Error{Code: CodeMalformed, Detail: fmt.Sprintf("annotation %q: %v", k, err)}
			}
			v = c
		}
		w.b = cbor.AppendRaw(w.b, v)
	}
}

func (w *writer) typeRef(t TypeRef) {
	switch t.Kind {
	case RefNamed:
		w.b = cbor.AppendUint(w.b, t.ID)
	case RefList, RefOptional, RefStream:
		op := map[RefKind]uint64{RefList: 0, RefOptional: 2, RefStream: 3}[t.Kind]
		w.b = cbor.AppendUint(cbor.AppendArrayHead(w.b, 2), op)
		w.elem(t.Elem)
	case RefMap:
		w.b = cbor.AppendUint(cbor.AppendArrayHead(w.b, 3), 1)
		w.elem(t.Key)
		w.elem(t.Elem)
	case RefByteStream:
		w.b = cbor.AppendUint(cbor.AppendArrayHead(w.b, 1), 4)
	default:
		if w.err == nil {
			w.err = errorf(CodeBadTypeRef, "unknown type-ref kind %d", t.Kind)
		}
		w.b = cbor.AppendNull(w.b)
	}
}

func (w *writer) elem(t *TypeRef) {
	if t == nil {
		if w.err == nil {
			w.err = errorf(CodeBadTypeRef, "type-ref without element")
		}
		w.b = cbor.AppendNull(w.b)
		return
	}
	w.typeRef(*t)
}

func (w *writer) uints(xs []uint64) {
	w.b = cbor.AppendArrayHead(w.b, len(xs))
	for _, x := range xs {
		w.b = cbor.AppendUint(w.b, x)
	}
}

func (w *writer) typeDef(t *TypeDef) {
	n := 5
	if t.Kind == KindStruct {
		n = 6
	}
	w.b = cbor.AppendUint(cbor.AppendArrayHead(w.b, n), uint64(t.Kind))
	w.b = cbor.AppendText(cbor.AppendUint(w.b, t.ID), t.Name)
	switch t.Kind {
	case KindStruct, KindUnion:
		w.b = cbor.AppendArrayHead(w.b, len(t.Fields))
		for i := range t.Fields {
			f := &t.Fields[i]
			w.b = cbor.AppendText(cbor.AppendUint(cbor.AppendArrayHead(w.b, 5), f.Tag), f.Name)
			w.typeRef(f.Type)
			w.b = cbor.AppendUint(w.b, f.Flags)
			w.annotations(f.Annotations)
		}
		if t.Kind == KindStruct {
			w.b = cbor.AppendUint(w.b, t.Flags)
		}
	case KindEnum:
		w.uints(t.Values)
	case KindAlias:
		w.typeRef(t.Target)
	default:
		if w.err == nil {
			w.err = errorf(CodeMalformed, "unknown type-def kind %d", t.Kind)
		}
		w.b = cbor.AppendNull(w.b)
	}
	w.annotations(t.Annotations)
}

func (w *writer) method(m *Method) {
	w.b = cbor.AppendText(cbor.AppendUint(cbor.AppendArrayHead(w.b, 7), m.ID), m.Name)
	w.typeRef(m.Input)
	w.typeRef(m.Output)
	w.uints(m.Errors)
	w.b = cbor.AppendUint(w.b, m.Flags)
	w.annotations(m.Annotations)
}

func (w *writer) service(s *Service) {
	w.b = cbor.AppendText(cbor.AppendUint(cbor.AppendArrayHead(w.b, 4), s.ID), s.Name)
	w.b = cbor.AppendArrayHead(w.b, len(s.Methods))
	for i := range s.Methods {
		w.method(&s.Methods[i])
	}
	w.annotations(s.Annotations)
}

func (w *writer) sigil(s *Sigil) {
	w.b = cbor.AppendText(cbor.AppendUint(cbor.AppendArrayHead(w.b, 4), s.ID), s.Name)
	w.b = cbor.AppendUint(w.b, s.Kind)
	w.annotations(s.Annotations)
}

func (w *writer) defs(types []TypeDef, services []Service, sigils []Sigil) {
	w.b = cbor.AppendArrayHead(w.b, len(types))
	for i := range types {
		w.typeDef(&types[i])
	}
	w.b = cbor.AppendArrayHead(w.b, len(services))
	for i := range services {
		w.service(&services[i])
	}
	w.b = cbor.AppendArrayHead(w.b, len(sigils))
	for i := range sigils {
		w.sigil(&sigils[i])
	}
}

func (w *writer) facet(f *Facet) {
	w.b = cbor.AppendUint(cbor.AppendArrayHead(w.b, 9), f.ID)
	w.b = cbor.AppendText(cbor.AppendText(w.b, f.Name), f.Version)
	w.defs(f.Types, f.Services, f.Sigils)
	if f.Implements == nil {
		w.b = cbor.AppendNull(w.b)
	} else {
		w.b = cbor.AppendBytes(w.b, f.Implements)
	}
	w.b = cbor.AppendArrayHead(w.b, len(f.Retired))
	for _, r := range f.Retired {
		w.b = cbor.AppendUint(cbor.AppendUint(cbor.AppendArrayHead(w.b, 2), uint64(r.Space)), r.ID)
	}
	w.annotations(f.Annotations)
}

func (w *writer) iface(i *Interface) {
	w.b = cbor.AppendText(cbor.AppendText(cbor.AppendArrayHead(w.b, 5), i.Name), i.Version)
	w.defs(i.Types, i.Services, i.Sigils)
}

func (w *writer) schema(s *Schema) {
	w.b = cbor.AppendUint(cbor.AppendArrayHead(w.b, 5), s.Format)
	w.b = cbor.AppendText(cbor.AppendText(w.b, s.Name), s.Version)
	w.b = cbor.AppendArrayHead(w.b, len(s.Facets))
	for i := range s.Facets {
		w.facet(&s.Facets[i])
	}
	w.annotations(s.Annotations)
}

func (w *writer) delta(d Delta) {
	w.b = cbor.AppendArrayHead(w.b, len(d))
	for _, op := range d {
		w.b = cbor.AppendUint(cbor.AppendArrayHead(w.b, 2), uint64(op.Op))
		switch op.Op {
		case OpPut:
			if op.Facet == nil {
				w.err = errorf(CodeMalformed, "put without facet")
				w.b = cbor.AppendNull(w.b)
				continue
			}
			w.facet(op.Facet)
		case OpRemove:
			w.b = cbor.AppendUint(w.b, op.FacetID)
		case OpAnnotations:
			w.annotations(op.Annotations)
		case OpVersion:
			w.b = cbor.AppendText(w.b, op.Version)
		default:
			w.err = errorf(CodeUnknownDeltaOp, "delta op %d", op.Op)
			w.b = cbor.AppendNull(w.b)
		}
	}
}

// Encode encodes the schema as it is, in list order. Annotation maps are
// written with sorted keys and their values as stored.
func (s *Schema) Encode() ([]byte, error) {
	w := &writer{}
	w.schema(s)
	return w.b, w.err
}

// Encode encodes the facet as it is.
func (f *Facet) Encode() ([]byte, error) {
	w := &writer{}
	w.facet(f)
	return w.b, w.err
}

// Encode encodes the interface as it is.
func (i *Interface) Encode() ([]byte, error) {
	w := &writer{}
	w.iface(i)
	return w.b, w.err
}

// Encode encodes the delta. Facets in it are written as they are.
func (d Delta) Encode() ([]byte, error) {
	w := &writer{}
	w.delta(d)
	return w.b, w.err
}

// Encode encodes a type reference.
func (t TypeRef) Encode() []byte {
	w := &writer{}
	w.typeRef(t)
	return w.b
}
