// Package value encodes and decodes payload values according to a facet's
// type definitions (sections 3.4 and 6.3).
//
// Go representation of each schema type:
//
//	unit                 nil
//	bool                 bool
//	int                  int64   (encoders also take other Go integer types)
//	uint                 uint64  (likewise)
//	float32, float64     float64 (encoders also take float32 and integers)
//	string               string
//	bytes                []byte
//	timestamp            cbor.Time (encoders also take time.Time)
//	uuid                 UUID    (encoders also take a 16-byte []byte)
//	dynamic              Dynamic
//	symbol               Symbol  (encoders also take a string)
//	enum                 uint64, the sigil
//	struct, sparse       Struct, field tag -> value
//	union                Union
//	alias                the target's representation
//	[0, T] list          []any
//	[1, K, V] map        cbor.Map (encoders also take map[string]any)
//	[2, T] optional      nil or T's representation
//	[4] byte stream      Token inside a value; nil as a method's whole input/output
//
// A [3, T] stream is not a value: encode each Item with T.
package value

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/schema"
)

// Struct is a struct value: field tag -> value. Absent fields are left out.
type Struct map[uint64]any

// Union is a union value. A decoded variant the reader does not know keeps
// its value as cbor.Raw.
type Union struct {
	Tag   uint64
	Value any
}

// Dynamic is a run-time typed value: [type_id, value].
type Dynamic struct {
	Type  uint64
	Value any
}

// Symbol is a symbol value: a sigil, or a text string when the string has
// no sigil.
type Symbol struct {
	Sigil    uint64
	Text     string
	HasSigil bool
}

// UUID is a 16-byte UUID (tag 37).
type UUID [16]byte

// Token references byte data sent in Bytes messages (section 7.8); it is
// nonzero inside a value.
type Token uint64

// MaxDepth bounds value nesting.
const MaxDepth = 64

// Codec encodes and decodes values of one facet's types.
type Codec struct {
	facet   *schema.Facet
	types   map[uint64]*schema.TypeDef
	symbols map[string]uint64 // kind-2 sigil names
	sigils  map[uint64]*schema.Sigil
}

// New returns a Codec for a facet, which must be valid.
func New(f *schema.Facet) (*Codec, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	c := &Codec{facet: f, types: f.TypeIndex(), symbols: map[string]uint64{}, sigils: map[uint64]*schema.Sigil{}}
	for i := range f.Sigils {
		s := &f.Sigils[i]
		c.sigils[s.ID] = s
		if s.Kind == schema.SigilSymbol {
			c.symbols[s.Name] = s.ID
		}
	}
	return c, nil
}

// Error is a value that does not match its type.
type Error struct {
	Path string
	Msg  string
}

func (e *Error) Error() string {
	if e.Path == "" {
		return "value: " + e.Msg
	}
	return "value: " + e.Path + ": " + e.Msg
}

func verr(path, f string, args ...any) error { return &Error{Path: path, Msg: fmt.Sprintf(f, args...)} }

// Encode encodes v as type t, as a method's whole input or output or as a
// top-level Item value: a top-level [4] encodes as null (token 0 inline).
func (c *Codec) Encode(t schema.TypeRef, v any) (cbor.Raw, error) {
	if t.Kind == schema.RefByteStream {
		if v != nil {
			return nil, verr("", "a whole-value byte stream carries no value; send Bytes with token 0")
		}
		return cbor.Raw{0xf6}, nil
	}
	if t.Kind == schema.RefStream {
		return nil, verr("", "a stream is not a value; encode each item with its element type")
	}
	e := &encoder{c: c}
	b, err := e.value(nil, t, v, "", 0, false)
	return b, err
}

// EncodeInner encodes v as type t nested inside another value, where a [4]
// is a nonzero Token.
func (c *Codec) EncodeInner(t schema.TypeRef, v any) (cbor.Raw, error) {
	e := &encoder{c: c}
	return e.value(nil, t, v, "", 0, false)
}

// DecodeInner decodes b as type t nested inside another value.
func (c *Codec) DecodeInner(t schema.TypeRef, b []byte) (any, error) {
	if err := cbor.Validate(b, cbor.Options{}); err != nil {
		return nil, err
	}
	d := cbor.NewDecoder(b)
	v, err := c.decode(d, t, "", 0, false)
	if err != nil {
		return nil, err
	}
	if !d.Done() {
		return nil, verr("", "trailing data")
	}
	return v, nil
}

type encoder struct{ c *Codec }

func (e *encoder) value(dst []byte, t schema.TypeRef, v any, path string, depth int, inDynamic bool) ([]byte, error) {
	if depth > MaxDepth {
		return nil, verr(path, "nested deeper than %d levels", MaxDepth)
	}
	switch t.Kind {
	case schema.RefList:
		xs, ok := v.([]any)
		if !ok {
			if ss, isStr := v.([]string); isStr {
				for _, s := range ss {
					xs = append(xs, s)
				}
				ok = true
			}
		}
		if !ok {
			return nil, verr(path, "list needs []any, got %T", v)
		}
		dst = cbor.AppendArrayHead(dst, len(xs))
		var err error
		for i, x := range xs {
			if dst, err = e.value(dst, *t.Elem, x, fmt.Sprintf("%s[%d]", path, i), depth+1, inDynamic); err != nil {
				return nil, err
			}
		}
		return dst, nil
	case schema.RefMap:
		var pairs cbor.Map
		switch m := v.(type) {
		case cbor.Map:
			pairs = m
		case map[string]any:
			for k, x := range m {
				pairs = append(pairs, cbor.Pair{Key: k, Value: x})
			}
		default:
			return nil, verr(path, "map needs cbor.Map, got %T", v)
		}
		type kv struct{ k, v []byte }
		entries := make([]kv, 0, len(pairs))
		seen := map[string]bool{}
		for _, p := range pairs {
			kb, err := e.value(nil, *t.Key, p.Key, path+".key", depth+1, inDynamic)
			if err != nil {
				return nil, err
			}
			if seen[string(kb)] {
				return nil, verr(path, "duplicate map key")
			}
			seen[string(kb)] = true
			vb, err := e.value(nil, *t.Elem, p.Value, fmt.Sprintf("%s[%v]", path, p.Key), depth+1, inDynamic)
			if err != nil {
				return nil, err
			}
			entries = append(entries, kv{kb, vb})
		}
		sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].k, entries[j].k) < 0 })
		dst = cbor.AppendMapHead(dst, len(entries))
		for _, x := range entries {
			dst = append(append(dst, x.k...), x.v...)
		}
		return dst, nil
	case schema.RefOptional:
		if v == nil {
			return cbor.AppendNull(dst), nil
		}
		return e.value(dst, *t.Elem, v, path, depth+1, inDynamic)
	case schema.RefStream:
		return nil, verr(path, "[3, T] is only allowed as a method's whole input or output")
	case schema.RefByteStream:
		if inDynamic {
			return nil, verr(path, "[4] must not appear inside a dynamic value")
		}
		tok, ok := toUint(v)
		if !ok || tok == 0 || tok > cbor.MaxSafeInt {
			return nil, verr(path, "a byte stream inside a value is a nonzero Token of at most 2^53 - 1, got %v", v)
		}
		return cbor.AppendUint(dst, tok), nil
	}
	return e.named(dst, t.ID, v, path, depth, inDynamic)
}

func toUint(v any) (uint64, bool) {
	switch x := v.(type) {
	case uint64:
		return x, true
	case uint:
		return uint64(x), true
	case uint32:
		return uint64(x), true
	case uint16:
		return uint64(x), true
	case uint8:
		return uint64(x), true
	case Token:
		return uint64(x), true
	case int, int64, int32, int16, int8:
		i, _ := toInt(v)
		if i < 0 {
			return 0, false
		}
		return uint64(i), true
	}
	return 0, false
}

func toInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case int32:
		return int64(x), true
	case int16:
		return int64(x), true
	case int8:
		return int64(x), true
	case uint64, uint, uint32, uint16, uint8:
		u, _ := toUint(v)
		if u > math.MaxInt64 {
			return 0, false
		}
		return int64(u), true
	}
	return 0, false
}

func (e *encoder) named(dst []byte, id uint64, v any, path string, depth int, inDynamic bool) ([]byte, error) {
	switch id {
	case schema.TypeUnit:
		if v != nil {
			return nil, verr(path, "unit must be nil, got %T", v)
		}
		return cbor.AppendNull(dst), nil
	case schema.TypeBool:
		b, ok := v.(bool)
		if !ok {
			return nil, verr(path, "bool needs bool, got %T", v)
		}
		return cbor.AppendBool(dst, b), nil
	case schema.TypeInt:
		i, ok := toInt(v)
		if !ok {
			return nil, verr(path, "int needs a signed 64-bit integer, got %T(%v)", v, v)
		}
		return cbor.AppendInt(dst, i), nil
	case schema.TypeUint:
		u, ok := toUint(v)
		if !ok {
			return nil, verr(path, "uint needs an unsigned integer, got %T(%v)", v, v)
		}
		return cbor.AppendUint(dst, u), nil
	case schema.TypeFloat32, schema.TypeFloat64:
		var f float64
		switch x := v.(type) {
		case float64:
			f = x
		case float32:
			f = float64(x)
		default:
			if i, ok := toInt(v); ok {
				f = float64(i)
			} else if u, ok := toUint(v); ok {
				f = float64(u)
			} else {
				return nil, verr(path, "float needs a number, got %T", v)
			}
		}
		if id == schema.TypeFloat32 && !math.IsNaN(f) {
			f = float64(float32(f))
		}
		return cbor.AppendFloat(dst, f), nil
	case schema.TypeString:
		s, ok := v.(string)
		if !ok {
			return nil, verr(path, "string needs string, got %T", v)
		}
		return cbor.AppendText(dst, s), nil
	case schema.TypeBytes:
		b, ok := v.([]byte)
		if !ok {
			return nil, verr(path, "bytes needs []byte, got %T", v)
		}
		return cbor.AppendBytes(dst, b), nil
	case schema.TypeTimestamp:
		switch x := v.(type) {
		case cbor.Time:
			if x.IsFloat && (math.IsNaN(x.Float) || math.IsInf(x.Float, 0)) {
				return nil, verr(path, "timestamp %v is not finite", x.Float)
			}
			if !x.IsFloat && (x.Sec > cbor.MaxSafeInt || x.Sec < -cbor.MaxSafeInt) {
				return nil, verr(path, "timestamp %d s is beyond ±(2^53 - 1)", x.Sec)
			}
			return cbor.AppendTime(dst, x), nil
		case time.Time:
			if s := x.Unix(); s > cbor.MaxSafeInt || s < -cbor.MaxSafeInt {
				return nil, verr(path, "timestamp %d s is beyond ±(2^53 - 1)", s)
			}
			return cbor.AppendTime(dst, cbor.FromTime(x)), nil
		}
		return nil, verr(path, "timestamp needs cbor.Time, got %T", v)
	case schema.TypeUUID:
		var u []byte
		switch x := v.(type) {
		case UUID:
			u = x[:]
		case []byte:
			u = x
		}
		if len(u) != 16 {
			return nil, verr(path, "uuid needs 16 bytes, got %T", v)
		}
		return cbor.AppendBytes(cbor.AppendTag(dst, cbor.TagUUID), u), nil
	case schema.TypeDynamic:
		d, ok := v.(Dynamic)
		if !ok {
			return nil, verr(path, "dynamic needs Dynamic, got %T", v)
		}
		if err := e.c.checkDynamicType(d.Type); err != nil {
			return nil, verr(path, "%v", err)
		}
		dst = cbor.AppendUint(cbor.AppendArrayHead(dst, 2), d.Type)
		return e.value(dst, schema.Named(d.Type), d.Value, path+".value", depth+1, true)
	case schema.TypeSymbol:
		switch x := v.(type) {
		case Symbol:
			if x.HasSigil {
				if x.Sigil > cbor.MaxSafeInt {
					return nil, verr(path, "sigil %d is beyond 2^53 - 1", x.Sigil)
				}
				return cbor.AppendUint(dst, x.Sigil), nil
			}
			return cbor.AppendText(dst, x.Text), nil
		case string:
			if s, ok := e.c.symbols[x]; ok {
				return cbor.AppendUint(dst, s), nil
			}
			return cbor.AppendText(dst, x), nil
		}
		return nil, verr(path, "symbol needs Symbol or string, got %T", v)
	}
	td := e.c.types[id]
	if td == nil {
		return nil, verr(path, "type %d is not defined in facet %d", id, e.c.facet.ID)
	}
	switch td.Kind {
	case schema.KindAlias:
		return e.value(dst, td.Target, v, path, depth+1, inDynamic)
	case schema.KindEnum:
		s, ok := toUint(v)
		if !ok {
			return nil, verr(path, "enum %s needs a sigil, got %T", td.Name, v)
		}
		known := false
		for _, x := range td.Values {
			known = known || x == s
		}
		if !known {
			return nil, verr(path, "sigil %d is not a value of enum %s", s, td.Name)
		}
		return cbor.AppendUint(dst, s), nil
	case schema.KindUnion:
		u, ok := v.(Union)
		if !ok {
			return nil, verr(path, "union %s needs Union, got %T", td.Name, v)
		}
		f := td.Field(u.Tag)
		if f == nil || f.Removed() {
			return nil, verr(path, "union %s has no variant %d", td.Name, u.Tag)
		}
		dst = cbor.AppendUint(cbor.AppendArrayHead(dst, 2), u.Tag)
		return e.value(dst, f.Type, u.Value, path+"."+f.Name, depth+1, inDynamic)
	case schema.KindStruct:
		s, ok := v.(Struct)
		if !ok {
			return nil, verr(path, "struct %s needs Struct, got %T", td.Name, v)
		}
		return e.structValue(dst, td, s, path, depth, inDynamic)
	}
	return nil, verr(path, "type %d has unknown kind", id)
}

func nullable(t schema.TypeRef) bool {
	return t.Kind == schema.RefOptional || (t.Kind == schema.RefNamed && t.ID == schema.TypeUnit)
}

func (e *encoder) structValue(dst []byte, td *schema.TypeDef, s Struct, path string, depth int, inDynamic bool) ([]byte, error) {
	for tag, x := range s {
		f := td.Field(tag)
		if f == nil {
			return nil, verr(path, "struct %s has no field %d", td.Name, tag)
		}
		if f.Removed() && x != nil {
			return nil, verr(path, "field %d of %s is removed", tag, td.Name)
		}
	}
	var maxTag uint64
	enc := map[uint64][]byte{}
	for i := range td.Fields {
		f := &td.Fields[i]
		if f.Removed() {
			continue
		}
		x, present := s[f.Tag]
		if !present || x == nil {
			if !f.Optional() && !nullable(f.Type) {
				return nil, verr(path, "required field %d (%s) of %s is missing", f.Tag, f.Name, td.Name)
			}
			continue
		}
		b, err := e.value(nil, f.Type, x, path+"."+f.Name, depth+1, inDynamic)
		if err != nil {
			return nil, err
		}
		enc[f.Tag] = b
		if f.Tag >= maxTag {
			maxTag = f.Tag
		}
	}
	tags := make([]uint64, 0, len(enc))
	for t := range enc {
		tags = append(tags, t)
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })
	if td.Sparse() {
		dst = cbor.AppendMapHead(dst, len(tags))
		for _, t := range tags {
			dst = append(cbor.AppendUint(dst, t), enc[t]...)
		}
		return dst, nil
	}
	if len(tags) == 0 {
		return cbor.AppendArrayHead(dst, 0), nil
	}
	if maxTag >= 1<<20 {
		return nil, verr(path, "field tag %d too sparse for a positional struct", maxTag)
	}
	n := int(maxTag) + 1 // trailing nulls are omitted
	dst = cbor.AppendArrayHead(dst, n)
	for t := 0; t < n; t++ {
		if b, ok := enc[uint64(t)]; ok {
			dst = append(dst, b...)
		} else {
			dst = cbor.AppendNull(dst)
		}
	}
	return dst, nil
}

// checkDynamicType checks that a dynamic value may name the type: a
// built-in or a named type of the facet, from which [4] is not reachable.
func (c *Codec) checkDynamicType(id uint64) error {
	if id <= schema.MaxBuiltinType {
		return nil
	}
	if c.types[id] == nil {
		return fmt.Errorf("dynamic type %d is not defined in facet %d", id, c.facet.ID)
	}
	if schema.ReachesByteStream(schema.Named(id), c.types) {
		return fmt.Errorf("dynamic type %d reaches [4], which must not appear inside a dynamic value", id)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

// Decode decodes b as type t (see Encode for the top-level rules). It
// validates b against the CBOR rules of section 3.1 first. Elements beyond
// the fields a struct knows and unknown sparse tags are skipped; unknown
// enum values and union variants are kept (readers MUST handle them).
func (c *Codec) Decode(t schema.TypeRef, b []byte) (any, error) {
	if err := cbor.Validate(b, cbor.Options{}); err != nil {
		return nil, err
	}
	d := cbor.NewDecoder(b)
	if t.Kind == schema.RefByteStream {
		if err := d.Null(); err != nil {
			return nil, verr("", "a whole-value byte stream is null")
		}
		return nil, nil
	}
	if t.Kind == schema.RefStream {
		return nil, verr("", "a stream is not a value; decode each item with its element type")
	}
	v, err := c.decode(d, t, "", 0, false)
	if err != nil {
		return nil, err
	}
	if !d.Done() {
		return nil, verr("", "trailing data")
	}
	return v, nil
}

func (c *Codec) decode(d *cbor.Decoder, t schema.TypeRef, path string, depth int, inDynamic bool) (any, error) {
	if depth > MaxDepth {
		return nil, verr(path, "nested deeper than %d levels", MaxDepth)
	}
	wrap := func(err error) error {
		if err == nil {
			return nil
		}
		var ve *Error
		if errors.As(err, &ve) {
			return err
		}
		return verr(path, "%v", err)
	}
	switch t.Kind {
	case schema.RefList:
		n, err := d.ArrayHead()
		if err != nil {
			return nil, wrap(err)
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			x, err := c.decode(d, *t.Elem, fmt.Sprintf("%s[%d]", path, i), depth+1, inDynamic)
			if err != nil {
				return nil, err
			}
			out = append(out, x)
		}
		return out, nil
	case schema.RefMap:
		n, err := d.MapHead()
		if err != nil {
			return nil, wrap(err)
		}
		out := make(cbor.Map, 0, n)
		for i := 0; i < n; i++ {
			k, err := c.decode(d, *t.Key, path+".key", depth+1, inDynamic)
			if err != nil {
				return nil, err
			}
			x, err := c.decode(d, *t.Elem, fmt.Sprintf("%s[%v]", path, k), depth+1, inDynamic)
			if err != nil {
				return nil, err
			}
			out = append(out, cbor.Pair{Key: k, Value: x})
		}
		return out, nil
	case schema.RefOptional:
		if d.PeekNull() {
			return nil, d.Null()
		}
		return c.decode(d, *t.Elem, path, depth+1, inDynamic)
	case schema.RefStream:
		return nil, verr(path, "[3, T] is only allowed as a method's whole input or output")
	case schema.RefByteStream:
		if inDynamic {
			return nil, verr(path, "[4] must not appear inside a dynamic value")
		}
		u, err := d.SafeUint()
		if err != nil || u == 0 {
			return nil, verr(path, "a byte stream inside a value is a nonzero token of at most 2^53 - 1")
		}
		return Token(u), nil
	}
	return c.decodeNamed(d, t.ID, path, depth, inDynamic, wrap)
}

func (c *Codec) decodeNamed(d *cbor.Decoder, id uint64, path string, depth int, inDynamic bool, wrap func(error) error) (any, error) {
	switch id {
	case schema.TypeUnit:
		return nil, wrap(d.Null())
	case schema.TypeBool:
		v, err := d.Bool()
		return v, wrap(err)
	case schema.TypeInt:
		v, err := d.Int()
		return v, wrap(err)
	case schema.TypeUint:
		v, err := d.Uint()
		return v, wrap(err)
	case schema.TypeFloat32, schema.TypeFloat64:
		v, err := d.Float()
		return v, wrap(err)
	case schema.TypeString:
		v, err := d.Text()
		return v, wrap(err)
	case schema.TypeBytes:
		v, err := d.Bytes()
		return append([]byte{}, v...), wrap(err)
	case schema.TypeTimestamp:
		v, err := d.Time()
		if err == nil && v.IsFloat && (math.IsNaN(v.Float) || math.IsInf(v.Float, 0)) {
			return nil, verr(path, "timestamp %v is not finite", v.Float)
		}
		return v, wrap(err)
	case schema.TypeUUID:
		tag, err := d.Tag()
		if err != nil || tag != cbor.TagUUID {
			return nil, verr(path, "uuid needs tag 37")
		}
		b, err := d.Bytes()
		if err != nil || len(b) != 16 {
			return nil, verr(path, "uuid needs 16 bytes")
		}
		var u UUID
		copy(u[:], b)
		return u, nil
	case schema.TypeDynamic:
		n, err := d.ArrayHead()
		if err != nil || n != 2 {
			return nil, verr(path, "dynamic needs [type_id, value]")
		}
		tid, err := d.SafeUint()
		if err != nil {
			return nil, wrap(err)
		}
		if err := c.checkDynamicType(tid); err != nil {
			return nil, verr(path, "%v", err)
		}
		x, err := c.decode(d, schema.Named(tid), path+".value", depth+1, true)
		if err != nil {
			return nil, err
		}
		return Dynamic{Type: tid, Value: x}, nil
	case schema.TypeSymbol:
		maj, err := d.PeekMajor()
		if err != nil {
			return nil, wrap(err)
		}
		if maj == cbor.MajorUint {
			s, err := d.SafeUint()
			if err != nil {
				return nil, wrap(err)
			}
			sym := Symbol{Sigil: s, HasSigil: true}
			if sg := c.sigils[s]; sg != nil {
				sym.Text = sg.Name
			}
			return sym, nil
		}
		s, err := d.Text()
		return Symbol{Text: s}, wrap(err)
	}
	td := c.types[id]
	if td == nil {
		return nil, verr(path, "type %d is not defined in facet %d", id, c.facet.ID)
	}
	switch td.Kind {
	case schema.KindAlias:
		return c.decode(d, td.Target, path, depth+1, inDynamic)
	case schema.KindEnum:
		v, err := d.SafeUint()
		return v, wrap(err)
	case schema.KindUnion:
		n, err := d.ArrayHead()
		if err != nil || n != 2 {
			return nil, verr(path, "union %s needs [variant_tag, value]", td.Name)
		}
		tag, err := d.SafeUint()
		if err != nil {
			return nil, wrap(err)
		}
		f := td.Field(tag)
		if f == nil || f.Removed() {
			raw, err := d.Raw()
			return Union{Tag: tag, Value: append(cbor.Raw{}, raw...)}, wrap(err)
		}
		x, err := c.decode(d, f.Type, path+"."+f.Name, depth+1, inDynamic)
		if err != nil {
			return nil, err
		}
		return Union{Tag: tag, Value: x}, nil
	case schema.KindStruct:
		return c.decodeStruct(d, td, path, depth, inDynamic, wrap)
	}
	return nil, verr(path, "type %d has unknown kind", id)
}

func (c *Codec) decodeStruct(d *cbor.Decoder, td *schema.TypeDef, path string, depth int, inDynamic bool, wrap func(error) error) (any, error) {
	s := Struct{}
	field := func(tag uint64) error {
		f := td.Field(tag)
		if f == nil || f.Removed() || d.PeekNull() {
			return d.Skip() // unknown, tombstone or absent
		}
		x, err := c.decode(d, f.Type, path+"."+f.Name, depth+1, inDynamic)
		if err != nil {
			return err
		}
		if x != nil {
			s[tag] = x
		}
		return nil
	}
	if td.Sparse() {
		n, err := d.MapHead()
		if err != nil {
			return nil, verr(path, "sparse struct %s needs a map: %v", td.Name, err)
		}
		for i := 0; i < n; i++ {
			tag, err := d.SafeUint()
			if err != nil {
				return nil, verr(path, "sparse struct keys are field tags")
			}
			if err := field(tag); err != nil {
				return nil, wrap(err)
			}
		}
	} else {
		n, err := d.ArrayHead()
		if err != nil {
			return nil, verr(path, "struct %s needs an array: %v", td.Name, err)
		}
		for i := 0; i < n; i++ {
			if err := field(uint64(i)); err != nil {
				return nil, wrap(err)
			}
		}
	}
	for i := range td.Fields {
		f := &td.Fields[i]
		if _, ok := s[f.Tag]; !ok && !f.Removed() && !f.Optional() && !nullable(f.Type) {
			return nil, verr(path, "required field %d (%s) of %s is missing", f.Tag, f.Name, td.Name)
		}
	}
	return s, nil
}
