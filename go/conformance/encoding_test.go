package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/internal/vectors"
	"github.com/aiviarium/sparrow/go/schema"
	"github.com/aiviarium/sparrow/go/value"
	"github.com/aiviarium/sparrow/go/wire"
)

// openPanelFacet is a fixture facet with the section 7.7 OpenPanel struct.
func openPanelFacet() *schema.Facet {
	return &schema.Facet{ID: 16, Name: "sparrow.ui", Version: "1.0.0", Types: []schema.TypeDef{{
		Kind: schema.KindStruct, ID: 64, Name: "OpenPanel",
		Fields: []schema.Field{
			{Tag: 0, Name: "name", Type: schema.Named(schema.TypeString)},
			{Tag: 1, Name: "focus", Type: schema.Named(schema.TypeBool), Flags: schema.FieldOptional},
		}}}}
}

func codecFor(t *testing.T, f *schema.Facet) *value.Codec {
	t.Helper()
	c, err := value.New(f)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func typeRefOf(t *testing.T, raw json.RawMessage) schema.TypeRef {
	t.Helper()
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch s {
		case "float32":
			return schema.Named(schema.TypeFloat32)
		case "float64":
			return schema.Named(schema.TypeFloat64)
		}
		if strings.HasPrefix(s, "OpenPanel") {
			return schema.Named(64)
		}
		t.Fatalf("schema_type %q", s)
	}
	b, err := vectors.TJSONToCBOR(raw)
	if err != nil {
		t.Fatal(err)
	}
	r, err := schema.DecodeTypeRef(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestEncoding(t *testing.T) {
	notes := codecFor(t, decodeFacetField(t, vector(t, "facet/acme-notes"), "input"))
	panel := codecFor(t, openPanelFacet())
	facet := decodeFacetField(t, vector(t, "facet/acme-notes"), "input")

	each(t, "encoding.json", func(t *testing.T, v vectors.Vector) {
		cb := v.Hex("cbor")
		if v.Type == "decode_only" {
			typ := typeRefOf(t, v.Fields["schema_type"])
			val, err := notes.Decode(typ, cb)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := strconv.ParseFloat(v.String("decoded_float"), 64)
			if f, ok := val.(float64); !ok || f != want {
				t.Fatalf("decoded %v", val)
			}
			if got, err := notes.Encode(typ, val); err != nil || !bytes.Equal(got, v.Hex("canonical_cbor")) {
				t.Fatalf("re-encoded %x", got)
			}
			return
		}
		if !bytes.Equal(cb, v.CBOR("value")) {
			t.Fatalf("cbor differs from typed JSON value")
		}
		if !cbor.IsCanonical(cb, cbor.Options{}) {
			t.Fatalf("vector bytes are not in preferred / deterministic form")
		}
		var st string
		_ = json.Unmarshal(v.Fields["schema_type"], &st)
		switch st {
		case "metadata":
			m, err := wire.Decode(append(append(cbor.AppendUint(cbor.AppendArrayHead(nil, 3), 19), 1), cb...))
			if err != nil {
				t.Fatal(err)
			}
			if got := m.(*wire.End).Trailers.AppendTo(nil); !bytes.Equal(got, cb) {
				t.Fatalf("metadata re-encoded %x", got)
			}
			checkMapEntries(t, v, cb)
			return
		case "any map":
			// Not all keys are symbols (-1, -25), so this is not valid
			// metadata; it checks generic canonical key order.
			c, err := cbor.Canonical(cb, cbor.Options{})
			if err != nil || !bytes.Equal(c, cb) {
				t.Fatal("canonical order")
			}
			checkMapEntries(t, v, cb)
			return
		case "params":
			m, err := wire.Decode(wire.Encode(&wire.Hello{Versions: []uint64{1}, Params: paramsOf(t, cb)}))
			if err != nil {
				t.Fatal(err)
			}
			if got := m.(*wire.Hello).Params.AppendTo(nil); !bytes.Equal(got, cb) {
				t.Fatalf("params re-encoded %x", got)
			}
			checkMapEntries(t, v, cb)
			return
		}
		c := notes
		if strings.HasPrefix(st, "OpenPanel") {
			c = panel
		}
		typ := typeRefOf(t, v.Fields["schema_type"])
		val, err := c.Decode(typ, cb)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got, err := c.Encode(typ, val); err != nil || !bytes.Equal(got, cb) {
			t.Fatalf("re-encode %x, %v\nwant %x", got, err, cb)
		}
		// Build the value from its logical description and encode it.
		var lg map[string]json.RawMessage
		v.Into("logical", &lg)
		sub := func(r schema.TypeRef, raw json.RawMessage) any {
			b, err := vectors.TJSONToCBOR(raw)
			if err != nil {
				t.Fatal(err)
			}
			x, err := c.DecodeInner(r, b)
			if err != nil {
				t.Fatalf("decode logical facet: %v", err)
			}
			return x
		}
		var built any
		switch v.String("rule") {
		case "int":
			tv, _ := vectors.TJSON(lg["value"])
			built = tv
			if bn, ok := tv.(cbor.BigNeg); ok {
				t.Fatalf("int out of range: %v", bn)
			}
		case "float":
			var s string
			_ = json.Unmarshal(lg["value"], &s)
			f, err := parseFloatName(s)
			if err != nil {
				t.Fatal(err)
			}
			built = f
		case "struct", "sparse_struct":
			var fields []struct {
				Tag   uint64          `json:"tag"`
				Name  string          `json:"name"`
				Value json.RawMessage `json:"value"`
			}
			if string(lg["fields"]) != "null" {
				_ = json.Unmarshal(lg["fields"], &fields)
			}
			td := facet.Type(typ.ID)
			if c == panel {
				td = openPanelFacet().Type(64)
			}
			s := value.Struct{}
			for _, f := range fields {
				fd := td.Field(f.Tag)
				if fd == nil || fd.Name != f.Name {
					t.Fatalf("field %d %s not in type", f.Tag, f.Name)
				}
				s[f.Tag] = sub(fd.Type, f.Value)
			}
			built = s
		case "enum":
			var sig uint64
			var name string
			_ = json.Unmarshal(lg["sigil"], &sig)
			_ = json.Unmarshal(lg["value_name"], &name)
			if sg := facet.Sigil(sig); sg == nil || !strings.HasSuffix(name, sg.Name) {
				t.Fatalf("enum sigil %d is not %s", sig, name)
			}
			built = sig
		case "union":
			var tag uint64
			_ = json.Unmarshal(lg["variant_tag"], &tag)
			f := facet.Type(typ.ID).Field(tag)
			built = value.Union{Tag: tag, Value: sub(f.Type, lg["value"])}
		case "dynamic":
			var tid uint64
			_ = json.Unmarshal(lg["type_id"], &tid)
			built = value.Dynamic{Type: tid, Value: sub(schema.Named(tid), lg["value"])}
		case "symbol":
			var text string
			_ = json.Unmarshal(lg["text"], &text)
			built = text // the encoder picks the sigil when the text has one
		case "literal":
			built = sub(typ, lg["value"])
		case "map":
			var entries [][2]json.RawMessage
			_ = json.Unmarshal(lg["entries"], &entries)
			m := cbor.Map{}
			for _, e := range entries {
				m = append(m, cbor.Pair{Key: sub(*typ.Key, e[0]), Value: sub(*typ.Elem, e[1])})
			}
			built = m
		default:
			t.Fatalf("rule %s", v.String("rule"))
		}
		if got, err := c.Encode(typ, built); err != nil || !bytes.Equal(got, cb) {
			t.Fatalf("encoding the logical value: %x, %v\nwant %x", got, err, cb)
		}
	}, "value", "decode_only")

	each(t, "encoding.json", func(t *testing.T, v vectors.Vector) {
		cb := v.Hex("cbor")
		if !bytes.Equal(cb, v.CBOR("message")) {
			t.Fatalf("cbor differs from typed JSON message")
		}
		want := v.Bool("expected_valid")
		if v.Int("max_depth") != cbor.DefaultMaxDepth || want != (v.Int("depth") <= cbor.DefaultMaxDepth) {
			t.Fatalf("vector depth fields")
		}
		_, err := wire.Decode(cb)
		if (err == nil) != want {
			t.Fatalf("Decode = %v, want valid=%v", err, want)
		}
		// A limit one level higher accepts it; one lower rejects it.
		if err := cbor.Validate(cb, cbor.Options{MaxDepth: int(v.Int("depth"))}); err != nil {
			t.Fatalf("depth %d with MaxDepth %d: %v", v.Int("depth"), v.Int("depth"), err)
		}
		if err := cbor.Validate(cb, cbor.Options{MaxDepth: int(v.Int("depth")) - 1}); err == nil {
			t.Fatalf("depth %d accepted with MaxDepth %d", v.Int("depth"), v.Int("depth")-1)
		}
	}, "depth")

	each(t, "encoding.json", func(t *testing.T, v vectors.Vector) {
		cb := v.Hex("cbor")
		m, err := wire.Decode(cb)
		if err != nil {
			t.Fatalf("non-shortest message rejected: %v", err)
		}
		shortest := v.Hex("shortest_cbor")
		if !bytes.Equal(shortest, v.CBOR("message")) {
			t.Fatalf("shortest_cbor differs from typed JSON message")
		}
		if bytes.Equal(cb, shortest) {
			t.Fatalf("not a non-shortest form")
		}
		if got := wire.Encode(m); !bytes.Equal(got, shortest) {
			// Metadata keeps its received order; compare canonically.
			c1, _ := cbor.Canonical(got, cbor.Options{})
			if !bytes.Equal(c1, shortest) {
				t.Fatalf("re-encoded %x, want %x", got, shortest)
			}
		}
	}, "non_shortest")

	each(t, "encoding.json", func(t *testing.T, v vectors.Vector) {
		cb := v.Hex("cbor")
		if !bytes.Equal(cb, v.CBOR("message")) {
			t.Fatalf("cbor differs from typed JSON message")
		}
		m, err := wire.Decode(cb)
		if !v.Bool("expected_valid") {
			var de *wire.DecodeError
			if !errors.As(err, &de) || v.String("expected_error") != "protocol_error" {
				t.Fatalf("Decode = %v, want a DecodeError (protocol_error)", err)
			}
			return
		}
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if got := wire.Encode(m); !bytes.Equal(got, cb) {
			t.Fatalf("re-encoded %x, want %x", got, cb)
		}
	}, "integer_range")
}

// checkMapEntries checks a map vector's logical entries against its bytes:
// encoding the entries in their logical order and canonicalising gives the
// vector bytes.
func checkMapEntries(t *testing.T, v vectors.Vector, cb []byte) {
	t.Helper()
	var lg struct {
		Entries [][2]json.RawMessage `json:"entries"`
	}
	v.Into("logical", &lg)
	m := cbor.Map{}
	for _, e := range lg.Entries {
		k, err := vectors.TJSON(e[0])
		if err != nil {
			t.Fatal(err)
		}
		x, err := vectors.TJSON(e[1])
		if err != nil {
			t.Fatal(err)
		}
		m = append(m, cbor.Pair{Key: k, Value: x})
	}
	got, err := cbor.EncodeCanonical(m, cbor.Options{})
	if err != nil || !bytes.Equal(got, cb) {
		t.Fatalf("entries encode to %x", got)
	}
}

func paramsOf(t *testing.T, cb []byte) wire.Params {
	t.Helper()
	h := append(cbor.AppendArrayHead(nil, 8), 0x00, 0x81, 0x01, 0xa0, 0xf6, 0xf6, 0xf6)
	h = append(append(h, cb...), 0xf4)
	m, err := wire.Decode(h)
	if err != nil {
		t.Fatal(err)
	}
	return m.(*wire.Hello).Params
}

func parseFloatName(s string) (float64, error) {
	switch s {
	case "NaN":
		return math.NaN(), nil
	case "Infinity":
		return math.Inf(1), nil
	case "-Infinity":
		return math.Inf(-1), nil
	case "-0":
		return math.Copysign(0, -1), nil
	}
	return strconv.ParseFloat(s, 64)
}
