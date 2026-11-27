package value

import (
	"bytes"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/schema"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func facet() *schema.Facet {
	return &schema.Facet{
		ID: 16, Name: "acme.notes", Version: "1.0.0",
		Types: []schema.TypeDef{
			{Kind: schema.KindStruct, ID: 64, Name: "Note", Fields: []schema.Field{
				{Tag: 0, Name: "id", Type: schema.Named(schema.TypeUUID)},
				{Tag: 1, Name: "title", Type: schema.Named(schema.TypeString)},
				{Tag: 2, Name: "body", Type: schema.Optional(schema.Named(schema.TypeString)), Flags: schema.FieldOptional},
				{Tag: 3, Name: "gone", Type: schema.Named(schema.TypeString), Flags: schema.FieldOptional | schema.FieldRemoved},
				{Tag: 4, Name: "color", Type: schema.Named(66), Flags: schema.FieldOptional},
				{Tag: 5, Name: "parent", Type: schema.Optional(schema.Named(64))}, // required but nullable
			}},
			{Kind: schema.KindStruct, ID: 65, Name: "Filter", Flags: schema.StructSparse, Fields: []schema.Field{
				{Tag: 0, Name: "query", Type: schema.Named(schema.TypeString), Flags: schema.FieldOptional},
				{Tag: 2, Name: "limit", Type: schema.Named(schema.TypeUint), Flags: schema.FieldOptional},
			}},
			{Kind: schema.KindEnum, ID: 66, Name: "Color", Values: []uint64{70, 71}},
			{Kind: schema.KindUnion, ID: 67, Name: "Change", Fields: []schema.Field{
				{Tag: 0, Name: "upserted", Type: schema.Named(64)},
				{Tag: 1, Name: "old", Type: schema.Named(schema.TypeUint), Flags: schema.FieldRemoved},
				{Tag: 2, Name: "cleared", Type: schema.Named(schema.TypeUnit)},
			}},
			{Kind: schema.KindAlias, ID: 68, Name: "Tags", Target: schema.List(schema.Named(schema.TypeString))},
			{Kind: schema.KindStruct, ID: 69, Name: "Attachment", Fields: []schema.Field{
				{Tag: 0, Name: "name", Type: schema.Named(schema.TypeString)},
				{Tag: 1, Name: "data", Type: schema.ByteStream()},
			}},
			{Kind: schema.KindAlias, ID: 70, Name: "Counts", Target: schema.MapOf(schema.Named(schema.TypeString), schema.Named(schema.TypeInt))},
		},
		Sigils: []schema.Sigil{
			{ID: 70, Name: "Color.red"}, {ID: 71, Name: "Color.green"},
			{ID: 80, Name: "note.updated", Kind: schema.SigilSymbol},
		},
	}
}

func codec(t *testing.T) *Codec {
	t.Helper()
	c, err := New(facet())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var id = UUID{0x6f, 0x1c, 0x2e, 0x4a, 0x8b, 0x3d, 0x4f, 0x5e, 0x9a, 0x7b, 0x0c, 0x1d, 0x2e, 0x3f, 0x4a, 0x5b}

func TestEncode(t *testing.T) {
	c := codec(t)
	n := schema.Named
	tests := []struct {
		name string
		t    schema.TypeRef
		v    any
		want string
	}{
		{"unit", n(0), nil, "f6"},
		{"bool", n(1), true, "f5"},
		{"int", n(2), -25, "3818"},
		{"int from uint64", n(2), uint64(7), "07"},
		{"uint", n(3), uint64(math.MaxUint64), "1bffffffffffffffff"},
		{"float32 rounds", n(4), 0.1, "fa3dcccccd"},
		{"float64", n(5), 1.5, "f93e00"},
		{"float from int", n(5), 3, "f94200"},
		{"string", n(6), "hi", "626869"},
		{"bytes", n(7), []byte{1}, "4101"},
		{"timestamp", n(8), cbor.Unix(1795737600), "c11a6b08c800"},
		{"timestamp from time.Time", n(8), time.Unix(1795737600, 500000000), "c1fb41dac23200200000"},
		{"uuid", n(9), id, "d825506f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b"},
		{"uuid from bytes", n(9), id[:], "d825506f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b"},
		{"dynamic", n(10), Dynamic{Type: 6, Value: "x"}, "82066178"},
		{"dynamic named", n(10), Dynamic{Type: 66, Value: uint64(71)}, "82184218 47"},
		{"symbol with sigil", n(11), "note.updated", "1850"},
		{"symbol text", n(11), "other", "656f74686572"},
		{"symbol explicit", n(11), Symbol{Sigil: 99, HasSigil: true}, "1863"},
		{"enum", n(66), uint64(70), "1846"},
		{"struct trailing nulls", n(64), Struct{0: id, 1: "t"}, "82 d825506f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b 6174"},
		{"struct slots", n(64), Struct{0: id, 1: "t", 4: uint64(71)}, "85 d825506f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b 6174 f6 f6 1847"},
		{"struct explicit nil optional", n(64), Struct{0: id, 1: "t", 2: nil}, "82 d825506f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b 6174"},
		{"sparse", n(65), Struct{2: 50, 0: "q"}, "a2 00 6171 02 1832"},
		{"sparse empty", n(65), Struct{}, "a0"},
		{"union", n(67), Union{Tag: 2}, "8202f6"},
		{"alias list", n(68), []any{"a"}, "816161"},
		{"alias list of strings", n(68), []string{"a"}, "816161"},
		{"map sorted", n(70), cbor.Map{{Key: "bb", Value: 1}, {Key: "a", Value: -1}}, "a2 6161 20 626262 01"},
		{"map from Go map", n(70), map[string]any{"bb": 1, "a": -1}, "a2 6161 20 626262 01"},
		{"optional nil", schema.Optional(n(6)), nil, "f6"},
		{"nested token", n(69), Struct{0: "a", 1: Token(1)}, "82 6161 01"},
		{"top-level byte stream", schema.ByteStream(), nil, "f6"},
	}
	for _, tc := range tests {
		got, err := c.Encode(tc.t, tc.v)
		if err != nil || !bytes.Equal(got, unhex(tc.want)) {
			t.Errorf("%s: %x, %v; want %s", tc.name, got, err, tc.want)
			continue
		}
		if tc.t.Kind == schema.RefByteStream {
			continue
		}
		v, err := c.Decode(tc.t, got)
		if err != nil {
			t.Errorf("%s: decode: %v", tc.name, err)
			continue
		}
		if again, err := c.Encode(tc.t, v); err != nil || !bytes.Equal(again, got) {
			t.Errorf("%s: round trip %x, %v", tc.name, again, err)
		}
	}
}

func TestEncodeErrors(t *testing.T) {
	c := codec(t)
	n := schema.Named
	tests := []struct {
		name string
		t    schema.TypeRef
		v    any
	}{
		{"unit with value", n(0), 1},
		{"bool from int", n(1), 1},
		{"int out of range", n(2), uint64(math.MaxUint64)},
		{"negative uint", n(3), -1},
		{"string from bytes", n(6), []byte("x")},
		{"float from string", n(5), "1"},
		{"short uuid", n(9), []byte{1}},
		{"timestamp from int", n(8), 5},
		{"dynamic undefined type", n(10), Dynamic{Type: 99}},
		{"dynamic reaching [4]", n(10), Dynamic{Type: 69, Value: Struct{0: "a", 1: Token(1)}}},
		{"dynamic not Dynamic", n(10), "x"},
		{"symbol from int", n(11), 3},
		{"enum value not listed", n(66), uint64(72)},
		{"enum from string", n(66), "red"},
		{"struct missing required", n(64), Struct{0: id}},
		{"struct unknown tag", n(64), Struct{0: id, 1: "t", 9: 1}},
		{"struct removed field set", n(64), Struct{0: id, 1: "t", 3: "x"}},
		{"struct field type", n(64), Struct{0: id, 1: 5}},
		{"struct not Struct", n(64), map[string]any{}},
		{"union unknown variant", n(67), Union{Tag: 9}},
		{"union removed variant", n(67), Union{Tag: 1, Value: uint64(1)}},
		{"union not Union", n(67), 1},
		{"list not slice", n(68), "a"},
		{"map duplicate key", n(70), cbor.Map{{Key: "a", Value: 1}, {Key: "a", Value: 2}}},
		{"map not map", n(70), []any{}},
		{"undefined type", n(99), 1},
		{"zero token", n(69), Struct{0: "a", 1: Token(0)}},
		{"top-level stream", schema.Stream(n(6)), "x"},
		{"nested stream", schema.List(schema.Stream(n(6))), []any{"x"}},
		{"top-level byte stream with data", schema.ByteStream(), []byte{1}},
	}
	for _, tc := range tests {
		if b, err := c.Encode(tc.t, tc.v); err == nil {
			t.Errorf("%s: encoded %x", tc.name, b)
		}
	}
	// a cyclic Go value is cut off by the depth limit
	l := []any{nil}
	l[0] = l
	if _, err := c.EncodeInner(schema.Named(10), Dynamic{Type: 68, Value: l}); err == nil {
		t.Error("cyclic list encoded")
	}
	deep := []any{}
	for i := 0; i < 100; i++ {
		deep = []any{deep}
	}
	rec := schema.List(schema.Named(68))
	if _, err := c.EncodeInner(rec, deep); err == nil {
		t.Error("deep list encoded")
	}
}

func TestDecodeForwardCompatible(t *testing.T) {
	c := codec(t)
	n := schema.Named
	// extra trailing elements (fields a newer writer added) are skipped
	v, err := c.Decode(n(64), unhex("88 d825506f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b 6174 f6 6178 f6 f6 a1 01 02 83 01 02 03"))
	if err != nil {
		t.Fatal(err)
	}
	s := v.(Struct)
	if s[1] != "t" || len(s) != 2 {
		t.Fatalf("struct %v", s)
	}
	// an unknown sparse tag is skipped
	v, err = c.Decode(n(65), unhex("a2 00 6171 07 83 01 02 03"))
	if err != nil || len(v.(Struct)) != 1 {
		t.Fatalf("sparse %v %v", v, err)
	}
	// unknown enum values and variants are kept
	if v, err := c.Decode(n(66), unhex("1863")); err != nil || v.(uint64) != 99 {
		t.Fatalf("enum %v %v", v, err)
	}
	v, err = c.Decode(n(67), unhex("82 09 a1 01 02"))
	if err != nil {
		t.Fatal(err)
	}
	if u := v.(Union); u.Tag != 9 || !bytes.Equal(u.Value.(cbor.Raw), unhex("a10102")) {
		t.Fatalf("unknown variant %+v", u)
	}
	if v, err := c.Decode(n(5), unhex("03")); err != nil || v.(float64) != 3 {
		t.Fatal("integer where a float is declared")
	}
	if v, err := c.Decode(n(11), unhex("1850")); err != nil || v.(Symbol).Text != "note.updated" {
		t.Fatalf("symbol %v", v)
	}
}

func TestDecodeErrors(t *testing.T) {
	c := codec(t)
	n := schema.Named
	tests := []struct {
		name string
		t    schema.TypeRef
		in   string
	}{
		{"not cbor", n(6), "ff"},
		{"trailing", n(3), "0000"},
		{"undefined", n(0), "f7"},
		{"int too large", n(2), "1bffffffffffffffff"},
		{"uint negative", n(3), "20"},
		{"uuid wrong tag", n(9), "c1 00"},
		{"uuid short", n(9), "d825 41 00"},
		{"timestamp untagged", n(8), "00"},
		{"dynamic length", n(10), "81 06"},
		{"dynamic undefined type", n(10), "82 1863 00"},
		{"dynamic reaching [4]", n(10), "82 1845 82 6161 01"},
		{"struct as map", n(64), "a0"},
		{"sparse as array", n(65), "80"},
		{"sparse key text", n(65), "a1 6161 00"},
		{"required field null", n(64), "82 f6 6174"},
		{"required field missing", n(64), "81 d825506f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b"},
		{"field of wrong type", n(64), "82 d825506f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b 01"},
		{"union length", n(67), "83 00 00 00"},
		{"token zero", n(69), "82 6161 00"},
		{"token text", n(69), "82 6161 6161"},
		{"top-level byte stream not null", schema.ByteStream(), "01"},
		{"top-level stream", schema.Stream(n(6)), "6161"},
		{"bool from int", n(1), "01"},
		{"list from map", n(68), "a0"},
		{"map from list", n(70), "80"},
		{"map value type", n(70), "a1 6161 6161"},
		{"undefined type", n(99), "00"},
	}
	for _, tc := range tests {
		if v, err := c.Decode(tc.t, unhex(tc.in)); err == nil {
			t.Errorf("%s: decoded %v", tc.name, v)
		}
	}
	if _, err := New(&schema.Facet{ID: 16, Name: "BAD"}); err == nil {
		t.Error("New accepted an invalid facet")
	}
	if (&Error{Msg: "x"}).Error() != "value: x" || (&Error{Path: "p", Msg: "x"}).Error() != "value: p: x" {
		t.Error("Error")
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"82 d825506f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b 6174", "a2 00 6171 02 1832", "8202f6",
		"82 1845 82 6161 01", "a2 6161 20 626262 01", "82066178"} {
		f.Add(uint8(0), unhex(s))
	}
	types := []schema.TypeRef{schema.Named(64), schema.Named(65), schema.Named(66), schema.Named(67),
		schema.Named(68), schema.Named(69), schema.Named(70), schema.Named(10), schema.Named(11), schema.Named(8),
		schema.Optional(schema.List(schema.Named(10)))}
	c, err := New(facet())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, which uint8, b []byte) {
		typ := types[int(which)%len(types)]
		v, err := c.Decode(typ, b)
		if err != nil {
			return
		}
		e, err := c.Encode(typ, v)
		if err != nil {
			return // e.g. unknown enum values or variants cannot be re-sent
		}
		v2, err := c.Decode(typ, e)
		if err != nil {
			t.Fatalf("re-encoded %x does not decode: %v", e, err)
		}
		e2, err := c.Encode(typ, v2)
		if err != nil || !bytes.Equal(e, e2) {
			t.Fatalf("encoding not stable %x %x", e, e2)
		}
	})
}
