package main

import (
	"fmt"
	"math"
	"strconv"

	"github.com/fxamacker/cbor/v2"
)

func encVec(name, desc, spec, rule string, typ any, logical O, value any, extra ...any) O {
	b := enc(value)
	v := o(
		"name", name,
		"description", desc,
		"spec", spec,
		"type", "value",
		"rule", rule,
		"schema_type", typ,
		"logical", logical,
		"value", tj(value),
		"diag", diag(b),
		"cbor", hx(b),
	)
	return append(v, o(extra...)...)
}

type fieldVal struct {
	tag  int
	name string
	v    any
}

// structValue applies section 3.4: element i holds the field with tag i,
// absent fields are null, trailing nulls are omitted.
func structValue(fields []fieldVal) []any {
	max := -1
	for _, f := range fields {
		if f.v != nil && f.tag > max {
			max = f.tag
		}
	}
	out := make([]any, max+1)
	for _, f := range fields {
		if f.v != nil {
			out[f.tag] = f.v
		}
	}
	return out
}

func sparseValue(fields []fieldVal) map[any]any {
	out := map[any]any{}
	for _, f := range fields {
		if f.v != nil {
			out[f.tag] = f.v
		}
	}
	return out
}

func fieldsLogical(typeName string, fields []fieldVal) O {
	var fs []any
	for _, f := range fields {
		fs = append(fs, o("tag", f.tag, "name", f.name, "value", tj(f.v)))
	}
	return o("type", typeName, "fields", fs)
}

func encodingVectors() O {
	var vs []any
	add := func(v O) { vs = append(vs, v) }

	// Integers: shortest form.
	ints := []struct {
		decl string
		v    any
	}{
		{"uint", 0}, {"uint", 23}, {"uint", 24}, {"uint", 255}, {"uint", 256}, {"uint", 65535}, {"uint", 65536},
		{"uint", uint64(4294967295)}, {"uint", uint64(4294967296)}, {"uint", uint64(9007199254740991)},
		{"uint", uint64(9007199254740992)}, {"uint", uint64(math.MaxUint64)},
		{"int", -1}, {"int", -24}, {"int", -25}, {"int", -256}, {"int", -257}, {"int", int64(math.MinInt64)},
	}
	for _, c := range ints {
		add(encVec("int/"+c.decl+"/"+fmt.Sprint(c.v),
			"Integers MUST use the shortest form.", "3.1, 6.3", "int", tUintOrInt(c.decl),
			o("declared", c.decl, "value", tj(c.v)), c.v))
	}
	// Floats: shortest width that keeps the value exact.
	floats := []struct {
		decl, s string
		desc    string
	}{
		{"float64", "1.5", "Exact in half precision."},
		{"float64", "1", "Integral float value 1.0 declared float64: shortest exact width is half precision. A JavaScript sender may also send integer 0x01, which decoders MUST accept (section 3.1). Floats never appear in canonical data (section 3.2)."},
		{"float64", "100000", "Integral float 100000.0: not exact in half, exact in single precision."},
		{"float64", "65504", "Largest finite half-precision value."},
		{"float64", "5.960464477539063e-08", "Smallest positive half-precision subnormal."},
		{"float64", "0.1", "Not exact in single precision: needs double."},
		{"float32", "0.1", "Declared float32: the float32 value nearest 0.1 (0.10000000149011612) is exact in single precision."},
		{"float32", "3.4028234663852886e+38", "Largest finite float32."},
		{"float64", "1.0000000000000002", "Needs all 53 bits of mantissa."},
		{"float64", "1e+300", "Out of single-precision range."},
		{"float64", "-0", "Negative zero is a distinct half-precision value."},
		{"float64", "NaN", "NaN in its canonical half-precision form 0xf97e00 (RFC 8949, section 4.2.1)."},
		{"float64", "Infinity", "Positive infinity in half precision."},
		{"float64", "-Infinity", "Negative infinity in half precision."},
	}
	for _, f := range floats {
		x, err := strconv.ParseFloat(f.s, 64)
		if f.s == "NaN" {
			x, err = math.NaN(), nil
		}
		must(err)
		var val any = x
		if f.decl == "float32" {
			val = float32(x)
		}
		add(encVec("float/"+f.decl+"/"+f.s, f.desc, "3.1, 3.2", "float", f.decl,
			o("declared", f.decl, "value", f.s), val))
	}
	add(o(
		"name", "float/integer-on-wire",
		"description", "Decoders MUST accept an integer where a float type is declared (JavaScript cannot tell 3 from 3.0). The wire bytes 0x03 decode to float64 3.0; the canonical encoding of 3.0 is f94200.",
		"spec", "3.1",
		"type", "decode_only",
		"rule", "float_from_int",
		"schema_type", "float64",
		"cbor", "03",
		"decoded_float", "3",
		"canonical_cbor", hx(enc(3.0)),
	))

	// Structs.
	noteFields := []fieldVal{
		{0, "id", noteUUID}, {1, "title", "Groceries"}, {2, "body", "milk, eggs"}, {3, "tags", []any{"home"}},
		{4, "updated", ts(1795737600)}, {6, "color", sgGreen},
	}
	add(encVec("struct/note", "Note (type 64 of part 16): tag 5 is a tombstoned field (flag 0x4), encoded as null so later fields do not shift; tag 7 'pinned' is absent, so the trailing null is omitted.",
		"3.4", "struct", tyNote, fieldsLogical("acme.notes.Note", noteFields), structValue(noteFields)))
	noteNoBody := []fieldVal{{0, "id", noteUUID}, {1, "title", "Empty"}, {3, "tags", []any{}}, {4, "updated", ts(1795737600)}}
	add(encVec("struct/note-trailing-nulls", "Note with body and color absent: the null slot for body (tag 2) stays; tags 5 and 6 are trailing nulls and are omitted.",
		"3.4", "struct", tyNote, fieldsLogical("acme.notes.Note", noteNoBody), structValue(noteNoBody)))
	notePinned := append(append([]fieldVal{}, noteNoBody...), fieldVal{7, "pinned", true})
	add(encVec("struct/note-pinned", "Note with the deprecated field pinned (tag 7) set: slots 2, 5 and 6 are null.",
		"3.4", "struct", tyNote, fieldsLogical("acme.notes.Note", notePinned), structValue(notePinned)))
	panel := []fieldVal{{0, "name", "settings"}, {1, "focus", true}}
	add(encVec("struct/7.7-input", "The input struct of the section 7.7 example.", "3.4, 7.7", "struct", "OpenPanel (example, not in the test schema)",
		fieldsLogical("sparrow.ui.OpenPanel", panel), structValue(panel)))
	att := []fieldVal{{0, "name", "a.txt"}, {2, "data", 1}}
	add(encVec("struct/attachment-token", "Attachment (type 69) with mime absent and the [4] field carrying byte token 1.",
		"3.4, 7.8", "struct", tyAttachment, fieldsLogical("acme.notes.Attachment", att), structValue(att)))

	// Sparse structs.
	sp1 := []fieldVal{{2, "limit", 50}, {1, "color", sgGreen}}
	add(encVec("sparse/filter-two", "Sparse NoteFilter (type 65): a map from field tag to value, absent fields left out. Keys sorted (canonical order).",
		"3.4", "sparse_struct", tyFilter, fieldsLogical("acme.notes.NoteFilter", sp1), sparseValue(sp1)))
	add(encVec("sparse/filter-empty", "Sparse NoteFilter with every field absent: an empty map.",
		"3.4", "sparse_struct", tyFilter, fieldsLogical("acme.notes.NoteFilter", nil), sparseValue(nil)))
	sp3 := []fieldVal{{4, "tags", []any{"home", "work"}}, {0, "query", "milk"}, {3, "since", ts(1767225600)}}
	add(encVec("sparse/filter-three", "Sparse NoteFilter with query, since and tags.",
		"3.4", "sparse_struct", tyFilter, fieldsLogical("acme.notes.NoteFilter", sp3), sparseValue(sp3)))

	// Enum, union, any, symbol.
	add(encVec("enum/color-green", "Enum value: the sigil as a uint.", "3.4, 6.5", "enum", tyColor,
		o("type", "acme.notes.Color", "value_name", "acme.notes.Color.green", "sigil", sgGreen), sgGreen))
	add(encVec("union/change-upserted", "Union Change (type 67), variant 0 'upserted' carrying a Note.", "3.4", "union", tyChange,
		o("type", "acme.notes.Change", "variant_tag", 0, "variant", "upserted", "value", tj(structValue(noteFields))), []any{0, structValue(noteFields)}))
	add(encVec("union/change-deleted", "Union Change, variant 1 'deleted' carrying a NoteId (uuid).", "3.4", "union", tyChange,
		o("type", "acme.notes.Change", "variant_tag", 1, "variant", "deleted", "value", tj(note2UUID)), []any{1, note2UUID}))
	add(encVec("union/change-cleared", "Union Change, variant 2 'cleared' carrying unit (null).", "3.4", "union", tyChange,
		o("type", "acme.notes.Change", "variant_tag", 2, "variant", "cleared", "value", nil), []any{2, nil}))
	add(encVec("dynamic/note", "dynamic: [type_id, value] for a Note (a named type of the same part).", "3.4, 6.3", "dynamic", tDynamic,
		o("type_id", tyNote, "value", tj(structValue(noteFields))), []any{tyNote, structValue(noteFields)}))
	add(encVec("dynamic/string", "dynamic carrying a built-in string (type 6).", "3.4, 6.3", "dynamic", tDynamic,
		o("type_id", tString, "value", "hello"), []any{tString, "hello"}))
	add(encVec("symbol/with-sigil", "symbol whose string has a sigil (note.updated = 80): the sigil is sent.", "6.3", "symbol", tSymbol,
		o("text", "note.updated", "sigil", sgUpdated), sgUpdated))
	add(encVec("symbol/text", "symbol without a sigil: the text is sent.", "6.3", "symbol", tSymbol,
		o("text", "note.archived", "sigil", nil), "note.archived"))

	// Other built-ins.
	add(encVec("unit", "unit is null.", "6.3", "literal", tUnit, o("value", nil), nil))
	add(encVec("bool/true", "bool true.", "6.3", "literal", tBool, o("value", true), true))
	add(encVec("bytes/empty", "Empty byte string.", "3.4, 6.3", "literal", tBytes, o("value", tj([]byte{})), []byte{}))
	add(encVec("bytes/short", "Byte string.", "3.4, 6.3", "literal", tBytes, o("value", tj(unhex("00ff10"))), unhex("00ff10")))
	add(encVec("string/utf8", "Text string with non-ASCII UTF-8.", "3.1, 6.3", "literal", tString, o("value", "Grüße ✓"), "Grüße ✓"))
	add(encVec("timestamp/int", "timestamp: tag 1 + integer seconds (2026-11-27T00:00:00Z).", "3.5, 6.3", "literal", tTimestamp,
		o("value", tj(ts(1795737600))), ts(1795737600)))
	add(encVec("timestamp/float", "timestamp: tag 1 + float seconds (needs double precision).", "3.5, 6.3", "literal", tTimestamp,
		o("value", tj(cbor.Tag{Number: 1, Content: 1795737600.5})), cbor.Tag{Number: 1, Content: 1795737600.5}))
	add(encVec("timestamp/negative", "timestamp before 1970: tag 1 + negative integer.", "3.5, 6.3", "literal", tTimestamp,
		o("value", tj(cbor.Tag{Number: 1, Content: -1})), cbor.Tag{Number: 1, Content: -1}))
	add(encVec("uuid", "uuid: tag 37 + 16-byte byte string.", "3.5, 6.3", "literal", tUUID, o("value", tj(noteUUID)), noteUUID))
	add(encVec("list/strings", "List of strings ([0, 6]).", "3.4, 6.3", "literal", tList(tString), o("value", []any{"a", "b"}), []any{"a", "b"}))
	add(encVec("list/empty", "Empty list.", "3.4", "literal", tList(tString), o("value", []any{}), []any{}))

	// Maps and canonical key order.
	mapCase := func(name, desc string, typ any, entries [][2]any) {
		m := map[any]any{}
		var es []any
		for _, e := range entries {
			m[e[0]] = e[1]
			es = append(es, []any{tj(e[0]), tj(e[1])})
		}
		add(encVec(name, desc, "3.2, 3.4", "map", typ, o("entries", es), m))
	}
	mapCase("map/text-keys", "Map string => uint. Core Deterministic Encoding sorts keys by their encoded bytes, so \"b\" (61 62) sorts before \"aa\" (62 61 61): shorter strings first, unlike plain string order.",
		tMap(tString, tUint), [][2]any{{"aa", 1}, {"b", 2}, {"ab", 3}, {"a", 4}})
	mapCase("map/uint-keys", "Map uint => string: 24 (18 18) sorts after 23 (17).", tMap(tUint, tString),
		[][2]any{{256, "c"}, {24, "b"}, {23, "a"}, {0, "z"}})
	mapCase("map/metadata-hub", "Metadata with all core keys a hub sets when forwarding (section 10.6): deadline (32), context (36, bytes), principal (37, string), plus an application text key.",
		"metadata", [][2]any{{37, "user:alice"}, {"x-tenant", "acme"}, {36, hubContext}, {32, 4950}})
	mapCase("map/mixed-keys", "Mixed key types as in metadata ({* symbol => any}) or annotations: uints (major type 0) before negative ints (1) before text (3); bytewise order, so 24 (18 18) sorts before -1 (20).",
		"metadata / any map", [][2]any{{"x-tenant", "acme"}, {-1, "neg"}, {35, 262144}, {24, "u24"}, {1, "one"}, {"", "empty"}, {-25, "neg25"}})
	mapCase("map/params", "A params map (section 5.4) in canonical order.", "params",
		[][2]any{{"maxStreams", 32}, {"maxMessageSize", 4194304}, {"leaseCredit", 2097152}, {"idleTimeoutMs", 20000}, {"sharedCredit", 65536}, {"maxInlineBytes", 65536}, {"maxConcurrentCalls", 100}})
	return o("area", "encoding", "vectors", vs)
}

func tUintOrInt(decl string) any {
	if decl == "uint" {
		return tUint
	}
	return tInt
}
