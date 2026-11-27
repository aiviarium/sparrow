package main

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"

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
	add(encVec("struct/note", "Note (type 64 of facet 16): tag 5 is a tombstoned field (flag 0x4), encoded as null so later fields do not shift; tag 7 'pinned' is absent, so the trailing null is omitted.",
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
	add(encVec("dynamic/note", "dynamic: [type_id, value] for a Note (a named type of the same facet).", "3.4, 6.3", "dynamic", tDynamic,
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
	mapCase("map/mixed-keys", "A map with keys of mixed CBOR major types, as in a generic CBOR value (the CDDL `any` of an annotation value or of Error.details). These keys are not metadata symbols: -1 and -25 are not uints or text, and 1, 24 and 35 are not used as metadata keys here. Core Deterministic Encoding orders uints (major type 0) before negative ints (1) before text (3), bytewise, so 24 (18 18) sorts before -1 (20).",
		"any map", [][2]any{{"x-tenant", "acme"}, {-1, "neg"}, {35, 262144}, {24, "u24"}, {1, "one"}, {"", "empty"}, {-25, "neg25"}})
	mapCase("map/params", "A params map (section 5.4) in canonical order.", "params",
		[][2]any{{"maxStreams", 32}, {"maxMessageSize", 4194304}, {"leaseCredit", 2097152}, {"idleTimeoutMs", 20000}, {"sharedCredit", 65536}, {"maxInlineBytes", 65536}, {"maxConcurrentCalls", 100}})
	depthVectors(add)
	nonShortestVectors(add)
	integerRangeVectors(add)
	return o("area", "encoding", "vectors", vs)
}

func tUintOrInt(decl string) any {
	if decl == "uint" {
		return tUint
	}
	return tInt
}

// nestArrays wraps x in n arrays.
func nestArrays(n int, x any) any {
	for i := 0; i < n; i++ {
		x = []any{x}
	}
	return x
}

// nestMixed builds n levels alternating map {"k": ...} and array, with a
// tag 1 holding an integer as the innermost level.
func nestMixed(n int) any {
	var x any = cbor.Tag{Number: 1, Content: 0}
	for i := 1; i < n; i++ {
		if i%2 == 1 {
			x = []any{x}
		} else {
			x = map[string]any{"k": x}
		}
	}
	return x
}

func depthVectors(add func(O)) {
	cases := []struct {
		name, desc string
		value      any
	}{
		{"depth/64-arrays", "Item whose value is 63 nested arrays around the uint 1. With the message's own array as level 1, the message is nested exactly 64 levels deep and MUST be accepted; the scalar inside adds no level (3.1).", nestArrays(63, 1)},
		{"depth/65-arrays", "The same Item with one more array: nested 65 levels deep, so a decoder MUST reject it (3.1).", nestArrays(64, 1)},
		{"depth/64-mixed", "Item whose value alternates arrays and maps {\"k\": ...}, with tag 1 (an integer timestamp) as the innermost level: arrays, maps and tags all count, and the message is nested exactly 64 levels deep. Accepted (3.1).", nestMixed(63)},
		{"depth/65-mixed", "The same with one more level: the tag is level 65, so a decoder MUST reject the message (3.1).", nestMixed(64)},
	}
	for _, c := range cases {
		msg := []any{18, 6, c.value}
		b := enc(msg)
		d := nestDepth(msg)
		add(o("name", c.name, "description", c.desc, "spec", "3.1, 11", "type", "depth",
			"message", tj(msg), "cbor", hx(b), "depth", d, "max_depth", 64, "expected_valid", d <= 64))
	}
}

func nonShortestVectors(add func(O)) {
	cases := []struct {
		name, desc, cborHex string
		msg                 []any
	}{
		{"non-shortest/credit", "Credit [24, 6, 100] with a one-byte array length (98 03) and every integer in a longer form than needed (kind 19 00 18, call ID 1a 00000006, amount 19 0064). Senders use the shortest form; a receiver MUST accept this one as the same message (3.1).",
			"98 03 19 00 18 1a 00 00 00 06 19 00 64", []any{24, 6, 100}},
		{"non-shortest/float-width", "Item [18, 6, 1.5] with the float sent as a 64-bit float (fb) although half precision is exact. Decoders MUST accept any float width (3.1).",
			"83 12 06 fb 3f f8 00 00 00 00 00 00", []any{18, 6, 1.5}},
		{"non-shortest/text-length", "Error [20, 2, 13, \"hello\", null] with the text length written as 78 05 instead of 65 (3.1).",
			"85 14 02 0d 78 05 68 65 6c 6c 6f f6", []any{20, 2, 13, "hello", nil}},
		{"non-shortest/unsorted-metadata", "Request whose metadata lists the text key before sigil key 32. Ordinary messages need not sort map keys (3.2): this is another valid encoding of the same message.",
			"86 10 02 10 18 64 a2 68 78 2d 74 65 6e 61 6e 74 64 61 63 6d 65 18 20 19 13 88 d8 25 50 6f 1c 2e 4a 8b 3d 4f 5e 9a 7b 0c 1d 2e 3f 4a 5b",
			[]any{16, 2, 16, 100, map[any]any{32: 5000, "x-tenant": "acme"}, noteUUID}},
	}
	for _, c := range cases {
		b := unhex(c.cborHex)
		var back any
		must(cbor.Unmarshal(b, &back))
		if !bytes.Equal(enc(back), enc(c.msg)) || bytes.Equal(b, enc(c.msg)) {
			panic(c.name + ": non-shortest bytes do not decode to the message, or are shortest")
		}
		add(o("name", c.name, "description", c.desc, "spec", "3.1, 3.2", "type", "non_shortest",
			"message", tj(c.msg), "cbor", hx(b), "shortest_cbor", hx(enc(c.msg)), "expected_valid", true))
	}
}

// definedInts returns the integers message m defines itself (section 3.1):
// its kind, IDs, counts, credit, durations, timestamps, metadata sigil keys
// and the deadline and credit metadata values, params values, versions and
// schema-offer forms. Payloads (input, output, value, details), caps, props,
// auth and schemas are left out.
func definedInts(m []any) []any {
	out := []any{m[0]}
	at := func(i ...int) {
		for _, j := range i {
			if m[j] != nil {
				out = append(out, m[j])
			}
		}
	}
	list := func(v any) {
		if l, ok := v.([]any); ok {
			out = append(out, l...)
		}
	}
	md := func(v any) {
		for k, x := range v.(map[any]any) {
			if _, text := k.(string); text {
				continue
			}
			out = append(out, k)
			if s, _ := asInt(k); s == 32 || s == 35 {
				if _, isInt := asInt(x); isInt {
					out = append(out, x)
				}
			}
		}
	}
	params := func(v any) {
		for _, x := range v.(map[string]any) {
			out = append(out, x)
		}
	}
	switch k, _ := asInt(m[0]); k {
	case 0:
		list(m[1])
		params(m[6])
	case 1:
		at(1)
		out = append(out, m[5].([]any)[0])
		params(m[6])
	case 3, 4, 7, 8:
		at(1)
	case 6:
		at(1)
		if t, ok := m[2].(cbor.Tag); ok {
			out = append(out, t.Content)
		}
	case 9:
		at(1, 3)
		list(m[4])
	case 16:
		at(1, 2, 3)
		md(m[4])
	case 17, 18:
		at(1)
	case 19, 22:
		at(1)
		md(m[2])
	case 20, 23, 24:
		at(1, 2)
	case 21:
		at(1, 2, 3)
	case 25:
		at(1, 2)
	}
	return out
}

// asInt returns an integer of the vector values as an int64 (ok false for
// a non-integer, and for one beyond int64, given as uint64).
func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case uint64:
		if x > math.MaxInt64 {
			return math.MaxInt64, true
		}
		return int64(x), true
	}
	return 0, false
}

func integerRangeVectors(add func(O)) {
	const big = uint64(1 << 53)
	cases := []struct {
		name, desc string
		msg        []any
	}{
		{"range/call-id-max", "Request with call ID 2^53 - 2, the largest even (client) call ID within ±(2^53 - 1). Accepted.",
			[]any{16, uint64(big - 2), 16, 0, map[any]any{}, nil}},
		{"range/call-id-2^53", "Request with call ID 2^53. Every integer a message defines itself MUST lie within ±(2^53 - 1), so JavaScript holds it exactly; this message is a protocol_error.",
			[]any{16, big, 16, 0, map[any]any{}, nil}},
		{"range/facet-id", "Request naming facet ID 2^53: a protocol_error.",
			[]any{16, 2, big, 0, map[any]any{}, nil}},
		{"range/credit-max", "Credit granting 2^53 - 1 bytes. Accepted.",
			[]any{24, 6, uint64(maxSafe)}},
		{"range/credit-2^53", "Credit granting 2^53 bytes: a protocol_error, not a credit that saturates.",
			[]any{24, 6, big}},
		{"range/retry-after", "GoAway(unavailable) with retry_after_ms 2^53: a protocol_error.",
			[]any{9, 14, "", big, nil}},
		{"range/progress-done", "Progress with done = 2^53: a protocol_error.",
			[]any{21, 7, big, nil, nil}},
		{"range/bytes-token", "Bytes for token 2^53: a protocol_error.",
			[]any{25, 2, big, []byte{}, true}},
		{"range/ping-nonce", "Ping with nonce 2^53: a protocol_error.",
			[]any{7, big}},
		{"range/deadline-key", "Request whose deadline metadata key (32) is 2^53 ms: a protocol_error.",
			[]any{16, 2, 16, 0, map[any]any{32: big}, nil}},
		{"range/metadata-sigil-key", "Request with metadata sigil key 2^53: a protocol_error.",
			[]any{16, 2, 16, 0, map[any]any{big: 0}, nil}},
		{"range/expires-at-min", "AuthStatus(ok) whose expires_at is -(2^53 - 1) s. Accepted.",
			[]any{6, 0, cbor.Tag{Number: 1, Content: int64(-maxSafe)}}},
		{"range/expires-at", "AuthStatus(ok) whose expires_at is -(2^53) s: a protocol_error.",
			[]any{6, 0, cbor.Tag{Number: 1, Content: int64(-maxSafe - 1)}}},
		{"range/params", "Hello whose params set maxMessageSize to 2^53: a protocol_error.",
			[]any{0, []any{1}, map[string]any{}, nil, nil, nil, map[string]any{"maxMessageSize": big}, false}},
		{"range/uint-input", "Request whose input is the uint 2^64 - 1. Application values of type int or uint keep their full 64-bit range: the input is a payload, not an integer the message defines. Accepted.",
			[]any{16, 2, 16, 0, map[any]any{}, uint64(math.MaxUint64)}},
	}
	for _, c := range cases {
		valid := true
		for _, x := range definedInts(c.msg) {
			switch v := x.(type) {
			case uint64:
				valid = valid && v <= maxSafe
			case int64:
				valid = valid && v <= maxSafe && v >= -maxSafe
			}
		}
		if valid != !strings.Contains(c.desc, "protocol_error") {
			panic(c.name + ": verdict differs from the description")
		}
		b := enc(c.msg)
		v := o("name", c.name, "description", c.desc, "spec", "3.1", "type", "integer_range",
			"message", tj(c.msg), "diag", diag(b), "cbor", hx(b), "expected_valid", valid)
		if !valid {
			v = append(v, o("expected_error", "protocol_error")...)
		}
		add(v)
	}
}
