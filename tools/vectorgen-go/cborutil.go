package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// All vectors are encoded with Core Deterministic Encoding (RFC 8949,
// section 4.2.1): shortest integers, shortest exact float width, definite
// lengths, map keys sorted bytewise by their encoded form. For ordinary
// messages this is one valid encoding (the spec does not require sorted
// keys there); for schemas and signed data it is the only valid one.
var (
	encMode  = mustMode(cbor.CoreDetEncOptions().EncMode())
	diagMode = mustMode(cbor.DiagOptions{FloatPrecisionIndicator: true}.DiagMode())
)

func mustMode[T any](m T, err error) T {
	must(err)
	return m
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func enc(v any) []byte {
	b, err := encMode.Marshal(v)
	must(err)
	return b
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	must(err)
	return b
}

func diag(b []byte) string {
	s, err := diagMode.Diagnose(b)
	must(err)
	return s
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Typed JSON ("tjson"): the readable form of a CBOR data item used in the
// vector files. See test-vectors/README.md.
// ---------------------------------------------------------------------------

const maxSafe = 1<<53 - 1

func tj(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case bool, string:
		return x
	case int:
		return tjInt(int64(x))
	case int64:
		return tjInt(x)
	case uint64:
		if x > maxSafe {
			return O{{"$int", strconv.FormatUint(x, 10)}}
		}
		return x
	case float64:
		return O{{"$float", fmtFloat(x)}}
	case float32:
		return O{{"$float", fmtFloat(float64(x))}}
	case []byte:
		return O{{"$bytes", hx(x)}}
	case cbor.Tag:
		return O{{"$tag", x.Number}, {"value", tj(x.Content)}}
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = tj(e)
		}
		return out
	case map[string]any:
		m := map[any]any{}
		for k, e := range x {
			m[k] = e
		}
		return tj(m)
	case map[any]any:
		type pair struct {
			k   any
			key []byte
		}
		var ps []pair
		allText := true
		for k := range x {
			s, ok := k.(string)
			if !ok || strings.HasPrefix(s, "$") {
				allText = false
			}
			ps = append(ps, pair{k, enc(k)})
		}
		sort.Slice(ps, func(i, j int) bool { return bytes.Compare(ps[i].key, ps[j].key) < 0 })
		if allText {
			out := O{}
			for _, p := range ps {
				out = append(out, kv{p.k.(string), tj(x[p.k])})
			}
			return out
		}
		pairs := []any{}
		for _, p := range ps {
			pairs = append(pairs, []any{tj(p.k), tj(x[p.k])})
		}
		return O{{"$map", pairs}}
	}
	panic(fmt.Sprintf("tj: unsupported type %T", v))
}

func tjInt(x int64) any {
	if x > maxSafe || x < -maxSafe {
		return O{{"$int", strconv.FormatInt(x, 10)}}
	}
	return x
}

func fmtFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0 && math.Signbit(f):
		return "-0"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// ---------------------------------------------------------------------------
// Ordered JSON objects, so the vector files are stable and readable.
// ---------------------------------------------------------------------------

type kv struct {
	k string
	v any
}

type O []kv

func o(args ...any) O {
	if len(args)%2 != 0 {
		panic("o: odd number of arguments")
	}
	out := O{}
	for i := 0; i < len(args); i += 2 {
		out = append(out, kv{args[i].(string), args[i+1]})
	}
	return out
}

func (m O) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, e := range m {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := marshalNoEscape(e.k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := marshalNoEscape(e.v)
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ---------------------------------------------------------------------------
// Small numeric helpers for generic trees.
// ---------------------------------------------------------------------------

func num(v any) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case uint64:
		return int64(x)
	}
	panic(fmt.Sprintf("num: not an integer: %T", v))
}

// deepCopy copies a generic value tree so that canonicalisation can sort in
// place without touching the original (unsorted) input.
func deepCopy(v any) any {
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	case map[any]any:
		out := map[any]any{}
		for k, e := range x {
			out[k] = deepCopy(e)
		}
		return out
	case []byte:
		return append([]byte{}, x...)
	case cbor.Tag:
		return cbor.Tag{Number: x.Number, Content: deepCopy(x.Content)}
	}
	return v
}

// QUIC variable-length integer (RFC 9000, section 16), shortest form.
func varint(v uint64) []byte {
	switch {
	case v < 1<<6:
		return []byte{byte(v)}
	case v < 1<<14:
		return []byte{0x40 | byte(v>>8), byte(v)}
	case v < 1<<30:
		return []byte{0x80 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
	case v < 1<<62:
		return []byte{0xc0 | byte(v>>56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
			byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	panic("varint: value too large")
}
