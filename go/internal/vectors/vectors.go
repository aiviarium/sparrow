// Package vectors loads the Sparrow RPC test vectors (test-vectors/*.json)
// and converts their "typed JSON" values into cbor value trees.
package vectors

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
)

// Dir returns the test-vectors directory: $SPARROW_VECTORS, or the
// repository's test-vectors directory.
func Dir() string {
	if d := os.Getenv("SPARROW_VECTORS"); d != "" {
		return d
	}
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "test-vectors")
}

// Vector is one test vector: its fields as raw JSON.
type Vector struct {
	Name   string
	Type   string
	Fields map[string]json.RawMessage
}

// File is one vector file.
type File struct {
	Name    string
	Header  map[string]json.RawMessage
	Vectors []Vector
}

// Files lists the vector files.
func Files() ([]string, error) {
	m, err := filepath.Glob(filepath.Join(Dir(), "*.json"))
	sort.Strings(m)
	return m, err
}

// Load reads one vector file by base name (e.g. "calls.json").
func Load(name string) (*File, error) {
	b, err := os.ReadFile(filepath.Join(Dir(), name))
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	var vs []map[string]json.RawMessage
	if err := json.Unmarshal(raw["vectors"], &vs); err != nil {
		return nil, err
	}
	f := &File{Name: name, Header: raw}
	for _, v := range vs {
		var n, t string
		_ = json.Unmarshal(v["name"], &n)
		_ = json.Unmarshal(v["type"], &t)
		f.Vectors = append(f.Vectors, Vector{Name: n, Type: t, Fields: v})
	}
	return f, nil
}

// Has reports whether the vector has a field.
func (v Vector) Has(k string) bool { _, ok := v.Fields[k]; return ok }

// String returns a string field.
func (v Vector) String(k string) string {
	var s string
	if err := json.Unmarshal(v.Fields[k], &s); err != nil {
		panic(fmt.Sprintf("%s: field %s: %v", v.Name, k, err))
	}
	return s
}

// Hex returns a hex-string field as bytes.
func (v Vector) Hex(k string) []byte { return MustHex(v.String(k)) }

// Bool returns a bool field.
func (v Vector) Bool(k string) bool {
	var b bool
	if err := json.Unmarshal(v.Fields[k], &b); err != nil {
		panic(fmt.Sprintf("%s: field %s: %v", v.Name, k, err))
	}
	return b
}

// Int returns an integer field.
func (v Vector) Int(k string) int64 {
	var n int64
	if err := json.Unmarshal(v.Fields[k], &n); err != nil {
		panic(fmt.Sprintf("%s: field %s: %v", v.Name, k, err))
	}
	return n
}

// Into unmarshals a field.
func (v Vector) Into(k string, out any) {
	if err := json.Unmarshal(v.Fields[k], out); err != nil {
		panic(fmt.Sprintf("%s: field %s: %v", v.Name, k, err))
	}
}

// CBOR converts a typed-JSON field to its canonical CBOR encoding.
func (v Vector) CBOR(k string) []byte {
	b, err := TJSONToCBOR(v.Fields[k])
	if err != nil {
		panic(fmt.Sprintf("%s: field %s: %v", v.Name, k, err))
	}
	return b
}

// MustHex decodes hex.
func MustHex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// TJSONToCBOR converts typed JSON to Core Deterministic CBOR.
func TJSONToCBOR(raw json.RawMessage) ([]byte, error) {
	t, err := TJSON(raw)
	if err != nil {
		return nil, err
	}
	b, err := cbor.Encode(t)
	if err != nil {
		return nil, err
	}
	return cbor.Canonical(b, cbor.Options{MaxDepth: 1000})
}

// TJSON converts typed JSON into a cbor value tree.
func TJSON(raw json.RawMessage) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return convert(v)
}

func convert(v any) (any, error) {
	switch x := v.(type) {
	case nil, bool, string:
		return x, nil
	case json.Number:
		return parseInt(string(x))
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			c, err := convert(e)
			if err != nil {
				return nil, err
			}
			out[i] = c
		}
		return out, nil
	case map[string]any:
		if s, ok := x["$int"].(string); ok && len(x) == 1 {
			return parseInt(s)
		}
		if s, ok := x["$float"].(string); ok && len(x) == 1 {
			return parseFloat(s)
		}
		if s, ok := x["$bytes"].(string); ok && len(x) == 1 {
			return hex.DecodeString(s)
		}
		if n, ok := x["$tag"].(json.Number); ok && len(x) == 2 {
			t, err := strconv.ParseUint(string(n), 10, 64)
			if err != nil {
				return nil, err
			}
			c, err := convert(x["value"])
			return cbor.Tag{Number: t, Content: c}, err
		}
		if ps, ok := x["$map"].([]any); ok && len(x) == 1 {
			m := cbor.Map{}
			for _, p := range ps {
				kv, ok := p.([]any)
				if !ok || len(kv) != 2 {
					return nil, fmt.Errorf("bad $map entry")
				}
				k, err := convert(kv[0])
				if err != nil {
					return nil, err
				}
				val, err := convert(kv[1])
				if err != nil {
					return nil, err
				}
				m = append(m, cbor.Pair{Key: k, Value: val})
			}
			return m, nil
		}
		out := map[string]any{}
		for k, e := range x {
			c, err := convert(e)
			if err != nil {
				return nil, err
			}
			out[k] = c
		}
		return out, nil
	}
	return nil, fmt.Errorf("unsupported JSON value %T", v)
}

func parseInt(s string) (any, error) {
	if strings.HasPrefix(s, "-") {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n, nil
		}
		u, err := strconv.ParseUint(s[1:], 10, 64)
		if err != nil {
			return nil, err
		}
		return cbor.BigNeg{N: u - 1}, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

func parseFloat(s string) (float64, error) {
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
