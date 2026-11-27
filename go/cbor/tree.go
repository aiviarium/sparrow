package cbor

import (
	"bytes"
	"fmt"
	"math"
	"sort"
)

// The generic value tree maps CBOR items to Go values:
//
//	unsigned integer  uint64
//	negative integer  int64 (or BigNeg below -2^63)
//	byte string       []byte
//	text string       string
//	array             []any
//	map               Map (pairs in received order)
//	tag               Tag
//	float             float64
//	false/true/null   bool / nil
//
// Encode additionally accepts int, int32, uint, uint32, float32, Raw,
// map[string]any and []byte.

// Pair is one map entry.
type Pair struct {
	Key, Value any
}

// Map is a CBOR map with its entries in order.
type Map []Pair

// Get returns the value for a key compared by encoded form.
func (m Map) Get(key any) (any, bool) {
	kb, err := Encode(key)
	if err != nil {
		return nil, false
	}
	for _, p := range m {
		if pk, err := Encode(p.Key); err == nil && bytes.Equal(pk, kb) {
			return p.Value, true
		}
	}
	return nil, false
}

// Tag is a tagged item.
type Tag struct {
	Number  uint64
	Content any
}

// BigNeg is a negative integer below the int64 range: its value is -1-N.
type BigNeg struct{ N uint64 }

// Decode validates b with opt and returns its value tree.
func Decode(b []byte, opt Options) (any, error) {
	if err := Validate(b, opt); err != nil {
		return nil, err
	}
	d := NewDecoder(b)
	return decodeTree(d)
}

// DecodeNext reads one item from d into a tree, without Sparrow validation.
func DecodeNext(d *Decoder) (any, error) { return decodeTree(d) }

func decodeTree(d *Decoder) (any, error) {
	start := d.off
	h, err := d.peek()
	if err != nil {
		return nil, err
	}
	switch h.major {
	case MajorUint:
		d.off += h.size
		return h.arg, nil
	case MajorNeg:
		d.off += h.size
		if h.arg > math.MaxInt64 {
			return BigNeg{h.arg}, nil
		}
		return -1 - int64(h.arg), nil
	case MajorBytes:
		b, err := d.Bytes()
		return append([]byte{}, b...), err
	case MajorText:
		return d.Text()
	case MajorArray:
		n, err := d.ArrayHead()
		if err != nil {
			return nil, err
		}
		out := make([]any, n)
		for i := range out {
			if out[i], err = decodeTree(d); err != nil {
				return nil, err
			}
		}
		return out, nil
	case MajorMap:
		n, err := d.MapHead()
		if err != nil {
			return nil, err
		}
		out := make(Map, n)
		for i := range out {
			if out[i].Key, err = decodeTree(d); err != nil {
				return nil, err
			}
			if out[i].Value, err = decodeTree(d); err != nil {
				return nil, err
			}
		}
		return out, nil
	case MajorTag:
		d.off += h.size
		c, err := decodeTree(d)
		if err != nil {
			return nil, err
		}
		return Tag{h.arg, c}, nil
	}
	switch h.info {
	case simpleFalse:
		d.off++
		return false, nil
	case simpleTrue:
		d.off++
		return true, nil
	case simpleNull:
		d.off++
		return nil, nil
	case infoFloat16, infoFloat32, infoFloat64:
		return d.Float()
	}
	return nil, errAt(start, "unsupported simple value")
}

// Encode encodes a value tree in preferred serialization. Map keeps its
// order; map[string]any is written in canonical key order.
func Encode(v any) ([]byte, error) { return AppendValue(nil, v) }

// EncodeCanonical encodes a value tree with Core Deterministic Encoding.
func EncodeCanonical(v any, opt Options) (Raw, error) {
	b, err := Encode(v)
	if err != nil {
		return nil, err
	}
	return Canonical(b, opt)
}

// AppendValue appends the encoding of a value tree.
func AppendValue(dst []byte, v any) ([]byte, error) {
	var err error
	switch x := v.(type) {
	case nil:
		return AppendNull(dst), nil
	case bool:
		return AppendBool(dst, x), nil
	case uint64:
		return AppendUint(dst, x), nil
	case uint:
		return AppendUint(dst, uint64(x)), nil
	case uint32:
		return AppendUint(dst, uint64(x)), nil
	case int:
		return AppendInt(dst, int64(x)), nil
	case int32:
		return AppendInt(dst, int64(x)), nil
	case int64:
		return AppendInt(dst, x), nil
	case BigNeg:
		return AppendNeg(dst, x.N), nil
	case float64:
		return AppendFloat(dst, x), nil
	case float32:
		return AppendFloat(dst, float64(x)), nil
	case []byte:
		return AppendBytes(dst, x), nil
	case string:
		return AppendText(dst, x), nil
	case Raw:
		return AppendRaw(dst, x), nil
	case []any:
		dst = AppendArrayHead(dst, len(x))
		for _, e := range x {
			if dst, err = AppendValue(dst, e); err != nil {
				return nil, err
			}
		}
		return dst, nil
	case Map:
		dst = AppendMapHead(dst, len(x))
		for _, p := range x {
			if dst, err = AppendValue(dst, p.Key); err != nil {
				return nil, err
			}
			if dst, err = AppendValue(dst, p.Value); err != nil {
				return nil, err
			}
		}
		return dst, nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		SortTextKeys(keys)
		dst = AppendMapHead(dst, len(x))
		for _, k := range keys {
			dst = AppendText(dst, k)
			if dst, err = AppendValue(dst, x[k]); err != nil {
				return nil, err
			}
		}
		return dst, nil
	case Tag:
		return AppendValue(AppendTag(dst, x.Number), x.Content)
	}
	return nil, fmt.Errorf("cbor: cannot encode %T", v)
}

// SortTextKeys sorts text map keys in Core Deterministic order: shorter
// keys first, then bytewise.
func SortTextKeys(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) < len(keys[j])
		}
		return keys[i] < keys[j]
	})
}

// ContainsFloat reports whether the well-formed item b contains a float
// anywhere. Malformed input reports false; validate it separately.
func ContainsFloat(b []byte) bool {
	found, _ := containsFloat(NewDecoder(b), 0)
	return found
}

func containsFloat(d *Decoder, depth int) (bool, error) {
	if depth > skipLimit {
		return false, errAt(d.off, "nesting too deep")
	}
	h, err := d.peek()
	if err != nil {
		return false, err
	}
	switch h.major {
	case MajorArray, MajorMap, MajorTag:
		d.off += h.size
		n := h.arg
		switch h.major {
		case MajorMap:
			if n > uint64(d.Remaining())/2 {
				return false, errAt(d.off, "map too long")
			}
			n *= 2
		case MajorTag:
			n = 1
		}
		if n > uint64(d.Remaining()) {
			return false, errAt(d.off, "array too long")
		}
		for i := uint64(0); i < n; i++ {
			f, err := containsFloat(d, depth+1)
			if f || err != nil {
				return f, err
			}
		}
		return false, nil
	case MajorSimple:
		if h.info >= infoFloat16 && h.info <= infoFloat64 {
			return true, nil
		}
	}
	return false, d.Skip()
}
