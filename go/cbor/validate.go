package cbor

import (
	"bytes"
	"math"
	"sort"
	"unicode/utf8"
)

// DefaultMaxDepth is the nesting limit of section 3.1.
const DefaultMaxDepth = 64

// Options select the rules Validate and Canonical enforce. The zero value is
// the wire profile of section 3.1 with a depth limit of 64 and tags 1 and 37.
type Options struct {
	// MaxDepth is the deepest allowed nesting level. Arrays, maps and tags
	// count, the outermost one is level 1, and scalars add no level, so a
	// message of 64 nested arrays holding a uint is nested 64 levels deep.
	// Zero means DefaultMaxDepth.
	MaxDepth int
	// ExtraTags lists tags a profile registered beyond 1 and 37.
	ExtraTags []uint64
	// NoFloats rejects floats anywhere (canonical data, section 3.2).
	NoFloats bool
	// RequirePreferred rejects integers, lengths and floats that are not in
	// preferred serialization. Section 3.1 obliges senders; receivers need
	// not check, so this is off by default.
	RequirePreferred bool
}

func (o Options) maxDepth() int {
	if o.MaxDepth <= 0 {
		return DefaultMaxDepth
	}
	return o.MaxDepth
}

func (o Options) tagAllowed(t uint64) bool {
	if t == TagEpochTime || t == TagUUID {
		return true
	}
	for _, x := range o.ExtraTags {
		if x == t {
			return true
		}
	}
	return false
}

// Validate checks that b is exactly one CBOR data item that follows the
// Sparrow rules of section 3.1: well-formed, definite lengths, valid UTF-8,
// unique map keys, only allowed tags (tag 1 holding an integer or float,
// tag 37 holding 16 bytes), simple values false/true/null only, and at most
// MaxDepth levels of nesting.
func Validate(b []byte, opt Options) error {
	d := NewDecoder(b)
	if _, err := walk(d, opt, 1, false); err != nil {
		return err
	}
	if !d.Done() {
		return errAt(d.off, "trailing bytes after data item")
	}
	return nil
}

// Canonical validates b like Validate and returns its Core Deterministic
// Encoding: preferred serialization everywhere and map keys sorted by the
// bytewise order of their encoded form.
func Canonical(b []byte, opt Options) (Raw, error) {
	d := NewDecoder(b)
	out, err := walk(d, opt, 1, true)
	if err != nil {
		return nil, err
	}
	if !d.Done() {
		return nil, errAt(d.off, "trailing bytes after data item")
	}
	return out, nil
}

// IsCanonical reports whether b is valid and already in Core Deterministic
// Encoding.
func IsCanonical(b []byte, opt Options) bool {
	c, err := Canonical(b, opt)
	return err == nil && bytes.Equal(c, b)
}

// walk validates one item. When emit is set it returns the canonical
// re-encoding; map keys are always re-encoded canonically to check
// uniqueness, so duplicate keys in non-preferred form are caught too.
//
// depth is the level the item would have if it is an array, map or tag:
// only those count (section 3.1), so a scalar inside a level-64 array is
// fine.
func walk(d *Decoder, opt Options, depth int, emit bool) ([]byte, error) {
	start := d.off
	h, err := d.peek()
	if err != nil {
		return nil, err
	}
	if (h.major == MajorArray || h.major == MajorMap || h.major == MajorTag) && depth > opt.maxDepth() {
		return nil, errAt(d.off, "nesting deeper than %d levels", opt.maxDepth())
	}
	if opt.RequirePreferred && !h.preferred() {
		return nil, errAt(start, "integer or length not in shortest form")
	}
	d.off += h.size
	var out []byte
	switch h.major {
	case MajorUint, MajorNeg:
		if emit {
			out = AppendHead(nil, h.major, h.arg)
		}
	case MajorBytes, MajorText:
		if h.arg > uint64(len(d.b)-d.off) {
			return nil, &Error{start, truncMsg}
		}
		s := d.b[d.off : d.off+int(h.arg)]
		d.off += int(h.arg)
		if h.major == MajorText && !utf8.Valid(s) {
			return nil, errAt(start, "invalid UTF-8 in text string")
		}
		if emit {
			out = append(AppendHead(nil, h.major, h.arg), s...)
		}
	case MajorArray:
		if h.arg > uint64(len(d.b)-d.off) {
			return nil, errAt(start, "array length %d exceeds remaining input", h.arg)
		}
		if emit {
			out = AppendHead(nil, MajorArray, h.arg)
		}
		for i := uint64(0); i < h.arg; i++ {
			e, err := walk(d, opt, depth+1, emit)
			if err != nil {
				return nil, err
			}
			out = append(out, e...)
		}
	case MajorMap:
		if h.arg > uint64(len(d.b)-d.off)/2 {
			return nil, errAt(start, "map size %d exceeds remaining input", h.arg)
		}
		type pair struct{ k, v []byte }
		pairs := make([]pair, 0, h.arg)
		seen := make(map[string]struct{}, h.arg)
		for i := uint64(0); i < h.arg; i++ {
			koff := d.off
			k, err := walk(d, opt, depth+1, true)
			if err != nil {
				return nil, err
			}
			if _, dup := seen[string(k)]; dup {
				return nil, errAt(koff, "duplicate map key")
			}
			seen[string(k)] = struct{}{}
			v, err := walk(d, opt, depth+1, emit)
			if err != nil {
				return nil, err
			}
			pairs = append(pairs, pair{k, v})
		}
		if emit {
			sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].k, pairs[j].k) < 0 })
			out = AppendHead(nil, MajorMap, h.arg)
			for _, p := range pairs {
				out = append(append(out, p.k...), p.v...)
			}
		}
	case MajorTag:
		if !opt.tagAllowed(h.arg) {
			return nil, errAt(start, "tag %d is not allowed", h.arg)
		}
		if err := checkTagContent(d, h.arg); err != nil {
			return nil, err
		}
		c, err := walk(d, opt, depth+1, emit)
		if err != nil {
			return nil, err
		}
		if emit {
			out = append(AppendHead(nil, MajorTag, h.arg), c...)
		}
	case MajorSimple:
		switch h.info {
		case simpleFalse, simpleTrue, simpleNull:
			if emit {
				out = []byte{d.b[start]}
			}
		case infoFloat16, infoFloat32, infoFloat64:
			if opt.NoFloats {
				return nil, errAt(start, "float not allowed in canonical data")
			}
			var f float64
			switch h.info {
			case infoFloat16:
				f = float16ToFloat64(uint16(h.arg))
			case infoFloat32:
				f = float64(math.Float32frombits(uint32(h.arg)))
			default:
				f = math.Float64frombits(h.arg)
			}
			c := AppendFloat(nil, f)
			if opt.RequirePreferred && len(c) != h.size {
				return nil, errAt(start, "float not in shortest exact width")
			}
			if emit {
				out = c
			}
		case simpleUndefined:
			return nil, errAt(start, "undefined is not allowed")
		default:
			return nil, errAt(start, "simple value %d is not allowed", h.arg)
		}
	}
	return out, nil
}

func checkTagContent(d *Decoder, tag uint64) error {
	h, err := d.peek()
	if err != nil {
		return err
	}
	switch tag {
	case TagEpochTime:
		isFloat := h.major == MajorSimple && h.info >= infoFloat16 && h.info <= infoFloat64
		if h.major != MajorUint && h.major != MajorNeg && !isFloat {
			return errAt(d.off, "tag 1 must hold an integer or float")
		}
	case TagUUID:
		if h.major != MajorBytes || h.arg != 16 {
			return errAt(d.off, "tag 37 must hold a 16-byte byte string")
		}
	}
	return nil
}

// StripSelfDescribed removes a leading tag 55799, which MAY prefix a stored
// schema file (section 3.5) but MUST NOT appear on the wire.
func StripSelfDescribed(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xd9 && b[1] == 0xd9 && b[2] == 0xf7 {
		return b[3:]
	}
	return b
}
