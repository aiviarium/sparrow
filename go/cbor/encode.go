// Package cbor is the small CBOR (RFC 8949) layer under Sparrow.
//
// It provides exactly what the protocol needs and nothing more:
//
//   - append-style encoders that always write preferred serialization
//     (shortest heads, shortest exact float width, definite lengths);
//   - a pull Decoder that returns views into the input and checks every
//     length against the remaining bytes before allocating;
//   - Validate, which enforces the Sparrow subset of CBOR (section 3.1):
//     definite lengths, valid UTF-8, unique map keys, only the allowed tags,
//     no undefined or other simple values, a nesting limit;
//   - Canonical, which re-encodes an item with Core Deterministic Encoding
//     (RFC 8949, section 4.2.1), as needed for hashing and signing;
//   - a generic value tree (Decode / Encode) for tests and tools.
//
// Raw holds one encoded data item; protocol layers keep payloads as Raw so a
// hub can forward them byte for byte.
package cbor

import (
	"math"
)

// Major types.
const (
	MajorUint   byte = 0
	MajorNeg    byte = 1
	MajorBytes  byte = 2
	MajorText   byte = 3
	MajorArray  byte = 4
	MajorMap    byte = 5
	MajorTag    byte = 6
	MajorSimple byte = 7
)

// Tags Sparrow uses (section 3.5).
const (
	TagEpochTime      uint64 = 1
	TagUUID           uint64 = 37
	TagSelfDescribed  uint64 = 55799
	simpleFalse       byte   = 20
	simpleTrue        byte   = 21
	simpleNull        byte   = 22
	simpleUndefined   byte   = 23
	infoFloat16       byte   = 25
	infoFloat32       byte   = 26
	infoFloat64       byte   = 27
	infoIndefinite    byte   = 31
	encodedNull       byte   = 0xf6
	encodedEmptyMap   byte   = 0xa0
	encodedEmptyArray byte   = 0x80
)

// Raw is one encoded CBOR data item. A nil Raw encodes as null.
type Raw []byte

// Null is the encoding of null.
var Null = Raw{encodedNull}

// IsNull reports whether r is nil or the encoding of null.
func (r Raw) IsNull() bool { return len(r) == 0 || (len(r) == 1 && r[0] == encodedNull) }

// AppendHead appends a head with the shortest argument encoding.
func AppendHead(dst []byte, major byte, arg uint64) []byte {
	m := major << 5
	switch {
	case arg < 24:
		return append(dst, m|byte(arg))
	case arg <= math.MaxUint8:
		return append(dst, m|24, byte(arg))
	case arg <= math.MaxUint16:
		return append(dst, m|25, byte(arg>>8), byte(arg))
	case arg <= math.MaxUint32:
		return append(dst, m|26, byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	}
	return append(dst, m|27, byte(arg>>56), byte(arg>>48), byte(arg>>40), byte(arg>>32),
		byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
}

// AppendUint appends an unsigned integer.
func AppendUint(dst []byte, v uint64) []byte { return AppendHead(dst, MajorUint, v) }

// AppendInt appends a signed integer.
func AppendInt(dst []byte, v int64) []byte {
	if v >= 0 {
		return AppendHead(dst, MajorUint, uint64(v))
	}
	return AppendHead(dst, MajorNeg, uint64(-(v + 1)))
}

// AppendNeg appends the negative integer -1-n.
func AppendNeg(dst []byte, n uint64) []byte { return AppendHead(dst, MajorNeg, n) }

// AppendBytes appends a byte string.
func AppendBytes(dst, b []byte) []byte {
	return append(AppendHead(dst, MajorBytes, uint64(len(b))), b...)
}

// AppendText appends a text string. The caller is responsible for UTF-8.
func AppendText(dst []byte, s string) []byte {
	return append(AppendHead(dst, MajorText, uint64(len(s))), s...)
}

// AppendArrayHead appends the head of an array of n elements.
func AppendArrayHead(dst []byte, n int) []byte { return AppendHead(dst, MajorArray, uint64(n)) }

// AppendMapHead appends the head of a map of n pairs.
func AppendMapHead(dst []byte, n int) []byte { return AppendHead(dst, MajorMap, uint64(n)) }

// AppendTag appends a tag head.
func AppendTag(dst []byte, tag uint64) []byte { return AppendHead(dst, MajorTag, tag) }

// AppendBool appends true or false.
func AppendBool(dst []byte, v bool) []byte {
	if v {
		return append(dst, 0xe0|simpleTrue)
	}
	return append(dst, 0xe0|simpleFalse)
}

// AppendNull appends null.
func AppendNull(dst []byte) []byte { return append(dst, encodedNull) }

// AppendRaw appends an encoded item; a nil or empty Raw appends null.
func AppendRaw(dst []byte, r Raw) []byte {
	if len(r) == 0 {
		return AppendNull(dst)
	}
	return append(dst, r...)
}

// AppendFloat appends f in the shortest width that keeps its value exact
// (RFC 8949, section 4.1). NaN is written as the canonical f97e00.
func AppendFloat(dst []byte, f float64) []byte {
	if math.IsNaN(f) {
		return append(dst, 0xf9, 0x7e, 0x00)
	}
	if h, ok := float16Exact(f); ok {
		return append(dst, 0xe0|infoFloat16, byte(h>>8), byte(h))
	}
	if f32 := float32(f); float64(f32) == f {
		b := math.Float32bits(f32)
		return append(dst, 0xe0|infoFloat32, byte(b>>24), byte(b>>16), byte(b>>8), byte(b))
	}
	b := math.Float64bits(f)
	return append(dst, 0xe0|infoFloat64, byte(b>>56), byte(b>>48), byte(b>>40), byte(b>>32),
		byte(b>>24), byte(b>>16), byte(b>>8), byte(b))
}

// float16Exact returns the IEEE 754 binary16 bits of f if f is exactly
// representable as a half-precision float.
func float16Exact(f float64) (uint16, bool) {
	var sign uint16
	if math.Signbit(f) {
		sign = 0x8000
	}
	a := math.Abs(f)
	switch {
	case math.IsInf(f, 0):
		return sign | 0x7c00, true
	case a == 0:
		return sign, true
	case a < 0x1p-14: // subnormal: m * 2^-24, 0 < m < 1024
		m := a * 0x1p24
		if m != math.Trunc(m) || m >= 1024 {
			return 0, false
		}
		return sign | uint16(m), true
	}
	frac, exp := math.Frexp(a) // a = frac * 2^exp, frac in [0.5, 1)
	m := frac * 2048           // in [1024, 2048)
	if m != math.Trunc(m) {
		return 0, false
	}
	e := exp - 1 + 15
	if e < 1 || e > 30 {
		return 0, false
	}
	return sign | uint16(e)<<10 | (uint16(m) - 1024), true
}

// float16ToFloat64 converts binary16 bits to a float64.
func float16ToFloat64(h uint16) float64 {
	sign := 1.0
	if h&0x8000 != 0 {
		sign = -1
	}
	e := int(h>>10) & 0x1f
	m := float64(h & 0x3ff)
	switch e {
	case 0:
		return sign * m * 0x1p-24
	case 31:
		if m == 0 {
			return math.Inf(int(sign))
		}
		return math.NaN()
	}
	return sign * (1 + m/1024) * math.Ldexp(1, e-15)
}
