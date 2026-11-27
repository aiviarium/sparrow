package cbor

import (
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// Error is a decoding error at a byte offset.
type Error struct {
	Offset int
	Msg    string
}

func (e *Error) Error() string { return fmt.Sprintf("cbor: %s at offset %d", e.Msg, e.Offset) }

// ErrTruncated matches (errors.Is) errors for input that ends inside an
// item.
var ErrTruncated = errors.New("cbor: unexpected end of data")

const truncMsg = "unexpected end of data"

// Is reports whether the error is ErrTruncated.
func (e *Error) Is(target error) bool { return target == ErrTruncated && e.Msg == truncMsg }

func errAt(off int, f string, args ...any) error {
	return &Error{Offset: off, Msg: fmt.Sprintf(f, args...)}
}

// Decoder reads CBOR items from a byte slice. Strings and Raw items it
// returns are views into the input, not copies.
//
// The Decoder checks well-formedness of each head it reads and rejects
// indefinite lengths, but it does not by itself enforce the Sparrow subset;
// call Validate on untrusted input first.
type Decoder struct {
	b   []byte
	off int
}

// NewDecoder returns a Decoder reading b.
func NewDecoder(b []byte) *Decoder { return &Decoder{b: b} }

// Offset returns the current read position.
func (d *Decoder) Offset() int { return d.off }

// Done reports whether all input has been consumed.
func (d *Decoder) Done() bool { return d.off >= len(d.b) }

// Remaining returns the number of unread bytes.
func (d *Decoder) Remaining() int { return len(d.b) - d.off }

type head struct {
	major byte
	info  byte
	arg   uint64
	size  int // bytes taken by the head
}

func (d *Decoder) peek() (head, error) {
	if d.off >= len(d.b) {
		return head{}, &Error{d.off, truncMsg}
	}
	ib := d.b[d.off]
	h := head{major: ib >> 5, info: ib & 0x1f, size: 1}
	switch {
	case h.info < 24:
		h.arg = uint64(h.info)
	case h.info <= 27:
		n := 1 << (h.info - 24)
		if d.off+1+n > len(d.b) {
			return head{}, &Error{d.off, truncMsg}
		}
		for _, c := range d.b[d.off+1 : d.off+1+n] {
			h.arg = h.arg<<8 | uint64(c)
		}
		h.size += n
	case h.info == infoIndefinite:
		if h.major == MajorSimple {
			return head{}, errAt(d.off, "unexpected break")
		}
		if h.major == MajorUint || h.major == MajorNeg || h.major == MajorTag {
			return head{}, errAt(d.off, "malformed head 0x%02x", ib)
		}
		return head{}, errAt(d.off, "indefinite length is not allowed")
	default:
		return head{}, errAt(d.off, "reserved additional information %d", h.info)
	}
	return h, nil
}

// preferred reports whether the head uses the shortest argument encoding.
func (h head) preferred() bool {
	if h.major == MajorSimple {
		return true
	}
	switch h.info {
	case 24:
		return h.arg >= 24
	case 25:
		return h.arg > math.MaxUint8
	case 26:
		return h.arg > math.MaxUint16
	case 27:
		return h.arg > math.MaxUint32
	}
	return true
}

// PeekMajor returns the major type of the next item without consuming it.
func (d *Decoder) PeekMajor() (byte, error) {
	if d.off >= len(d.b) {
		return 0, &Error{d.off, truncMsg}
	}
	return d.b[d.off] >> 5, nil
}

// PeekNull reports whether the next item is null.
func (d *Decoder) PeekNull() bool { return d.off < len(d.b) && d.b[d.off] == encodedNull }

func (d *Decoder) expect(major byte, what string) (head, error) {
	h, err := d.peek()
	if err != nil {
		return h, err
	}
	if h.major != major || (major == MajorSimple) {
		return h, errAt(d.off, "expected %s, found %s", what, describe(h))
	}
	d.off += h.size
	return h, nil
}

func describe(h head) string {
	switch h.major {
	case MajorUint:
		return "unsigned integer"
	case MajorNeg:
		return "negative integer"
	case MajorBytes:
		return "byte string"
	case MajorText:
		return "text string"
	case MajorArray:
		return "array"
	case MajorMap:
		return "map"
	case MajorTag:
		return fmt.Sprintf("tag %d", h.arg)
	}
	switch h.info {
	case simpleFalse, simpleTrue:
		return "bool"
	case simpleNull:
		return "null"
	case simpleUndefined:
		return "undefined"
	case infoFloat16, infoFloat32, infoFloat64:
		return "float"
	}
	return "simple value"
}

// Null consumes a null.
func (d *Decoder) Null() error {
	if !d.PeekNull() {
		if d.off >= len(d.b) {
			return &Error{d.off, truncMsg}
		}
		h, err := d.peek()
		if err != nil {
			return err
		}
		return errAt(d.off, "expected null, found %s", describe(h))
	}
	d.off++
	return nil
}

// Uint reads an unsigned integer.
func (d *Decoder) Uint() (uint64, error) {
	h, err := d.expect(MajorUint, "unsigned integer")
	return h.arg, err
}

// Int reads an integer in the signed 64-bit range.
func (d *Decoder) Int() (int64, error) {
	h, err := d.peek()
	if err != nil {
		return 0, err
	}
	switch h.major {
	case MajorUint:
		if h.arg > math.MaxInt64 {
			return 0, errAt(d.off, "integer %d out of signed 64-bit range", h.arg)
		}
		d.off += h.size
		return int64(h.arg), nil
	case MajorNeg:
		if h.arg > math.MaxInt64 {
			return 0, errAt(d.off, "integer -1-%d out of signed 64-bit range", h.arg)
		}
		d.off += h.size
		return -1 - int64(h.arg), nil
	}
	return 0, errAt(d.off, "expected integer, found %s", describe(h))
}

// Bool reads true or false.
func (d *Decoder) Bool() (bool, error) {
	h, err := d.peek()
	if err != nil {
		return false, err
	}
	if h.major == MajorSimple && (h.info == simpleFalse || h.info == simpleTrue) {
		d.off++
		return h.info == simpleTrue, nil
	}
	return false, errAt(d.off, "expected bool, found %s", describe(h))
}

func (d *Decoder) str(major byte, what string) ([]byte, error) {
	start := d.off
	h, err := d.expect(major, what)
	if err != nil {
		return nil, err
	}
	if h.arg > uint64(len(d.b)-d.off) {
		d.off = start
		return nil, &Error{start, truncMsg}
	}
	s := d.b[d.off : d.off+int(h.arg) : d.off+int(h.arg)]
	d.off += int(h.arg)
	return s, nil
}

// Bytes reads a byte string and returns a view into the input. An empty
// byte string is returned as a non-nil empty slice.
func (d *Decoder) Bytes() ([]byte, error) {
	b, err := d.str(MajorBytes, "byte string")
	if err == nil && b == nil {
		b = []byte{}
	}
	return b, err
}

// Text reads a text string and checks that it is valid UTF-8.
func (d *Decoder) Text() (string, error) {
	start := d.off
	b, err := d.str(MajorText, "text string")
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", errAt(start, "invalid UTF-8 in text string")
	}
	return string(b), nil
}

// ArrayHead reads the head of an array and returns its length. The length
// is checked against the remaining input.
func (d *Decoder) ArrayHead() (int, error) {
	start := d.off
	h, err := d.expect(MajorArray, "array")
	if err != nil {
		return 0, err
	}
	if h.arg > uint64(len(d.b)-d.off) {
		d.off = start
		return 0, errAt(start, "array length %d exceeds remaining input", h.arg)
	}
	return int(h.arg), nil
}

// MapHead reads the head of a map and returns its number of pairs.
func (d *Decoder) MapHead() (int, error) {
	start := d.off
	h, err := d.expect(MajorMap, "map")
	if err != nil {
		return 0, err
	}
	if h.arg > uint64(len(d.b)-d.off)/2 {
		d.off = start
		return 0, errAt(start, "map size %d exceeds remaining input", h.arg)
	}
	return int(h.arg), nil
}

// Tag reads a tag head and returns the tag number.
func (d *Decoder) Tag() (uint64, error) {
	h, err := d.expect(MajorTag, "tag")
	return h.arg, err
}

// PeekTag returns the tag number if the next item is a tag.
func (d *Decoder) PeekTag() (uint64, bool) {
	h, err := d.peek()
	if err != nil || h.major != MajorTag {
		return 0, false
	}
	return h.arg, true
}

// IsFloat reports whether the next item is a float.
func (d *Decoder) IsFloat() bool {
	h, err := d.peek()
	return err == nil && h.major == MajorSimple && h.info >= infoFloat16 && h.info <= infoFloat64
}

// Float reads a float of any width. It also accepts an integer, as section
// 3.1 requires where a float type is declared.
func (d *Decoder) Float() (float64, error) {
	h, err := d.peek()
	if err != nil {
		return 0, err
	}
	switch {
	case h.major == MajorUint:
		d.off += h.size
		return float64(h.arg), nil
	case h.major == MajorNeg:
		d.off += h.size
		return -1 - float64(h.arg), nil
	case h.major == MajorSimple && h.info == infoFloat16:
		d.off += h.size
		return float16ToFloat64(uint16(h.arg)), nil
	case h.major == MajorSimple && h.info == infoFloat32:
		d.off += h.size
		return float64(math.Float32frombits(uint32(h.arg))), nil
	case h.major == MajorSimple && h.info == infoFloat64:
		d.off += h.size
		return math.Float64frombits(h.arg), nil
	}
	return 0, errAt(d.off, "expected float, found %s", describe(h))
}

// skipLimit bounds recursion in Skip; Validate enforces the real limit.
const skipLimit = 512

// Skip consumes one complete item.
func (d *Decoder) Skip() error { return d.skip(0) }

func (d *Decoder) skip(depth int) error {
	if depth > skipLimit {
		return errAt(d.off, "nesting too deep")
	}
	start := d.off
	h, err := d.peek()
	if err != nil {
		return err
	}
	d.off += h.size
	switch h.major {
	case MajorBytes, MajorText:
		if h.arg > uint64(len(d.b)-d.off) {
			d.off = start
			return &Error{start, truncMsg}
		}
		d.off += int(h.arg)
	case MajorArray, MajorMap:
		n := h.arg
		if h.major == MajorMap {
			if n > math.MaxUint64/2 {
				d.off = start
				return errAt(start, "map size overflow")
			}
			n *= 2
		}
		if n > uint64(len(d.b)-d.off) {
			d.off = start
			return errAt(start, "length %d exceeds remaining input", h.arg)
		}
		for i := uint64(0); i < n; i++ {
			if err := d.skip(depth + 1); err != nil {
				return err
			}
		}
	case MajorTag:
		return d.skip(depth + 1)
	case MajorSimple:
		if h.info < 24 && h.info != simpleFalse && h.info != simpleTrue && h.info != simpleNull && h.info != simpleUndefined {
			// unassigned simple values are well-formed; Validate rejects them
			return nil
		}
	}
	return nil
}

// Raw consumes one complete item and returns its bytes as a view.
func (d *Decoder) Raw() (Raw, error) {
	start := d.off
	if err := d.Skip(); err != nil {
		return nil, err
	}
	return Raw(d.b[start:d.off:d.off]), nil
}

// RawOrNull consumes one item; it returns nil if the item is null.
func (d *Decoder) RawOrNull() (Raw, error) {
	if d.PeekNull() {
		d.off++
		return nil, nil
	}
	return d.Raw()
}

// Time is a tag-1 epoch timestamp (section 3.5): integer seconds, or float
// seconds when IsFloat is set.
type Time struct {
	Sec     int64
	Float   float64
	IsFloat bool
}

// Unix returns an integer-seconds Time.
func Unix(sec int64) Time { return Time{Sec: sec} }

// Seconds returns the time in seconds as a float64.
func (t Time) Seconds() float64 {
	if t.IsFloat {
		return t.Float
	}
	return float64(t.Sec)
}

// AppendTime appends tag 1 and the time's integer or float seconds.
func AppendTime(dst []byte, t Time) []byte {
	dst = AppendTag(dst, TagEpochTime)
	if t.IsFloat {
		return AppendFloat(dst, t.Float)
	}
	return AppendInt(dst, t.Sec)
}

// Time reads a tag-1 timestamp holding an integer (signed 64-bit range) or
// a float.
func (d *Decoder) Time() (Time, error) {
	start := d.off
	tag, err := d.Tag()
	if err != nil {
		return Time{}, err
	}
	if tag != TagEpochTime {
		d.off = start
		return Time{}, errAt(start, "expected tag 1 timestamp, found tag %d", tag)
	}
	if d.IsFloat() {
		f, err := d.Float()
		return Time{Float: f, IsFloat: true}, err
	}
	s, err := d.Int()
	return Time{Sec: s}, err
}
