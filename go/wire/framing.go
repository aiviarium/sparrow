// Package wire implements the Sparrow wire format: QUIC varints, the
// length-prefixed framing and stream header of section 4.1, the message
// envelope and kind ranges of section 3.3, typed encoders and decoders for
// every message of sections 5.4, 5.5 and 7.2, metadata and params maps,
// and credit accounting (section 7.4).
//
// Payload fields (input, output, value, details, data, trailers' values,
// schemas and deltas) are kept as cbor.Raw views so a hub can forward them
// byte for byte without decoding them.
package wire

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"
)

// MaxVarint is the largest value a QUIC variable-length integer holds.
const MaxVarint = 1<<62 - 1

// ErrVarintRange is returned when encoding a value above MaxVarint.
var ErrVarintRange = errors.New("wire: varint value out of range")

// VarintLen returns the length of the shortest encoding of v.
func VarintLen(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	}
	return 8
}

// AppendVarint appends the shortest QUIC varint encoding of v (RFC 9000,
// section 16). It panics if v > MaxVarint; use PutVarint for an error.
func AppendVarint(dst []byte, v uint64) []byte {
	b, err := PutVarint(dst, v)
	if err != nil {
		panic(err)
	}
	return b
}

// PutVarint is AppendVarint with an error for out-of-range values.
func PutVarint(dst []byte, v uint64) ([]byte, error) {
	switch {
	case v < 1<<6:
		return append(dst, byte(v)), nil
	case v < 1<<14:
		return append(dst, 0x40|byte(v>>8), byte(v)), nil
	case v < 1<<30:
		return append(dst, 0x80|byte(v>>24), byte(v>>16), byte(v>>8), byte(v)), nil
	case v <= MaxVarint:
		return append(dst, 0xc0|byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v)), nil
	}
	return dst, ErrVarintRange
}

// ParseVarint decodes a varint in any valid (possibly non-minimal) form
// from the start of b and returns its value and length.
func ParseVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, io.ErrUnexpectedEOF
	}
	v := uint64(b[0] & 0x3f)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n, nil
}

// ReadVarint reads a varint in any valid form. It returns io.EOF if r is
// at EOF before the first byte, and io.ErrUnexpectedEOF inside the varint.
func ReadVarint(r io.ByteReader) (uint64, error) {
	c, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := 1 << (c >> 6)
	v := uint64(c & 0x3f)
	for i := 1; i < n; i++ {
		c, err = r.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// TooLargeError reports a message longer than maxMessageSize; it maps to
// status message_too_large.
type TooLargeError struct {
	Size, Max uint64
}

func (e *TooLargeError) Error() string {
	return fmt.Sprintf("wire: message of %d bytes exceeds maxMessageSize %d", e.Size, e.Max)
}

// ErrEmptyFrame is returned for a zero-length frame, which cannot hold a
// CBOR data item.
var ErrEmptyFrame = errors.New("wire: empty frame")

// AppendFrame appends msg preceded by its length as a shortest-form varint.
func AppendFrame(dst, msg []byte) []byte {
	return append(AppendVarint(dst, uint64(len(msg))), msg...)
}

// FrameReader reads length-prefixed messages from a stream (section 4.1). It rejects a message longer than MaxMessageSize
// before reading or buffering its body.
type FrameReader struct {
	r   *bufio.Reader
	Max uint64
}

// NewFrameReader returns a FrameReader with the given maxMessageSize.
func NewFrameReader(r io.Reader, maxMessageSize uint64) *FrameReader {
	br, ok := r.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(r)
	}
	return &FrameReader{r: br, Max: maxMessageSize}
}

// ReadHeader reads the one-byte stream header the opener of a stream sends
// before its first message. Use it only on a stream the peer opened.
func (fr *FrameReader) ReadHeader() (byte, error) { return fr.r.ReadByte() }

// ReadFrame returns the next message. It returns io.EOF at a clean end of
// stream and io.ErrUnexpectedEOF if the stream ends inside a frame.
func (fr *FrameReader) ReadFrame() ([]byte, error) {
	n, err := ReadVarint(fr.r)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrEmptyFrame
	}
	if n > fr.Max {
		return nil, &TooLargeError{Size: n, Max: fr.Max}
	}
	// The buffer grows with the bytes that arrive, so a length prefix
	// alone (a few bytes) cannot make the reader allocate up to the limit.
	buf := make([]byte, 0, min(n, frameChunk))
	for uint64(len(buf)) < n {
		if len(buf) == cap(buf) {
			buf = slices.Grow(buf, int(min(n-uint64(len(buf)), uint64(cap(buf)))))
		}
		end := min(uint64(cap(buf)), n)
		k, err := io.ReadFull(fr.r, buf[len(buf):end])
		buf = buf[:len(buf)+k]
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
	return buf, nil
}

// frameChunk is the first buffer size for a frame; it doubles as the bytes
// arrive.
const frameChunk = 64 << 10

// FrameWriter writes length-prefixed messages.
type FrameWriter struct {
	w   io.Writer
	buf []byte
}

// NewFrameWriter returns a FrameWriter on w.
func NewFrameWriter(w io.Writer) *FrameWriter { return &FrameWriter{w: w} }

// WriteHeader writes a stream header byte; only the opener of a stream
// does this, once, before anything else.
func (fw *FrameWriter) WriteHeader(h byte) error {
	_, err := fw.w.Write([]byte{h})
	return err
}

// WriteFrame writes one message with its length prefix in a single Write.
func (fw *FrameWriter) WriteFrame(msg []byte) error {
	fw.buf = AppendFrame(fw.buf[:0], msg)
	_, err := fw.w.Write(fw.buf)
	return err
}

// Stream header bytes (section 4.1).
const (
	HeaderSharedLane byte = 0x00
	HeaderLeased     byte = 0x01
)

// Role is the side of a session.
type Role int

const (
	Client Role = iota
	Server
)

func (r Role) String() string {
	if r == Client {
		return "client"
	}
	return "server"
}

// StreamKind is what an opened stream is, according to its header byte.
type StreamKind int

const (
	SharedLane StreamKind = iota
	LeasedStream
	ProfileStream // 0x40-0x7F: reserved for profiles
)

// ErrStreamHeader is returned for a header byte that is a protocol_error.
var ErrStreamHeader = errors.New("wire: invalid stream header")

// ClassifyStreamHeader decides what a newly opened stream is from its
// header byte, the role of the peer that opened it, and whether the
// session already has a shared lane. Any value other than 0x00, 0x01 and
// 0x40-0x7F, a second shared lane, or a shared lane opened by the server
// is a protocol_error (section 4.1). Profile bytes are returned as
// ProfileStream; a peer without such a profile treats them as an error.
func ClassifyStreamHeader(h byte, opener Role, sharedLaneOpen bool) (StreamKind, error) {
	switch {
	case h == HeaderSharedLane:
		if opener != Client {
			return 0, fmt.Errorf("%w: shared lane opened by the server", ErrStreamHeader)
		}
		if sharedLaneOpen {
			return 0, fmt.Errorf("%w: a second shared lane", ErrStreamHeader)
		}
		return SharedLane, nil
	case h == HeaderLeased:
		return LeasedStream, nil
	case h >= 0x40 && h <= 0x7f:
		return ProfileStream, nil
	}
	return 0, fmt.Errorf("%w: byte 0x%02x", ErrStreamHeader, h)
}
