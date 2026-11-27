package wire

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/fuzzseed"
)

// checkFields exercises the accessors of a decoded message: none may panic,
// and what they accept must survive re-encoding.
func checkFields(t *testing.T, m Message) {
	switch m := m.(type) {
	case *Hello:
		checkParams(t, m.Params, Client)
		_ = m.CheckOptimistic()
		if m.ClientSchema != nil && m.ClientSchema.Schema.IsNull() {
			t.Fatal("inline schema decoded as null")
		}
	case *Welcome:
		checkParams(t, m.Params, Server)
		if m.ServerSchema.Kind >= offerKindsCount {
			t.Fatalf("offer kind %d", m.ServerSchema.Kind)
		}
	case *Request:
		checkMetadata(t, m.Metadata)
		f := ForwardRequest(m, m.CallID+2, m.FacetID+1, m.Metadata.Clone())
		r, err := Decode(f)
		if err != nil {
			t.Fatalf("forwarded request does not decode: %v", err)
		}
		if !bytes.Equal(r.(*Request).Input, m.Input) {
			t.Fatal("forwarding changed the input")
		}
	case *Headers:
		checkMetadata(t, m.Metadata)
	case *End:
		checkMetadata(t, m.Trailers)
	}
}

func checkParams(t *testing.T, p Params, sender Role) {
	l := p.Limits(sender)
	err := p.Validate()
	var pe *ParamError
	if err != nil && !errors.As(err, &pe) {
		t.Fatalf("Validate: %T %v", err, err)
	}
	if err == nil && (l.MaxMessageSize < MinMaxMessageSize || l.MaxInlineBytes < MinMaxInlineBytes ||
		l.SharedCredit < MinSharedCredit || l.LeaseCredit < MinLeaseCredit || l.MaxConcurrentCalls < MinMaxConcurrentCalls) {
		t.Fatalf("Validate accepted limits below the minimums: %+v", l)
	}
	_ = l.BelowDefaults(sender)
	_ = InitialCredit(l, false, nil)
	_ = InitialCredit(l, true, nil)
	for k := range p.Extra {
		if isParamKey(k) {
			t.Fatalf("known key %q kept in Extra", k)
		}
	}
}

func checkMetadata(t *testing.T, md Metadata) {
	_, _, _ = md.Deadline()
	_, _, _ = md.Credit()
	_, _, _ = md.Context()
	_, _, _ = md.Principal()
	if tr, ok, err := md.Trace(); err == nil && ok && len(tr) != TraceLen {
		t.Fatalf("trace of %d bytes accepted", len(tr))
	}
	e := md.AppendTo(nil)
	d := cbor.NewDecoder(e)
	md2, err := readMetadata(d)
	if err != nil || !d.Done() || len(md2) != len(md) {
		t.Fatalf("metadata round trip: %v", err)
	}
	if !bytes.Equal(md2.AppendTo(nil), e) {
		t.Fatal("metadata encoding not stable")
	}
}

// FuzzFrameReader reads a stream of length-prefixed frames: every frame
// returned fits the limit, and the frames read re-frame to the bytes
// consumed. The limit can be huge: the reader must not allocate what a
// length prefix claims before the bytes arrive.
func FuzzFrameReader(f *testing.F) {
	f.Add(uint64(1<<16), []byte{0x02, 0x81, 0x00, 0x01, 0xf6})
	f.Add(uint64(16384), []byte{0x40, 0x05, 1, 2, 3, 4, 5})
	f.Add(uint64(1<<62), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0})
	f.Add(uint64(1<<40), []byte{0xc0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 3})
	f.Add(uint64(3), []byte{0x00, 0x04, 1, 2, 3, 4})
	for _, b := range fuzzseed.Hex("framing.json") {
		f.Add(uint64(DefaultMaxMessageSize), b)
	}
	f.Fuzz(func(t *testing.T, max uint64, b []byte) {
		fr := NewFrameReader(bytes.NewReader(b), max)
		rest := b // the model: frames parsed by hand
		for {
			msg, err := fr.ReadFrame()
			n, k, perr := ParseVarint(rest)
			if err != nil {
				var tl *TooLargeError
				switch {
				case err == io.EOF:
					if len(rest) != 0 {
						t.Fatalf("EOF with %x left", rest)
					}
				case err == io.ErrUnexpectedEOF:
					if perr == nil && uint64(len(rest)-k) >= n {
						t.Fatalf("unexpected EOF with a whole frame left: %x", rest)
					}
				case err == ErrEmptyFrame:
					if perr != nil || n != 0 {
						t.Fatal("empty frame")
					}
				case errors.As(err, &tl):
					if tl.Size <= max || tl.Max != max || tl.Size != n {
						t.Fatalf("TooLarge %d/%d with limit %d", tl.Size, tl.Max, max)
					}
				default:
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if perr != nil || uint64(len(msg)) != n || !bytes.Equal(msg, rest[k:k+int(n)]) {
				t.Fatalf("frame %x does not match the input %x", msg, rest)
			}
			if len(msg) == 0 || uint64(len(msg)) > max {
				t.Fatalf("frame of %d bytes with limit %d", len(msg), max)
			}
			if cap(msg) > 2*len(msg) && cap(msg) > frameChunk {
				t.Fatalf("frame buffer of %d bytes for %d bytes", cap(msg), len(msg))
			}
			rest = rest[k+int(n):]
		}
	})
}

// FuzzVarint checks the QUIC varint parsers against each other and the
// encoder.
func FuzzVarint(f *testing.F) {
	f.Add([]byte{0x25})
	f.Add([]byte{0x7b, 0xbd})
	f.Add([]byte{0x9d, 0x7f, 0x3e, 0x7d})
	f.Add([]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c})
	f.Add([]byte{0x40, 0x25})
	f.Fuzz(func(t *testing.T, b []byte) {
		v, n, err := ParseVarint(b)
		r, rerr := ReadVarint(bytes.NewReader(b))
		if err != nil {
			if rerr == nil {
				t.Fatalf("ReadVarint accepted %x", b)
			}
			return
		}
		if rerr != nil || r != v || n < 1 || n > 8 || v > MaxVarint {
			t.Fatalf("ParseVarint %d/%d, ReadVarint %d %v", v, n, r, rerr)
		}
		e := AppendVarint(nil, v)
		if len(e) > n {
			t.Fatalf("shortest form %x longer than %x", e, b[:n])
		}
		if v2, n2, err := ParseVarint(e); err != nil || v2 != v || n2 != len(e) {
			t.Fatal("round trip")
		}
	})
}

// A length prefix alone does not make the reader allocate the length.
func TestFrameReaderAllocatesWhatArrives(t *testing.T) {
	hdr := AppendVarint(nil, 1<<30)
	in := append(hdr, make([]byte, 1000)...)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := NewFrameReader(bytes.NewReader(in), 1<<31).ReadFrame()
	runtime.ReadMemStats(&after)
	if err != io.ErrUnexpectedEOF {
		t.Fatal(err)
	}
	allocs := after.TotalAlloc - before.TotalAlloc
	if allocs > 1<<20 {
		t.Fatalf("%d bytes allocated for a frame header and 1000 bytes", allocs)
	}
}
