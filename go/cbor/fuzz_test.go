package cbor

import (
	"bytes"
	"errors"
	"testing"

	fx "github.com/fxamacker/cbor/v2"

	"github.com/aiviarium/sparrow-rpc/go/internal/fuzzseed"
)

// seedVectors adds every hex string of the test vectors.
func seedVectors(f *testing.F) {
	for _, b := range fuzzseed.Hex() {
		f.Add(b)
	}
	// nesting at and just past the limit (3.1)
	deep := func(n int) []byte { return append(bytes.Repeat([]byte{0x81}, n), 0x00) }
	f.Add(deep(DefaultMaxDepth))
	f.Add(deep(DefaultMaxDepth + 1))
	f.Add(append(bytes.Repeat([]byte{0xc1}, 3), 0x00))
}

var fxDec = func() fx.DecMode {
	m, err := fx.DecOptions{DupMapKey: fx.DupMapKeyEnforcedAPF, IndefLength: fx.IndefLengthForbidden,
		MaxNestedLevels: 256, MaxArrayElements: 1 << 20, MaxMapPairs: 1 << 20}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// FuzzDifferential checks the validator against fxamacker/cbor: whatever
// Validate accepts is well-formed CBOR without duplicate keys there too,
// and so is its canonical form.
func FuzzDifferential(f *testing.F) {
	seedVectors(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		if Validate(b, Options{}) != nil {
			return
		}
		if err := fxDec.Wellformed(b); err != nil {
			t.Fatalf("accepted %x, fxamacker: %v", b, err)
		}
		var v any
		if err := fxDec.Unmarshal(b, &v); err != nil {
			var dup *fx.DupMapKeyError
			if errors.As(err, &dup) {
				t.Fatalf("accepted %x with a duplicate key: %v", b, err)
			}
			// other errors are semantic (e.g. tag contents fxamacker types)
		}
		c, err := Canonical(b, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := fxDec.Wellformed(c); err != nil {
			t.Fatalf("canonical form %x, fxamacker: %v", c, err)
		}
	})
}

// FuzzDecoder drives the pull decoder with a script of reads chosen by the
// bytes of script: it never panics, never moves backwards or past the end,
// and a read that fails consumes nothing (DecodeNext aside).
func FuzzDecoder(f *testing.F) {
	f.Add([]byte{0, 1, 2}, []byte{0x83, 0x01, 0x62, 'h', 'i', 0xf6})
	f.Add([]byte{5, 3, 7, 9, 10}, []byte{0xa1, 0x61, 'k', 0xc1, 0x1a, 1, 2, 3, 4})
	f.Add([]byte{11, 12, 13, 14}, []byte{0xc1, 0xfb, 0x3f, 0xb9, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a})
	for _, b := range fuzzseed.Hex("encoding.json") {
		f.Add([]byte{14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, b)
	}
	f.Fuzz(func(t *testing.T, script, b []byte) {
		d := NewDecoder(b)
		for _, op := range script {
			before := d.Offset()
			var err error
			switch op % 17 {
			case 0:
				_, err = d.Uint()
			case 1:
				_, err = d.Int()
			case 2:
				_, err = d.Bool()
			case 3:
				var s []byte
				s, err = d.Bytes()
				if err == nil && s == nil {
					t.Fatal("Bytes returned nil")
				}
			case 4:
				_, err = d.Text()
			case 5:
				_, err = d.ArrayHead()
			case 6:
				_, err = d.MapHead()
			case 7:
				_, err = d.Tag()
			case 8:
				_, _ = d.PeekTag()
			case 9:
				var r Raw
				r, err = d.Raw()
				if err == nil && len(r) != d.Offset()-before {
					t.Fatal("Raw length")
				}
			case 10:
				_, err = d.Float()
			case 11:
				_, err = d.Time()
			case 12:
				err = d.Null()
			case 13:
				_, err = d.RawOrNull()
			case 14:
				err = d.Skip()
			case 15:
				_, err = DecodeNext(d)
			case 16:
				_, err = d.PeekMajor()
				_ = d.PeekNull()
				_ = d.IsFloat()
			}
			after := d.Offset()
			if after < before || after > len(b) || d.Remaining() != len(b)-after {
				t.Fatalf("op %d moved the offset %d -> %d of %d (%v)", op%17, before, after, len(b), err)
			}
			if err != nil && after != before && op%17 != 15 {
				t.Fatalf("op %d consumed input and failed: %v", op%17, err)
			}
		}
	})
}
