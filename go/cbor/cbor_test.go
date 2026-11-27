package cbor

import (
	"bytes"
	"encoding/hex"
	"math"
	"math/rand"
	"strings"
	"testing"
	"time"

	fx "github.com/fxamacker/cbor/v2"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func TestAppendInts(t *testing.T) {
	tests := []struct {
		v    int64
		want string
	}{
		{0, "00"}, {23, "17"}, {24, "1818"}, {255, "18ff"}, {256, "190100"},
		{65535, "19ffff"}, {65536, "1a00010000"}, {4294967295, "1affffffff"},
		{4294967296, "1b0000000100000000"}, {-1, "20"}, {-24, "37"}, {-25, "3818"},
		{-256, "38ff"}, {-257, "390100"}, {math.MinInt64, "3b7fffffffffffffff"},
		{math.MaxInt64, "1b7fffffffffffffff"},
	}
	for _, tc := range tests {
		if got := AppendInt(nil, tc.v); hex.EncodeToString(got) != tc.want {
			t.Errorf("AppendInt(%d) = %x, want %s", tc.v, got, tc.want)
		}
		d := NewDecoder(unhex(tc.want))
		if got, err := d.Int(); err != nil || got != tc.v {
			t.Errorf("Int(%s) = %d, %v", tc.want, got, err)
		}
	}
	if got := AppendUint(nil, math.MaxUint64); hex.EncodeToString(got) != "1bffffffffffffffff" {
		t.Errorf("max uint: %x", got)
	}
	if _, err := NewDecoder(unhex("1bffffffffffffffff")).Int(); err == nil {
		t.Error("Int accepted 2^64-1")
	}
	if _, err := NewDecoder(unhex("3bffffffffffffffff")).Int(); err == nil {
		t.Error("Int accepted -2^64")
	}
}

func TestAppendFloat(t *testing.T) {
	tests := []struct {
		f    float64
		want string
	}{
		{0, "f90000"}, {math.Copysign(0, -1), "f98000"}, {1, "f93c00"}, {1.5, "f93e00"},
		{65504, "f97bff"}, {65505, "fa477fe100"}, {100000, "fa47c35000"},
		{5.960464477539063e-08, "f90001"}, {6.103515625e-05, "f90400"}, {-4, "f9c400"},
		{0.1, "fb3fb999999999999a"}, {float64(float32(0.1)), "fa3dcccccd"},
		{3.4028234663852886e+38, "fa7f7fffff"}, {1e300, "fb7e37e43c8800759c"},
		{math.Inf(1), "f97c00"}, {math.Inf(-1), "f9fc00"}, {math.NaN(), "f97e00"},
		{1.0000000000000002, "fb3ff0000000000001"}, {2.9802322387695312e-08, "fa33000000"},
	}
	for _, tc := range tests {
		got := AppendFloat(nil, tc.f)
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("AppendFloat(%v) = %x, want %s", tc.f, got, tc.want)
		}
		back, err := NewDecoder(got).Float()
		if err != nil || (back != tc.f && !(math.IsNaN(back) && math.IsNaN(tc.f))) || math.Signbit(back) != math.Signbit(tc.f) {
			t.Errorf("Float(%x) = %v, %v", got, back, err)
		}
	}
}

// The shortest-float encoder agrees with fxamacker/cbor's on random values.
func TestAppendFloatDifferential(t *testing.T) {
	em, err := fx.EncOptions{ShortestFloat: fx.ShortestFloat16, NaNConvert: fx.NaNConvert7e00, InfConvert: fx.InfConvertFloat16}.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 200000; i++ {
		var f float64
		switch i % 4 {
		case 0:
			f = math.Float64frombits(r.Uint64())
		case 1:
			f = float64(math.Float32frombits(r.Uint32()))
		case 2:
			f = float16ToFloat64(uint16(r.Uint32()))
		default:
			f = float64(r.Intn(1<<20)) / float64(int(1)<<r.Intn(40))
		}
		want, err := em.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if got := AppendFloat(nil, f); !bytes.Equal(got, want) {
			t.Fatalf("AppendFloat(%v) = %x, fxamacker %x", f, got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		opt  Options
		ok   bool
	}{
		{"uint", "1818", Options{}, true},
		{"non-preferred uint accepted", "1801", Options{}, true},
		{"non-preferred uint strict", "1801", Options{RequirePreferred: true}, false},
		{"non-preferred float strict", "fa3fc00000", Options{RequirePreferred: true}, false},
		{"float16", "f93e00", Options{}, true},
		{"float forbidden", "f93e00", Options{NoFloats: true}, false},
		{"indefinite array", "9fff", Options{}, false},
		{"indefinite text", "7fff", Options{}, false},
		{"break", "ff", Options{}, false},
		{"reserved info", "1c", Options{}, false},
		{"undefined", "f7", Options{}, false},
		{"simple 0", "e0", Options{}, false},
		{"simple 255", "f8ff", Options{}, false},
		{"null true false", "83f6f5f4", Options{}, true},
		{"tag 1 int", "c11a6b08c800", Options{}, true},
		{"tag 1 float", "c1fb41dac23200200000", Options{}, true},
		{"tag 1 text", "c16161", Options{}, false},
		{"tag 37", "d825506f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b", Options{}, true},
		{"tag 37 short", "d825436f1c2e", Options{}, false},
		{"tag 2 bignum", "c249010000000000000000", Options{}, false},
		{"tag 55799", "d9d9f700", Options{}, false},
		{"extra tag", "d9d9f700", Options{ExtraTags: []uint64{TagSelfDescribed}}, true},
		{"invalid utf8", "62c328", Options{}, false},
		{"valid utf8", "62c3bc", Options{}, true},
		{"bytes not utf8 checked", "42c328", Options{}, true},
		{"dup keys", "a2616101616102", Options{}, false},
		{"dup keys non-preferred", "a201011801 02", Options{}, false},
		{"distinct keys", "a2616101616202", Options{}, true},
		{"trailing", "0000", Options{}, false},
		{"truncated text", "63616263"[:6], Options{}, false},
		{"truncated head", "19ff", Options{}, false},
		{"huge array", "9bffffffffffffffff", Options{}, false},
		{"huge map", "bbffffffffffffffff", Options{}, false},
		{"huge text", "7bffffffffffffffff", Options{}, false},
		{"empty", "", Options{}, false},
	}
	for _, tc := range tests {
		err := Validate(unhex(tc.in), tc.opt)
		if (err == nil) != tc.ok {
			t.Errorf("%s: Validate(%s) = %v, want ok=%v", tc.name, tc.in, err, tc.ok)
		}
	}
}

// nested returns n nested arrays around the uint 0: nesting depth n, since
// scalars add no level.
func nested(n int) []byte {
	b := bytes.Repeat([]byte{0x81}, n)
	return append(b, 0x00)
}

func TestValidateDepth(t *testing.T) {
	if err := Validate(nested(64), Options{}); err != nil {
		t.Errorf("depth 64: %v", err)
	}
	if err := Validate(nested(65), Options{}); err == nil {
		t.Error("depth 65 accepted")
	}
	if err := Validate(nested(10), Options{MaxDepth: 9}); err == nil {
		t.Error("MaxDepth 9 not enforced")
	}
	if err := Validate(nested(9), Options{MaxDepth: 9}); err != nil {
		t.Errorf("MaxDepth 9, depth 9: %v", err)
	}
	// tags count as a level
	deep := append(bytes.Repeat([]byte{0x81}, 63), 0xc1, 0x00)
	if err := Validate(deep, Options{}); err != nil {
		t.Errorf("63 arrays and a tag (depth 64): %v", err)
	}
	deep = append(bytes.Repeat([]byte{0x81}, 64), 0xc1, 0x00)
	if err := Validate(deep, Options{}); err == nil {
		t.Error("tag level not counted")
	}
	// maps count as a level
	deep = append(bytes.Repeat([]byte{0x81}, 64), 0xa0)
	if err := Validate(deep, Options{}); err == nil {
		t.Error("map level not counted")
	}
	// Skip and the tree decoder survive very deep input without Validate.
	d := NewDecoder(nested(100000))
	if err := d.Skip(); err == nil {
		t.Error("Skip accepted 100000 levels")
	}
}

func TestCanonical(t *testing.T) {
	tests := []struct{ in, want string }{
		{"a3 6161 01 6162 02 626161 03", "a3616101616202626161 03"},
		{"a2 626262 01 6161 02", "a2 6161 02 626262 01"},
		{"a2 1818 00 17 00", "a2170018 1800"},
		{"a2 20 00 01 00", "a2010020 00"},
		{"1801", "01"},
		{"5801 ff", "41ff"},
		{"83 1800 1900 01 1a00000002", "83000102"},
		{"fa3fc00000", "f93e00"},
		{"fb7ff8000000000001", "f97e00"},
		{"c1 1a6b08c800", "c11a6b08c800"},
		{"a1 a1 1801 00 00", "a1a1010000"},
	}
	for _, tc := range tests {
		got, err := Canonical(unhex(tc.in), Options{})
		if err != nil || !bytes.Equal(got, unhex(tc.want)) {
			t.Errorf("Canonical(%s) = %x, %v; want %s", tc.in, got, err, tc.want)
		}
		if !IsCanonical(unhex(tc.want), Options{}) {
			t.Errorf("IsCanonical(%s) = false", tc.want)
		}
	}
	if _, err := Canonical(unhex("f93e00"), Options{NoFloats: true}); err == nil {
		t.Error("float accepted with NoFloats")
	}
	if !ContainsFloat(unhex("a1616183 00 f93e00 01")) || ContainsFloat(unhex("a1616183 00 01 c100")) {
		t.Error("ContainsFloat")
	}
}

// Canonical agrees with fxamacker/cbor's Core Deterministic Encoding.
func TestCanonicalDifferential(t *testing.T) {
	em, err := fx.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewSource(2))
	var gen func(depth int) any
	gen = func(depth int) any {
		switch k := r.Intn(9); {
		case k == 0:
			return r.Uint64() >> uint(r.Intn(64))
		case k == 1:
			return -int64(r.Uint64()>>uint(1+r.Intn(63))) - 1
		case k == 2:
			b := make([]byte, r.Intn(30))
			r.Read(b)
			return b
		case k == 3:
			return strings.Repeat("ab", r.Intn(20))
		case k == 4 && depth < 4:
			n := r.Intn(5)
			xs := make([]any, n)
			for i := range xs {
				xs[i] = gen(depth + 1)
			}
			return xs
		case k == 5 && depth < 4:
			m := map[any]any{}
			for i := r.Intn(6); i > 0; i-- {
				var key any
				if r.Intn(2) == 0 {
					key = r.Uint64() >> uint(r.Intn(64))
				} else {
					key = strings.Repeat("k", r.Intn(30))
				}
				m[key] = gen(depth + 1)
			}
			return m
		case k == 6:
			return r.Intn(2) == 0
		}
		return nil
	}
	toTree := func(v any) any { return v }
	for i := 0; i < 3000; i++ {
		v := gen(0)
		want, err := em.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		// encode the same value non-canonically: maps in arbitrary order
		got, err := Canonical(want, Options{})
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("Canonical(%x) = %x, %v", want, got, err)
		}
		tree, err := Decode(want, Options{})
		if err != nil {
			t.Fatal(err)
		}
		shuffleMaps(r, tree)
		re, err := EncodeCanonical(toTree(tree), Options{})
		if err != nil || !bytes.Equal(re, want) {
			t.Fatalf("EncodeCanonical(shuffled) = %x, want %x", re, want)
		}
	}
}

func shuffleMaps(r *rand.Rand, v any) {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			shuffleMaps(r, e)
		}
	case Map:
		r.Shuffle(len(x), func(i, j int) { x[i], x[j] = x[j], x[i] })
		for _, p := range x {
			shuffleMaps(r, p.Value)
		}
	}
}

func TestDecoderErrors(t *testing.T) {
	d := NewDecoder(unhex("61 61"))
	if _, err := d.Uint(); err == nil {
		t.Error("Uint on text")
	}
	if _, err := d.Bytes(); err == nil {
		t.Error("Bytes on text")
	}
	if s, err := d.Text(); err != nil || s != "a" {
		t.Errorf("Text = %q, %v", s, err)
	}
	if _, err := d.Uint(); err == nil {
		t.Error("read past end")
	}
	if _, err := NewDecoder(unhex("8a00")).ArrayHead(); err == nil {
		t.Error("array longer than input")
	}
	if _, err := NewDecoder(unhex("a200")).MapHead(); err == nil {
		t.Error("map longer than input")
	}
	if _, err := NewDecoder(unhex("f6")).Bool(); err == nil {
		t.Error("Bool on null")
	}
	if err := NewDecoder(unhex("00")).Null(); err == nil {
		t.Error("Null on 0")
	}
	if _, err := NewDecoder(unhex("c200")).Time(); err == nil {
		t.Error("Time on tag 2")
	}
	tm, err := NewDecoder(unhex("c1fb41dac23200200000")).Time()
	if err != nil || !tm.IsFloat || tm.Seconds() != 1795737600.5 {
		t.Errorf("Time = %+v, %v", tm, err)
	}
	if b := AppendTime(nil, tm); !bytes.Equal(b, unhex("c1fb41dac23200200000")) {
		t.Errorf("AppendTime = %x", b)
	}
	if f, err := NewDecoder(unhex("20")).Float(); err != nil || f != -1 {
		t.Errorf("Float(-1) = %v %v", f, err)
	}
	r, err := NewDecoder(unhex("f6")).RawOrNull()
	if err != nil || r != nil {
		t.Error("RawOrNull(null)")
	}
	if !Raw(nil).IsNull() || !Null.IsNull() || (Raw{0}).IsNull() {
		t.Error("IsNull")
	}
}

func TestTreeRoundTrip(t *testing.T) {
	in := unhex("a4 01 82 f5 f6 20 c1 00 6161 41 00 3bffffffffffffffff f93e00")
	v, err := Decode(in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	m := v.(Map)
	if x, ok := m.Get(uint64(1)); !ok || len(x.([]any)) != 2 {
		t.Errorf("Get(1) = %v", x)
	}
	if x, _ := m.Get(BigNeg{N: math.MaxUint64}); x.(float64) != 1.5 {
		t.Errorf("BigNeg key: %v", x)
	}
	out, err := Encode(v)
	if err != nil || !bytes.Equal(out, in) {
		t.Errorf("Encode = %x, %v", out, err)
	}
	if _, err := Encode(struct{}{}); err == nil {
		t.Error("Encode accepted a struct")
	}
	if b, _ := Encode(map[string]any{"bb": 1, "a": 2, "c": 3}); !bytes.Equal(b, unhex("a3 6161 02 6163 03 626262 01")) {
		t.Errorf("text map order %x", b)
	}
}

func TestStripSelfDescribed(t *testing.T) {
	if b := StripSelfDescribed(unhex("d9d9f78100")); !bytes.Equal(b, unhex("8100")) {
		t.Errorf("%x", b)
	}
	if b := StripSelfDescribed(unhex("8100")); !bytes.Equal(b, unhex("8100")) {
		t.Errorf("%x", b)
	}
}

func FuzzValidate(f *testing.F) {
	for _, s := range []string{"00", "a2616101616202", "c11a6b08c800", "9fff", "83f6f5f4", "d825506f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b",
		"fb3fb999999999999a", "a201011801 02", "7bffffffffffffffff"} {
		f.Add(unhex(s))
	}
	seedVectors(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		err := Validate(b, Options{})
		c, cerr := Canonical(b, Options{})
		if (err == nil) != (cerr == nil) {
			t.Fatalf("Validate %v but Canonical %v", err, cerr)
		}
		_ = ContainsFloat(b)
		_ = NewDecoder(b).Skip()
		if err != nil {
			return
		}
		if c2, err := Canonical(c, Options{RequirePreferred: true}); err != nil || !bytes.Equal(c, c2) {
			t.Fatalf("Canonical not idempotent: %x -> %x (%v)", c, c2, err)
		}
		v, err := Decode(b, Options{})
		if err != nil {
			t.Fatal(err)
		}
		e, err := EncodeCanonical(v, Options{})
		if err != nil || !bytes.Equal(e, c) {
			t.Fatalf("tree round trip %x != %x (%v)", e, c, err)
		}
		if IsCanonical(b, Options{}) != bytes.Equal(b, c) {
			t.Fatal("IsCanonical disagrees with Canonical")
		}
		// Preferred-form input is accepted with RequirePreferred, and its
		// canonical form only reorders map keys: same length.
		if Validate(c, Options{RequirePreferred: true}) != nil {
			t.Fatalf("canonical form %x not preferred", c)
		}
		if Validate(b, Options{RequirePreferred: true}) == nil && len(b) != len(c) {
			t.Fatalf("preferred input %x changed length in canonical form %x", b, c)
		}
		// Tighter limits only reject more.
		if Validate(b, Options{MaxDepth: 2}) == nil && Validate(b, Options{MaxDepth: 3}) != nil {
			t.Fatal("depth limit not monotonic")
		}
		if Validate(b, Options{NoFloats: true}) == nil && ContainsFloat(b) {
			t.Fatal("NoFloats accepted a float")
		}
	})
}

// timestampMillis is shared with the TypeScript tests
// (ts/test/value.test.ts): seconds as float64, and the millisecond both
// implementations round them to (seconds*1000, nearest, halves up).
var timestampMillis = []struct {
	sec float64
	ms  int64
}{
	{1.001, 1001}, // 1000.9999999999999 ms: truncating would give 1000
	{1.0015, 1002},
	{-1.5005, -1500},
	{0.0005, 1},
	{-0.0005, 0},
	{-1.5, -1500},
	{-0.0015, -1},
	{0.00049999999999999994, 0}, // floor(y+0.5) would give 1
	{1e-9, 0},
	{-1e-9, 0},
	{1795780800.5, 1795780800500},
	{1795780800.0015, 1795780800002},
}

func TestTime(t *testing.T) {
	for _, c := range timestampMillis {
		if ms, ok := (Time{IsFloat: true, Float: c.sec}).UnixMilli(); !ok || ms != c.ms {
			t.Errorf("UnixMilli(%v) = %d, %v; want %d", c.sec, ms, ok, c.ms)
		}
	}
	if ms, ok := Unix(-3).UnixMilli(); !ok || ms != -3000 {
		t.Errorf("Unix(-3).UnixMilli() = %d, %v", ms, ok)
	}
	for _, bad := range []Time{{IsFloat: true, Float: math.NaN()}, {IsFloat: true, Float: math.Inf(-1)}, {IsFloat: true, Float: 1e300}, Unix(math.MaxInt64)} {
		if _, ok := bad.UnixMilli(); ok {
			t.Errorf("UnixMilli(%+v) ok", bad)
		}
	}
	// Integer seconds whenever there is no fraction (core 6.3).
	enc := []struct {
		t    Time
		want string
	}{
		{Unix(0), "c100"},
		{Unix(-1), "c120"},
		{Time{IsFloat: true, Float: 2}, "c102"},
		{Time{IsFloat: true, Float: -2}, "c121"},
		{Time{IsFloat: true, Float: math.Copysign(0, -1)}, "c100"},
		{Time{IsFloat: true, Float: 1.5}, "c1f93e00"},
		{Time{IsFloat: true, Float: -1.5}, "c1f9be00"},
		{FromTime(time.Unix(1795780800, 0)), "c11a6b0970c0"},
		{FromTime(time.Unix(-2, 500_000_000)), "c1f9be00"}, // -1.5 s
		{FromTime(time.UnixMilli(1795780800500)), "c1fb41dac25c30200000"},
	}
	for _, c := range enc {
		if got := hex.EncodeToString(AppendTime(nil, c.t)); got != c.want {
			t.Errorf("AppendTime(%+v) = %s, want %s", c.t, got, c.want)
		}
	}
	// FromTime and Time keep the time to well under a microsecond today.
	now := time.Unix(1795780800, 123_456_000)
	if d := FromTime(now).Time().Sub(now); d > time.Microsecond || d < -time.Microsecond {
		t.Errorf("round trip of %v is off by %v", now, d)
	}
	if got := (Time{IsFloat: true, Float: -1.5}).Time(); !got.Equal(time.Unix(-2, 500_000_000)) {
		t.Errorf("Time(-1.5) = %v", got)
	}
}

// TestSafeInts: SafeUint, SafeInt and Time refuse integers beyond
// ±(2^53 - 1), the bound of every integer a message defines (core 3.1),
// and consume nothing then.
func TestSafeInts(t *testing.T) {
	ok := []struct {
		in string
		u  bool
		v  int64
	}{
		{"1b001fffffffffffff", true, MaxSafeInt},
		{"00", true, 0},
		{"3b001ffffffffffffe", false, -MaxSafeInt},
	}
	for _, c := range ok {
		d := NewDecoder(unhex(c.in))
		var got int64
		var err error
		if c.u {
			var u uint64
			u, err = d.SafeUint()
			got = int64(u)
		} else {
			got, err = d.SafeInt()
		}
		if err != nil || got != c.v || !d.Done() {
			t.Errorf("%s: %d, %v", c.in, got, err)
		}
	}
	for _, in := range []string{"1b0020000000000000", "1bffffffffffffffff", "3b001fffffffffffff", "c1 1b0020000000000000", "c1 3b001fffffffffffff"} {
		b := unhex(in)
		d := NewDecoder(b)
		var err error
		switch {
		case b[0] == 0xc1:
			_, err = d.Time()
		case b[0]>>5 == MajorUint:
			if _, err = d.SafeUint(); err == nil {
				t.Errorf("SafeUint(%s) accepted", in)
			}
			_, err = d.SafeInt()
		default:
			_, err = d.SafeInt()
		}
		if err == nil || d.Offset() != 0 {
			t.Errorf("%s: accepted or consumed (%v, offset %d)", in, err, d.Offset())
		}
	}
	// An integral float beyond the bound stays a float.
	if got := hex.EncodeToString(AppendTime(nil, Time{IsFloat: true, Float: 1 << 53})); got != "c1fa5a000000" {
		t.Errorf("AppendTime(2^53) = %s", got)
	}
}
