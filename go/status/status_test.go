package status

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTable(t *testing.T) {
	for c := Code(0); c <= 40; c++ {
		ws, err := WebSocketCloseCode(c)
		wt, err2 := WebTransportCode(c)
		if c.IsCore() != (err == nil) || c.IsCore() != (err2 == nil) {
			t.Errorf("%d: core %v, errors %v %v", c, c.IsCore(), err, err2)
		}
		if !c.IsCore() {
			if c.Name() != "" || c.AllowedIn(InGoAway) || !c.AllowedIn(InError) {
				t.Errorf("%d: application code", c)
			}
			continue
		}
		want := 4000 + int(c)
		if c == OK {
			want = 1000
		}
		if ws != want || wt != uint32(c) {
			t.Errorf("%d: ws %d wt %d", c, ws, wt)
		}
		if b, ok := FromWebSocketCloseCode(ws); !ok || b != c {
			t.Errorf("%d: FromWebSocketCloseCode", c)
		}
		if b, ok := FromWebTransportCode(wt); !ok || b != c {
			t.Errorf("%d: FromWebTransportCode", c)
		}
		if c.IsDefined() != (c <= MessageTooLarge) {
			t.Errorf("%d: IsDefined", c)
		}
	}
	for _, bad := range []int{0, 999, 1001, 4000, 4032, 1006} {
		if _, ok := FromWebSocketCloseCode(bad); ok {
			t.Errorf("FromWebSocketCloseCode(%d) accepted", bad)
		}
	}
	if _, ok := FromWebTransportCode(32); ok {
		t.Error("FromWebTransportCode(32)")
	}
	names := map[Code]string{OK: "ok", Unimplemented: "unimplemented", ProtocolError: "protocol_error",
		SchemaMismatch: "schema_mismatch", GoingAway: "going_away", MessageTooLarge: "message_too_large", 23: "(reserved)"}
	for c, n := range names {
		if c.Name() != n {
			t.Errorf("%d: %q", c, c.Name())
		}
	}
	if Code(65).String() != "status(65)" || Unavailable.String() != "unavailable" {
		t.Error("String")
	}
	if Unavailable.Retry() != RetryBackoff || OK.Retry() != RetryNotApplicable || Code(70).Retry() != RetryNo ||
		Unauthenticated.Retry() != RetryAfterReauth || GoingAway.Retry() != RetryNewSession {
		t.Error("Retry")
	}
	if _, ok := ByName("nope"); ok {
		t.Error("ByName")
	}
}

func TestTruncateReason(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 123, "short"},
		{"abc", 0, ""},
		{"aä", 2, "a"}, // ä is 2 bytes
		{"aä", 3, "aä"},
		{"€€", 4, "€"}, // € is 3 bytes
		{"€€", 5, "€"},
		{"€€", 6, "€€"},
		{"😀x", 3, ""},
		{"a\xffb", 123, "a�b"},
	}
	for _, tc := range tests {
		got := TruncateReason(tc.in, tc.max)
		if got != tc.want || len(got) > tc.max || !utf8.ValidString(got) {
			t.Errorf("TruncateReason(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
	long := strings.Repeat("ü", 1000)
	if got := TruncateReason(long, MaxWebSocketReason); len(got) != 122 {
		t.Errorf("len %d", len(got))
	}
}
