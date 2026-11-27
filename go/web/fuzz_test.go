package web

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/fuzzseed"
	"github.com/aiviarium/sparrow-rpc/go/names"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/websign"
)

var fuzzKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))

// FuzzTicket feeds tickets to Parse: arbitrary strings, and tickets with
// arbitrary header and claims JSON signed with the edge's key (so the
// claim checks are reached). Whatever is accepted meets every rule of 9.2.
func FuzzTicket(f *testing.F) {
	now := time.Unix(1_800_000_000, 0)
	tk := &Tickets{Key: fuzzKey, Audience: "edge-1", Now: func() time.Time { return now }}
	good, _, err := tk.Issue(&Login{Principal: "user:alice", Session: "s", Expires: now.Add(time.Hour)})
	if err != nil {
		f.Fatal(err)
	}
	parts := strings.Split(good, ".")
	hb, _ := b64.DecodeString(parts[0])
	pb, _ := b64.DecodeString(parts[1])
	f.Add(good, hb, pb)
	f.Add("a.b.c", []byte(`{"alg":"none"}`), []byte(`{}`))
	f.Add("", []byte(`{"alg":"EdDSA"}`), []byte(`{"sub":"user:a","sid":"s","aud":"edge-1","iat":1800000000,"exp":1800000030,"jti":"j","sexp":1800003600}`))
	f.Add("", []byte(`{"alg":"EdDSA"}`), []byte(`{"sub":"user:a","sid":"s","aud":"edge-1","iat":-9223372036854775808,"exp":9223372036854775807,"jti":"j","sexp":9223372036854775807}`))
	f.Fuzz(func(t *testing.T, raw string, header, claims []byte) {
		if c, err := tk.Parse(raw); err == nil && raw != good {
			// only tickets signed with the key pass; the fuzzer cannot
			// forge one, so anything else accepted is a bug
			checkClaims(t, c, now)
			in := raw[:strings.LastIndexByte(raw, '.')]
			sig, _ := b64.DecodeString(raw[strings.LastIndexByte(raw, '.')+1:])
			if !ed25519.Verify(fuzzKey.Public().(ed25519.PublicKey), []byte(in), sig) {
				t.Fatal("accepted a ticket without a valid signature")
			}
		}
		in := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
		signed := in + "." + b64.EncodeToString(ed25519.Sign(fuzzKey, []byte(in)))
		c, err := tk.Parse(signed)
		if err != nil {
			return
		}
		var h jwtHeader
		if json.Unmarshal(header, &h) != nil || h.Alg != "EdDSA" {
			t.Fatal("accepted a header that is not EdDSA")
		}
		checkClaims(t, c, now)
	})
}

func checkClaims(t *testing.T, c *Claims, now time.Time) {
	t.Helper()
	n := now.Unix()
	switch {
	case c.Audience != "edge-1":
		t.Fatalf("accepted aud %q", c.Audience)
	case c.Expires <= n:
		t.Fatal("accepted an expired ticket")
	case c.IssuedAt == 0:
		t.Fatal("accepted a ticket without iat")
	case c.IssuedAt > c.Expires || c.Expires > c.IssuedAt+60 || c.IssuedAt+60 < c.IssuedAt:
		t.Fatalf("accepted exp %d not within 60 s of iat %d", c.Expires, c.IssuedAt)
	case c.SessionExpires <= n:
		t.Fatal("accepted a ticket whose login session ended")
	case !names.IsPrincipal(c.Subject) || c.LoginSession == "" || c.ID == "":
		t.Fatalf("accepted claims %+v", c)
	}
}

// FuzzEntry decodes web-module entries; an accepted entry re-encodes to
// one that decodes the same, and its hostApi range parses.
func FuzzEntry(f *testing.F) {
	for _, b := range fuzzseed.Hex("signing.json") {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := DecodeEntry(b)
		if err != nil {
			return
		}
		if !names.IsModuleID(e.ID()) || len(e.Hash()) != 33 {
			t.Fatal("entry checks")
		}
		raw, err := e.Module.Encode()
		if err != nil {
			return // floats in unknown fields
		}
		e2, err := DecodeEntry(raw)
		if err != nil {
			t.Fatalf("re-encoded entry: %v", err)
		}
		if e2.ID() != e.ID() || e2.Version() != e.Version() || e2.HostAPI != e.HostAPI ||
			len(e2.Deps) != len(e.Deps) || len(e2.Assets) != len(e.Assets) || e2.Load != e.Load {
			t.Fatal("entry changed in the round trip")
		}
		_ = Files([]*Entry{e})
	})
}

// FuzzTopLevel parses ref.web annotation maps with and without root keys,
// and runs the loader over a schema carrying them: no panics, and what is
// accepted with roots is accepted without.
func FuzzTopLevel(f *testing.F) {
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	pubk := root.Public().(ed25519.PublicKey)
	cert, _ := websign.SignCertificate(root, pubk, "acme.", 2_000_000_000)
	rev, _ := websign.SignRevocation(root, 1, [][]byte{{1, 2}})
	m := cbor.AppendMapHead(nil, 3)
	m = cbor.AppendRaw(cbor.AppendText(m, AnnKeys), cbor.AppendRaw(cbor.AppendArrayHead(nil, 1), cert.Encode()))
	m = cbor.AppendRaw(cbor.AppendText(m, AnnApply), cbor.AppendText(nil, "hot"))
	m = cbor.AppendRaw(cbor.AppendText(m, AnnRevoked), rev.Encode())
	c, _ := cbor.Canonical(m, cbor.Options{})
	f.Add([]byte(c))
	for _, b := range fuzzseed.Hex("signing.json") {
		f.Add(b)
	}
	roots := [][]byte{pubk}
	f.Fuzz(func(t *testing.T, b []byte) {
		withRoots, err := ParseTopLevel(b, roots)
		without, err2 := ParseTopLevel(b, nil)
		if err == nil && err2 != nil {
			t.Fatalf("accepted with roots, refused without: %v", err2)
		}
		if err == nil && len(withRoots) != len(without) {
			t.Fatal("annotations differ")
		}
		if err2 != nil {
			return
		}
		sc := &schema.Schema{Format: schema.Format, Name: "t", Version: "1", Annotations: without}
		l := &Loader{Roots: roots, HostAPI: "3.1.0", Now: func() time.Time { return time.Unix(1_900_000_000, 0) }}
		_, _ = l.Accept(sc.Canonical())
	})
}

// FuzzRange parses hostApi ranges: a range made of one full version with
// any operator that includes equality contains that version, and Contains
// never panics.
func FuzzRange(f *testing.F) {
	for _, s := range []string{"^3.1", "^0.2.3", "~3.1", ">=3.0.0 <4", "3.x || 5", "*", "3.2.0-rc.1", "<=1", ">2.1", "=1.2.3"} {
		f.Add(s, "3.1.0")
	}
	f.Add("^18446744073709551615.0.0", "18446744073709551615.0.0")
	f.Add("~1.18446744073709551615", "1.18446744073709551615.0")
	f.Fuzz(func(t *testing.T, r, v string) {
		rg, err := ParseRange(r)
		if err != nil {
			return
		}
		_ = rg.Contains(v)
		ver, err := websign.ParseVersion(v)
		if err != nil {
			return
		}
		if len(ver.Pre) > 0 || ver.Build != "" {
			return
		}
		for _, op := range []string{"", "=", ">=", "<=", "^", "~"} {
			q, err := ParseRange(op + v)
			if err != nil {
				t.Fatalf("%q does not parse: %v", op+v, err)
			}
			if !q.Contains(v) {
				t.Fatalf("%q does not contain %q", op+v, v)
			}
		}
	})
}

// FuzzSnapshot decodes offline snapshots: an accepted one verifies and
// re-encodes to bytes that decode to the same snapshot.
func FuzzSnapshot(f *testing.F) {
	sc := schemaWith(nil, facetWith(16, "acme.app"))
	s, err := NewSnapshot(sc, cbor.AppendMapHead(nil, 0), nil, nil, time.Unix(1_800_000_000, 0))
	if err != nil {
		f.Fatal(err)
	}
	b, err := s.Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := DecodeSnapshot(b)
		if err != nil {
			return
		}
		e, err := s.Encode()
		if err != nil {
			return // floats in props
		}
		s2, err := DecodeSnapshot(e)
		if err != nil {
			t.Fatalf("re-encoded snapshot: %v", err)
		}
		e2, err := s2.Encode()
		if err != nil || !bytes.Equal(e, e2) {
			t.Fatalf("snapshot encoding not stable: %v", err)
		}
	})
}
