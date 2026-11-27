package admin

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/internal/fuzzseed"
)

// fuzzEnv knows the secrets named "s0".."s9" (values by name, "s0" and
// "s1" share one) and accepts any extension named "ok".
func fuzzEnv() ValidateEnv {
	return ValidateEnv{
		SecretExists: func(name string) bool { return len(name) == 2 && name[0] == 's' && name[1] >= '0' && name[1] <= '9' },
		SecretValue: func(name string) ([]byte, bool) {
			if name == "s1" {
				name = "s0"
			}
			return []byte(name), len(name) == 2 && name[0] == 's'
		},
		Extension: func(node, key string, value []byte) error {
			if key == "ok" {
				return nil
			}
			return ErrUnsupported
		},
	}
}

// FuzzDecode feeds arbitrary bytes to every decoder of the facet's input
// types; a document that decodes must re-encode to bytes that decode to
// the same document, validation must not panic and must be deterministic,
// and a CommitRequest round-trips too.
func FuzzDecode(f *testing.F) {
	f.Add(EmptyConfig().Encode())
	f.Add((&CommitRequest{Base: 1, Config: &Config{Nodes: map[string]*NodeConfig{"a": {Link: DialIn("c")}, "b": {Link: Dialed(Dial{URL: "https://b", Pin: []byte{1}, Credential: "d"})}}}, ConfirmWithinMs: 5}).Encode())
	f.Add(EncodeSecret("x", []byte{1}))
	f.Add(EncodeProblems([]Problem{{Path: []string{"a", "0"}, Message: "m"}}))
	f.Add(EncodeValidateRequest(3, &Config{Nodes: map[string]*NodeConfig{"s": {Link: DialIn("s0")}, "t": {Link: DialIn("s1")}}}))
	for _, b := range fuzzseed.Hex("admin.json") {
		f.Add(b)
	}
	env := fuzzEnv()
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := DecodeConfig(b); err == nil {
			e := c.Encode()
			c2, err := DecodeConfig(e)
			if err != nil || !bytes.Equal(c2.Encode(), e) {
				t.Fatalf("round trip: %v", err)
			}
			p1 := Validate(c, env)
			p2 := Validate(c2, env)
			if !bytes.Equal(EncodeProblems(p1), EncodeProblems(p2)) {
				t.Fatal("validation not deterministic")
			}
			_ = Validate(c, ValidateEnv{})
			if j, err := json.Marshal(c); err == nil {
				var c3 Config
				if err := json.Unmarshal(j, &c3); err != nil {
					t.Fatalf("JSON form does not read back: %v\n%s", err, j)
				}
				if !bytes.Equal(c3.Encode(), e) {
					t.Fatalf("JSON round trip changed the document:\n%s", j)
				}
			}
		}
		if r, err := DecodeCommitRequest(b); err == nil {
			e := r.Encode()
			r2, err := DecodeCommitRequest(e)
			if err != nil || !bytes.Equal(r2.Encode(), e) {
				t.Fatalf("commit request round trip: %v", err)
			}
			_ = Validate(r.Config, env)
		}
		_, _, _ = DecodeSecret(b)
		if ps, err := DecodeProblems(b); err == nil {
			if ps2, err := DecodeProblems(EncodeProblems(ps)); err != nil || len(ps2) != len(ps) {
				t.Fatalf("problems round trip: %v", err)
			}
		}
		_, _ = DecodeEvent(b)
		_, _ = DecodeSnapshot(b)
		_, _ = DecodeStrings(b)
	})
}

// FuzzConfigJSON reads the JSON form of a document (sparrow-admin's
// input): whatever is accepted encodes to a CBOR document that decodes,
// and writes back to JSON that reads to the same document.
func FuzzConfigJSON(f *testing.F) {
	f.Add([]byte(`{"nodes": {"remote": {"link": {"dial": {"url": "https://r:1/x", "pin": "00ff", "credential": "s0"}}},
		"acme": {"link": {"credential": "s1"}, "peer": false, "enabled": true, "extensions": {"ok": "f6"}}},
		"defaults": {"0102": "acme.notes"}, "extensions": {"ref.policy": "80"}}`))
	f.Add([]byte(`{"nodes": {}}`))
	f.Add([]byte(`{"nodes": {"a": {"link": {}}}}`))
	f.Add([]byte(`{"nodes": {"a": null}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var c Config
		if err := json.Unmarshal(b, &c); err != nil {
			return
		}
		e := c.Encode()
		c2, err := DecodeConfig(e)
		if err != nil {
			t.Fatalf("JSON document does not decode as CBOR: %v", err)
		}
		_ = Validate(c2, fuzzEnv())
		j, err := json.Marshal(&c)
		if err != nil {
			t.Fatalf("accepted JSON does not write back: %v", err)
		}
		var c3 Config
		if err := json.Unmarshal(j, &c3); err != nil || !bytes.Equal(c3.Encode(), e) {
			t.Fatalf("JSON round trip: %v\n%s", err, j)
		}
	})
}
