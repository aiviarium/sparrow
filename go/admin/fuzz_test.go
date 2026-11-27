package admin

import (
	"bytes"
	"testing"
)

// FuzzDecode feeds arbitrary bytes to every decoder of the facet's input
// types; a document that decodes must re-encode to bytes that decode to
// the same document.
func FuzzDecode(f *testing.F) {
	f.Add(EmptyConfig().Encode())
	f.Add((&CommitRequest{Base: 1, Config: &Config{Nodes: map[string]*NodeConfig{"a": {Credential: ptr("c"), Facets: [][]byte{{1}}}}}, ConfirmWithinMs: 5}).Encode())
	f.Add(EncodeSecret("x", []byte{1}))
	f.Add(EncodeProblems([]Problem{{Path: []string{"a", "0"}, Message: "m"}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := DecodeConfig(b); err == nil {
			e := c.Encode()
			c2, err := DecodeConfig(e)
			if err != nil || !bytes.Equal(c2.Encode(), e) {
				t.Fatalf("round trip: %v", err)
			}
			_ = Validate(c, ValidateEnv{})
		}
		_, _ = DecodeCommitRequest(b)
		_, _, _ = DecodeSecret(b)
		_, _ = DecodeProblems(b)
		_, _ = DecodeEvent(b)
		_, _ = DecodeSnapshot(b)
	})
}
