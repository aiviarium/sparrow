package admin

import (
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/status"
)

// TestNoOpCommitIsCanonicalByteEquality: a commit is a no-op only when its
// document is byte-for-byte equal to the applied one in canonical encoding
// (hub-admin 2): a document that means the same but encodes differently
// (an explicit default) is an ordinary commit, so a stale base aborts it.
func TestNoOpCommitIsCanonicalByteEquality(t *testing.T) {
	m, _ := newManager(t, t.TempDir(), testutil.NewFakeClock())
	_ = m.SetSecret("cred", []byte("v"))
	if _, err := m.Commit(&CommitRequest{Base: 0, Config: doc("a", "b")}); err != nil {
		t.Fatal(err)
	}
	// The same document built in another order: identical bytes.
	same := doc("b", "a")
	if rev, err := m.Commit(&CommitRequest{Base: 99, Config: same}); err != nil || rev != 1 {
		t.Fatalf("identical: %d %v", rev, err)
	}
	explicit := doc("a", "b")
	explicit.Nodes["a"].Enabled = ptr(true)
	if _, err := m.Commit(&CommitRequest{Base: 99, Config: explicit}); code(err) != status.Aborted {
		t.Fatalf("an explicit default was taken as a no-op: %v", err)
	}
	if rev, err := m.Commit(&CommitRequest{Base: 1, Config: explicit}); err != nil || rev != 2 {
		t.Fatalf("%d %v", rev, err)
	}
}

// TestJSONFormUnions: the JSON form writes a union as an object keyed by
// its variant name (Start, EnvValue), the form Problem.path follows; the
// reader also takes the older shorthand.
func TestJSONFormUnions(t *testing.T) {
	c := &Config{Nodes: map[string]*NodeConfig{
		"echo": {Start: &Start{Spawn: &Spawn{Command: []string{"echo-node"}, Env: map[string]EnvValue{"A": {Value: "x"}, "B": {Secret: true, Value: "s"}}}}},
	}}
	b, err := c.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"nodes":{"echo":{"start":{"spawn":{"command":["echo-node"],"env":{"A":{"literal":"x"},"B":{"secret":"s"}}}}}}}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
	var back, short Config
	if err := back.UnmarshalJSON(b); err != nil || !back.Equal(c) {
		t.Fatalf("round trip: %v", err)
	}
	if err := short.UnmarshalJSON([]byte(`{"nodes":{"echo":{"spawn":{"command":["echo-node"],"env":{"A":"x","B":{"secret":"s"}}}}}}`)); err != nil || !short.Equal(c) {
		t.Fatalf("shorthand: %v", err)
	}
	var bad Config
	if err := bad.UnmarshalJSON([]byte(`{"nodes":{"echo":{"start":{"spawn":{"command":["x"]}},"dial":{"url":"https://h","pin":"","credential":"c"}}}}`)); err == nil {
		t.Fatal("two starts accepted")
	}
}
