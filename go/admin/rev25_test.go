package admin

import (
	"strings"
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

// TestJSONForm: the JSON form names struct fields as in the interface and
// writes byte strings as hex; a node with the old "start" key is refused.
func TestJSONForm(t *testing.T) {
	pin := make([]byte, 32)
	pin[0] = 0xab
	c := &Config{Nodes: map[string]*NodeConfig{
		"echo":    {Dial: &Dial{URL: "https://h:1/sparrow/wt", Pin: pin, Credential: "s"}},
		"inbound": {Credential: ptr("t"), Enabled: ptr(false)},
	}}
	b, err := c.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"nodes":{"echo":{"dial":{"url":"https://h:1/sparrow/wt","pin":"ab` + strings.Repeat("00", 31) + `","credential":"s"}},"inbound":{"credential":"t","enabled":false}}}`
	if string(b) != want {
		t.Fatalf("got %s", b)
	}
	var back Config
	if err := back.UnmarshalJSON(b); err != nil || !back.Equal(c) {
		t.Fatalf("round trip: %v", err)
	}
	var bad Config
	if err := bad.UnmarshalJSON([]byte(`{"nodes":{"echo":{"start":{"dial":{"url":"https://h","pin":"","credential":"c"}}}}}`)); err == nil {
		t.Fatal("a start key was accepted")
	}
}
