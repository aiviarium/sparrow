package admin

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/adminiface"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	"github.com/aiviarium/sparrow-rpc/go/internal/vectors"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/value"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

func canon(t *testing.T, b []byte) []byte {
	t.Helper()
	c, err := cbor.Canonical(b, cbor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestValueVectors decodes every admin value vector with this package's
// codec and re-encodes it to the same bytes, and checks the encoding
// against the interface with the schema-driven value codec.
func TestValueVectors(t *testing.T) {
	f, err := vectors.Load("admin.json")
	if err != nil {
		t.Fatal(err)
	}
	codec, err := value.New(adminiface.Facet(16))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range f.Vectors {
		if v.Type != "admin_value" && v.Name != "admin/commit-invalid" {
			continue
		}
		var hexs string
		_ = json.Unmarshal(v.Fields["cbor"], &hexs)
		raw, _ := hex.DecodeString(hexs)
		if v.Name == "admin/commit-invalid" {
			m, err := wire.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			e := m.(*wire.Error)
			ps, err := DecodeProblems(e.Details)
			if err != nil || !bytes.Equal(ProblemsDetails(ps), e.Details) {
				t.Fatalf("%s: %v", v.Name, err)
			}
			n++
			continue
		}
		var tid uint64
		_ = json.Unmarshal(v.Fields["type_id"], &tid)
		if _, err := codec.Decode(schema.Named(tid), raw); err != nil {
			t.Fatalf("%s: not a %d: %v", v.Name, tid, err)
		}
		var got []byte
		switch tid {
		case adminiface.TypeConfig:
			c, err := DecodeConfig(raw)
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			got = c.Encode()
		case adminiface.TypeCommitRequest:
			c, err := DecodeCommitRequest(raw)
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			got = c.Encode()
		case adminiface.TypeSnapshot:
			s, err := DecodeSnapshot(raw)
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			got = s.AppendTo(nil)
		case adminiface.TypeEvent:
			e, err := DecodeEvent(raw)
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			got = e.Encode()
		case adminiface.TypeProblems:
			ps, err := DecodeProblems(raw)
			if err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			got = EncodeProblems(ps)
		default:
			t.Fatalf("%s: type %d not covered", v.Name, tid)
		}
		if !bytes.Equal(canon(t, got), canon(t, raw)) {
			t.Fatalf("%s: re-encoded\n%x\nwant\n%x", v.Name, got, raw)
		}
		n++
	}
	if n < 11 {
		t.Fatalf("only %d admin vectors checked", n)
	}
}

func TestConfigRoundTrip(t *testing.T) {
	c := &Config{
		Nodes: map[string]*NodeConfig{
			"a": {Start: &Start{Spawn: &Spawn{Command: []string{"x", "y"}, Env: map[string]EnvValue{"K": {Value: "v"}, "S": {Secret: true, Value: "s"}}, Dir: ptr("/tmp")}},
				Facets: [][]byte{{1, 2}}, Enabled: ptr(false), Extensions: map[string][]byte{"ref.lazy": {0xf5}}},
			"b": {Credential: ptr("c"), Peer: ptr(true)},
			"c": {Start: &Start{Dial: &Dial{URL: "https://x", Pin: make([]byte, 32), Credential: "d"}}},
			"d": {Start: &Start{Other: &Other{Kind: "wasm", Params: []byte{0xa0}}}},
		},
		Defaults:   map[string]string{string(make([]byte, 33)): "a"},
		Extensions: map[string][]byte{},
	}
	b := c.Encode()
	if !cbor.IsCanonical(b, cbor.Options{}) {
		t.Fatalf("not canonical: %x", b)
	}
	d, err := DecodeConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.Encode(), b) {
		t.Fatal("round trip changed the document")
	}
	codec, _ := value.New(adminiface.Facet(16))
	if _, err := codec.Decode(schema.Named(adminiface.TypeConfig), b); err != nil {
		t.Fatal(err)
	}
	// Extra trailing struct elements and unknown variants are tolerated.
	extra := []byte{0x84, 0xa0, 0xf6, 0xf6, 0x01}
	if _, err := DecodeConfig(extra); err != nil {
		t.Fatalf("extra element: %v", err)
	}
	unk := cbor.AppendArrayHead(nil, 1)
	unk = cbor.AppendMapHead(unk, 1)
	unk = cbor.AppendText(unk, "n")
	unk = append(unk, 0x81, 0x82, 0x09, 0xf6) // NodeConfig [[9, null]]
	dc, err := DecodeConfig(unk)
	if err != nil || dc.Nodes["n"].Start.UnknownTag != 9 {
		t.Fatalf("unknown variant: %v", err)
	}
	if ps := Validate(dc, ValidateEnv{}); len(ps) == 0 || !strings.Contains(ps[0].Message, "unknown start variant") {
		t.Fatalf("%v", ps)
	}
	for _, bad := range [][]byte{{0x80}, {0x81, 0x01}, {0x81, 0xa1, 0x61, 'a', 0x81, 0x82, 0x00, 0x80}} {
		if _, err := DecodeConfig(bad); err == nil {
			t.Fatalf("%x decoded", bad)
		}
	}
}

func ptr[T any](v T) *T { return &v }

func facetDoc(t *testing.T, name string, id uint64) []byte {
	t.Helper()
	f := &schema.Facet{ID: id, Name: name, Version: "1.0.0", Types: []schema.TypeDef{}, Annotations: schema.Annotations{},
		Services: []schema.Service{{ID: 0, Name: "S", Annotations: schema.Annotations{}, Methods: []schema.Method{
			{ID: 1, Name: "b", Input: schema.Named(schema.TypeUnit), Output: schema.Named(schema.TypeUnit), Errors: []uint64{}, Annotations: schema.Annotations{}},
			{ID: 0, Name: "a", Input: schema.Named(schema.TypeUnit), Output: schema.Named(schema.TypeUnit), Errors: []uint64{}, Annotations: schema.Annotations{}},
		}}}, Sigils: []schema.Sigil{}, Retired: []schema.Retired{}}
	// Encode without canonicalizing: methods out of order.
	b, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidate(t *testing.T) {
	secrets := map[string]bool{"s1": true, "s2": true, "dial": true}
	charts := &schema.Facet{Name: "acme.charts"}
	other := &schema.Facet{Name: "other"}
	env := ValidateEnv{
		SecretExists: func(n string) bool { return secrets[n] },
		StoredFacet: func(k []byte) *schema.Facet {
			switch string(k) {
			case "charts":
				return charts
			case "other":
				return other
			}
			return nil
		},
		Extension: func(node, key string, v []byte) error {
			if key == "ok" {
				return nil
			}
			if key == "bad" {
				return errors.New("bad contents")
			}
			return ErrUnsupported
		},
	}
	pin := make([]byte, 32)
	cases := []struct {
		name string
		cfg  *Config
		want [][]string // problem paths
	}{
		{"empty", EmptyConfig(), nil},
		{"good", &Config{Nodes: map[string]*NodeConfig{
			"acme":        {Credential: ptr("s1")},
			"acme.charts": {Start: &Start{Spawn: &Spawn{Command: []string{"x"}, Env: map[string]EnvValue{"T": {Secret: true, Value: "s2"}}}}, Facets: [][]byte{[]byte("charts")}},
			"remote":      {Start: &Start{Dial: &Dial{URL: "wss://h/x", Pin: pin, Credential: "dial"}}},
		}, Extensions: map[string][]byte{"ok": {0}}}, nil},
		{"grammar and reserved", &Config{Nodes: map[string]*NodeConfig{
			"A":         {Credential: ptr("s1")},
			"sparrow":   {Credential: ptr("s1")},
			"sparrow.x": {Credential: ptr("s1")},
		}}, [][]string{{"nodes", "A"}, {"nodes", "sparrow"}, {"nodes", "sparrow.x"}}},
		{"directions", &Config{Nodes: map[string]*NodeConfig{
			"both":    {Credential: ptr("s1"), Start: &Start{Spawn: &Spawn{Command: []string{"x"}}}},
			"neither": {},
		}}, [][]string{{"nodes", "both"}, {"nodes", "neither"}}},
		{"missing secrets", &Config{Nodes: map[string]*NodeConfig{
			"a": {Credential: ptr("nope")},
			"b": {Start: &Start{Spawn: &Spawn{Command: []string{"x"}, Env: map[string]EnvValue{"K": {Secret: true, Value: "nope"}, "1bad": {Value: "x"}}}}},
			"c": {Start: &Start{Dial: &Dial{URL: "http://h", Pin: []byte{1}, Credential: "nope2"}}},
		}}, [][]string{{"nodes", "a", "credential"}, {"nodes", "b", "start", "spawn", "env", "1bad"}, {"nodes", "b", "start", "spawn", "env", "K"},
			{"nodes", "c", "start", "dial", "url"}, {"nodes", "c", "start", "dial", "pin"}, {"nodes", "c", "start", "dial", "credential"}}},
		{"replayable credential", &Config{Nodes: map[string]*NodeConfig{
			"a": {Credential: ptr("s1")},
			"b": {Start: &Start{Dial: &Dial{URL: "https://h", Pin: pin, Credential: "s1"}}},
		}}, [][]string{{"nodes", "a", "credential"}, {"nodes", "b", "start", "dial", "credential"}}},
		{"facets", &Config{Nodes: map[string]*NodeConfig{
			"acme":   {Credential: ptr("s1"), Facets: [][]byte{[]byte("charts"), []byte("charts"), []byte("other"), []byte("gone")}},
			"peer-1": {Credential: ptr("s2"), Peer: ptr(true), Facets: [][]byte{[]byte("charts")}},
		}}, [][]string{{"nodes", "acme", "facets", "1"}, {"nodes", "acme", "facets", "2"}, {"nodes", "acme", "facets", "3"},
			{"nodes", "peer-1", "facets"}, {"nodes", "peer-1", "facets", "0"}}},
		{"defaults and extensions", &Config{Nodes: map[string]*NodeConfig{
			"a": {Credential: ptr("s1"), Extensions: map[string][]byte{"nope": {0}}},
		}, Defaults: map[string]string{"short": "a", string(make([]byte, 33)): "Bad Name"}, Extensions: map[string][]byte{"bad": {0}, "x": {0}}},
			[][]string{{"nodes", "a", "extensions", "nope"}, {"defaults", hex.EncodeToString(make([]byte, 33))}, {"defaults", hex.EncodeToString([]byte("short"))},
				{"extensions", "bad"}, {"extensions", "x"}}},
		{"other kinds", &Config{Nodes: map[string]*NodeConfig{
			"a": {Start: &Start{Other: &Other{Kind: "wasm", Params: []byte{0xa0}}}},
		}}, [][]string{{"nodes", "a", "start", "other", "kind"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ps := Validate(c.cfg, env)
			var got [][]string
			for _, p := range ps {
				got = append(got, p.Path)
			}
			if len(got) != len(c.want) {
				t.Fatalf("problems %v, want paths %v", ps, c.want)
			}
			for i := range got {
				if strings.Join(got[i], "/") != strings.Join(c.want[i], "/") {
					t.Fatalf("problem %d: %v, want %v (all: %v)", i, got[i], c.want[i], ps)
				}
			}
		})
	}
}

// --- Manager -----------------------------------------------------------

type recApplier struct {
	mu   sync.Mutex
	revs []uint64
	docs []*Config
}

func (a *recApplier) Apply(c *Config, rev uint64) {
	a.mu.Lock()
	a.revs = append(a.revs, rev)
	a.docs = append(a.docs, c)
	a.mu.Unlock()
}

func (a *recApplier) last() (uint64, *Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.revs[len(a.revs)-1], a.docs[len(a.docs)-1]
}

func newManager(t *testing.T, dir string, clk session.Clock) (*Manager, *recApplier) {
	t.Helper()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(Options{Store: s, Clock: clk, WatchQueue: 8})
	if err != nil {
		t.Fatal(err)
	}
	a := &recApplier{}
	m.Start(a)
	return m, a
}

func code(err error) status.Code { return session.Code(err) }

func doc(ids ...string) *Config {
	c := EmptyConfig()
	for _, id := range ids {
		c.Nodes[id] = &NodeConfig{Credential: ptr("cred")}
	}
	return c
}

func nextEvent(t *testing.T, ch <-chan []byte) *Event {
	t.Helper()
	select {
	case b, ok := <-ch:
		if !ok {
			t.Fatal("watch ended")
		}
		e, err := DecodeEvent(b)
		if err != nil {
			t.Fatal(err)
		}
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	return nil
}

func TestManagerRevisions(t *testing.T) {
	dir := t.TempDir()
	clk := testutil.NewFakeClock()
	m, a := newManager(t, dir, clk)
	if s := m.Get(); s.Revision != 0 || len(s.Config.Nodes) != 0 || s.State != Confirmed {
		t.Fatalf("revision 0: %+v", s)
	}
	if rev, _ := a.last(); rev != 0 {
		t.Fatal("not applied at start")
	}
	events, _, cancel := m.Watch()
	defer cancel()
	if e := nextEvent(t, events); e.Snapshot == nil || e.Snapshot.Revision != 0 {
		t.Fatalf("first event %+v", e)
	}
	// Invalid: failed_precondition with problems.
	_, err := m.Commit(&CommitRequest{Base: 0, Config: doc("x")})
	if code(err) != status.FailedPrecondition {
		t.Fatalf("got %v", err)
	}
	var se *session.Error
	errors.As(err, &se)
	ps, _ := DecodeProblems(se.Details)
	if len(ps) != 1 || strings.Join(ps[0].Path, "/") != "nodes/x/credential" {
		t.Fatalf("problems %v", ps)
	}
	if err := m.SetSecret("cred", []byte("v")); err != nil {
		t.Fatal(err)
	}
	// Commit confirmed at once.
	rev, err := m.Commit(&CommitRequest{Base: 0, Config: doc("a")})
	if err != nil || rev != 1 {
		t.Fatalf("%d %v", rev, err)
	}
	if e := nextEvent(t, events); e.Revision == nil || e.Revision.Revision != 1 || e.Revision.State != Confirmed {
		t.Fatalf("event %+v", e)
	}
	// Stale base.
	_, err = m.Commit(&CommitRequest{Base: 0, Config: doc("b")})
	if code(err) != status.Aborted {
		t.Fatalf("stale base: %v", err)
	}
	if _, err := m.Validate(0, doc("b")); code(err) != status.Aborted {
		t.Fatalf("stale validate: %v", err)
	}
	// An identical document is a no-op whatever the base.
	if rev, err := m.Commit(&CommitRequest{Base: 77, Config: doc("a")}); err != nil || rev != 1 {
		t.Fatalf("identical: %d %v", rev, err)
	}
	// Pending.
	rev, err = m.Commit(&CommitRequest{Base: 1, Config: doc("a", "b"), ConfirmWithinMs: 1000})
	if err != nil || rev != 2 {
		t.Fatalf("%d %v", rev, err)
	}
	if e := nextEvent(t, events); e.Revision.Revision != 2 || e.Revision.State != Pending || *e.Revision.ConfirmInMs != 1000 {
		t.Fatalf("event %+v", e.Revision)
	}
	clk.Advance(300 * time.Millisecond)
	if s := m.Get(); s.State != Pending || *s.ConfirmInMs != 700 {
		t.Fatalf("snapshot %+v", s)
	}
	// While pending every commit is aborted, even an identical one.
	for _, c := range []*Config{doc("a", "b"), doc("a")} {
		if _, err := m.Commit(&CommitRequest{Base: 2, Config: c}); code(err) != status.Aborted {
			t.Fatalf("while pending: %v", err)
		}
	}
	// Deleting a secret the rollback target refers to fails.
	if err := m.DeleteSecret("cred"); code(err) != status.FailedPrecondition {
		t.Fatalf("%v", err)
	}
	if err := m.Confirm(1); code(err) != status.NotFound {
		t.Fatalf("confirm old: %v", err)
	}
	if err := m.Confirm(2); err != nil {
		t.Fatal(err)
	}
	if err := m.Confirm(2); err != nil {
		t.Fatalf("confirm is idempotent: %v", err)
	}
	if e := nextEvent(t, events); e.Revision.Revision != 2 || e.Revision.State != Confirmed {
		t.Fatalf("event %+v", e.Revision)
	}
	clk.Advance(2 * time.Second) // the old deadline does nothing now
	if s := m.Get(); s.Revision != 2 || s.State != Confirmed {
		t.Fatalf("%+v", s)
	}
	// Timeout rollback: revision 4 is the rollback target, confirmed.
	rev, _ = m.Commit(&CommitRequest{Base: 2, Config: doc("c"), ConfirmWithinMs: 500})
	if rev != 3 {
		t.Fatal(rev)
	}
	nextEvent(t, events)
	clk.Advance(501 * time.Millisecond)
	e1, e2 := nextEvent(t, events), nextEvent(t, events)
	if e1.Revision.Revision != 3 || e1.Revision.State != RolledBack || e2.Revision.Revision != 4 || e2.Revision.State != Confirmed {
		t.Fatalf("events %+v %+v", e1.Revision, e2.Revision)
	}
	if s := m.Get(); s.Revision != 4 || !s.Config.Equal(doc("a", "b")) {
		t.Fatalf("after rollback %+v", s)
	}
	if rev, d := a.last(); rev != 4 || !d.Equal(doc("a", "b")) {
		t.Fatalf("applied %d", rev)
	}
	if err := m.Confirm(3); code(err) != status.NotFound {
		t.Fatalf("confirm after the deadline: %v", err)
	}
	// Explicit rollback.
	rev, _ = m.Commit(&CommitRequest{Base: 4, Config: doc("d"), ConfirmWithinMs: 60000})
	if _, err := m.Rollback(4); code(err) != status.NotFound {
		t.Fatal("rollback of a confirmed revision")
	}
	nrev, err := m.Rollback(rev)
	if err != nil || nrev != rev+1 {
		t.Fatalf("%d %v", nrev, err)
	}
	if s := m.Get(); s.Revision != 6 || !s.Config.Equal(doc("a", "b")) {
		t.Fatalf("%+v", s)
	}
	// A confirmation processed after the deadline fails, even if the timer
	// has not run.
	rev, _ = m.Commit(&CommitRequest{Base: 6, Config: doc("e"), ConfirmWithinMs: 100})
	m.mu.Lock()
	m.timer.Stop() // the timer is late
	m.mu.Unlock()
	clk.Advance(200 * time.Millisecond)
	if err := m.Confirm(rev); code(err) != status.NotFound {
		t.Fatalf("late confirm: %v", err)
	}
	if s := m.Get(); s.Revision != rev+1 || s.State != Confirmed {
		t.Fatalf("%+v", s)
	}
}

func TestManagerRestartDuringPending(t *testing.T) {
	dir := t.TempDir()
	clk := testutil.NewFakeClock()
	m, _ := newManager(t, dir, clk)
	_ = m.SetSecret("cred", []byte("v"))
	if _, err := m.Commit(&CommitRequest{Base: 0, Config: doc("a")}); err != nil {
		t.Fatal(err)
	}
	rev, err := m.Commit(&CommitRequest{Base: 1, Config: doc("a", "b"), ConfirmWithinMs: 60000})
	if err != nil || rev != 2 {
		t.Fatal(err)
	}
	// "Crash": a new manager on the same directory.
	m2, a2 := newManager(t, dir, clk)
	s := m2.Get()
	if s.Revision != 3 || s.State != Confirmed || !s.Config.Equal(doc("a")) {
		t.Fatalf("after restart %+v", s)
	}
	if r, d := a2.last(); r != 3 || !d.Equal(doc("a")) {
		t.Fatalf("applied %d", r)
	}
	if m2.HighWater() != 3 {
		t.Fatal(m2.HighWater())
	}
	// And again: nothing pending any more.
	m3, _ := newManager(t, dir, clk)
	if s := m3.Get(); s.Revision != 3 {
		t.Fatalf("%+v", s)
	}
}

func TestManagerHighWaterSurvivesCrash(t *testing.T) {
	dir := t.TempDir()
	m, _ := newManager(t, dir, nil)
	_ = m.SetSecret("cred", []byte("v"))
	m.store.CrashAfterWrite = func(name string) error {
		if name == fileState {
			return errors.New("crash")
		}
		return nil
	}
	if _, err := m.Commit(&CommitRequest{Base: 0, Config: doc("a")}); code(err) != status.Internal {
		t.Fatalf("got %v", err)
	}
	// After the crash: revision 0 applied, but revision 1 was handed out
	// and is never handed out again.
	m2, _ := newManager(t, dir, nil)
	if s := m2.Get(); s.Revision != 0 {
		t.Fatalf("%+v", s)
	}
	rev, err := m2.Commit(&CommitRequest{Base: 0, Config: doc("a")})
	if err != nil || rev != 2 {
		t.Fatalf("%d %v", rev, err)
	}
	m3, _ := newManager(t, dir, nil)
	if s := m3.Get(); s.Revision != 2 || !s.Config.Equal(doc("a")) {
		t.Fatalf("%+v", s)
	}
}

func TestStoreCrashSafety(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir)
	if err := s.Write("x", []byte("old")); err != nil {
		t.Fatal(err)
	}
	s.CrashAfterWrite = func(string) error { return errors.New("crash") }
	if err := s.Write("x", []byte("new")); err == nil {
		t.Fatal("no crash")
	}
	tmps, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(tmps) != 1 {
		t.Fatalf("temporary files %v", tmps)
	}
	if b, _ := s.Read("x"); string(b) != "old" {
		t.Fatalf("content %q after a crash before the rename", b)
	}
	s2, _ := OpenStore(dir)
	tmps, _ = filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(tmps) != 0 {
		t.Fatal("temporary file not cleaned up")
	}
	if b, _ := s2.Read("x"); string(b) != "old" {
		t.Fatal(string(b))
	}
	if err := s2.Write("sub/y", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "sub", "y")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", fi, err)
	}
	if _, err := s2.Read("../etc/passwd"); err == nil {
		t.Fatal("path escape")
	}
}

func TestSecretsAndFacets(t *testing.T) {
	dir := t.TempDir()
	m, _ := newManager(t, dir, nil)
	if err := m.SetSecret("Bad Name", nil); code(err) != status.InvalidArgument {
		t.Fatal(err)
	}
	if err := m.SetSecret("s", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if err := m.SetSecret("s", []byte("2")); code(err) != status.AlreadyExists {
		t.Fatalf("secrets are immutable: %v", err)
	}
	if v, _ := m.SecretValue("s"); string(v) != "1" {
		t.Fatal(string(v))
	}
	// Two encodings of one facet (one unsorted, with a facet ID) get the
	// same key; the stored form is canonical with ID 0.
	k1, err := m.PutFacet(facetDoc(t, "acme", 17))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := m.PutFacet(facetDoc(t, "acme", 0))
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("%x %x %v", k1, k2, err)
	}
	f := m.StoredFacet(k1)
	if f == nil || f.ID != 0 || f.Services[0].Methods[0].ID != 0 {
		t.Fatalf("%+v", f)
	}
	want, _ := f.StoredKey()
	if !bytes.Equal(want, k1) {
		t.Fatal("key")
	}
	if _, err := m.PutFacet([]byte{0x01}); code(err) != status.InvalidArgument {
		t.Fatalf("%v", err)
	} else if ps := ProblemsOf(err); len(ps) != 1 {
		t.Fatalf("details %v", ps)
	}
	if got := m.ListFacets(); len(got) != 1 {
		t.Fatal(got)
	}
	cfg := &Config{Nodes: map[string]*NodeConfig{"acme": {Credential: ptr("s"), Facets: [][]byte{k1}}}}
	if _, err := m.Commit(&CommitRequest{Base: 0, Config: cfg}); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteFacet(k1); code(err) != status.FailedPrecondition {
		t.Fatalf("%v", err)
	}
	if err := m.DeleteSecret("s"); code(err) != status.FailedPrecondition {
		t.Fatalf("%v", err)
	}
	if err := m.DeleteSecret("missing"); err != nil {
		t.Fatal(err)
	}
	// Persisted.
	m2, _ := newManager(t, dir, nil)
	if got := m2.ListSecrets(); len(got) != 1 || got[0] != "s" {
		t.Fatal(got)
	}
	if m2.StoredFacet(k1) == nil {
		t.Fatal("facet lost")
	}
	if _, err := m2.Commit(&CommitRequest{Base: 1, Config: EmptyConfig()}); err != nil {
		t.Fatal(err)
	}
	if err := m2.DeleteFacet(k1); err != nil {
		t.Fatal(err)
	}
	if err := m2.DeleteSecret("s"); err != nil {
		t.Fatal(err)
	}
	if len(m2.ListSecrets()) != 0 || len(m2.ListFacets()) != 0 {
		t.Fatal("not deleted")
	}
}

func TestWatchLagging(t *testing.T) {
	m, _ := newManager(t, t.TempDir(), nil)
	events, lagged, cancel := m.Watch()
	defer cancel()
	for i := 0; i < 20; i++ {
		m.NodeEvent(NodeEvent{Node: "n", Revision: uint64(i), State: Starting})
	}
	n := 0
	for range events {
		n++
	}
	if !lagged() || n > 10 {
		t.Fatalf("lagged %v after %d events", lagged(), n)
	}
	if m.Watchers() != 0 {
		t.Fatal("lagging watcher kept")
	}
	// A new watcher starts with a snapshot and the node states.
	ev2, _, c2 := m.Watch()
	defer c2()
	if e := nextEvent(t, ev2); e.Snapshot == nil {
		t.Fatal("no snapshot")
	}
	if e := nextEvent(t, ev2); e.Node == nil || e.Node.Revision != 19 {
		t.Fatalf("%+v", e)
	}
}
