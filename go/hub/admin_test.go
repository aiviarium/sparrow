package hub

import (
	"context"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiviarium/sparrow-rpc/go/admin"
	"github.com/aiviarium/sparrow-rpc/go/adminiface"
	"github.com/aiviarium/sparrow-rpc/go/cbor"
	"github.com/aiviarium/sparrow-rpc/go/internal/testutil"
	nd "github.com/aiviarium/sparrow-rpc/go/node"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/session"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

func nextEv(t *testing.T, w *admin.Watcher) *admin.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	e, err := w.Next(ctx)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	return e
}

// waitNodeEvent reads events until one for node with state and revision.
func waitNodeEvent(t *testing.T, w *admin.Watcher, node string, st admin.NodeState, rev uint64) {
	t.Helper()
	for {
		e := nextEv(t, w)
		if e.Node != nil && e.Node.Node == node && e.Node.State == st && e.Node.Revision == rev {
			return
		}
	}
}

func TestAdminOverTheWire(t *testing.T) {
	f := newFixture(t, nil)
	c, _ := f.adminClient("webtransport")
	ctx := tctx(t)
	w, err := c.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if e := nextEv(t, w); e.Snapshot == nil || e.Snapshot.Revision != 0 {
		t.Fatalf("first event %+v", e)
	}
	// Commit with confirmation; confirm over a new session (2.3).
	cfg := &admin.Config{Nodes: map[string]*admin.NodeConfig{"echo": f.echo("echo")}, Extensions: policy(grant("user:alice", "echo", "use"))}
	rev, err := c.Commit(ctx, 0, cfg, 30000)
	if err != nil || rev != 1 {
		t.Fatalf("%d %v", rev, err)
	}
	f.startEchoes()
	if e := nextEv(t, w); e.Revision == nil || e.Revision.State != admin.Pending || e.Revision.ConfirmInMs == nil {
		t.Fatalf("%+v", e)
	}
	waitNodeEvent(t, w, "echo", admin.Connected, 1)
	// While pending: identical or not, every commit is aborted.
	if _, err := c.Commit(ctx, 1, cfg, 0); session.Code(err) != status.Aborted {
		t.Fatalf("%v", err)
	}
	c2, _ := f.adminClient("websocket")
	if err := c2.Confirm(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if e := nextEv(t, w); e.Revision == nil || e.Revision.Revision != 1 || e.Revision.State != admin.Confirmed {
		t.Fatalf("%+v", e)
	}
	// An unconfirmed commit is rolled back at its deadline: the node it
	// added is removed again.
	cfg2 := cfg.Clone()
	cfg2.Nodes["echo2"] = f.echo("echo2")
	rev, err = c.Commit(ctx, 1, cfg2, 1500)
	if err != nil || rev != 2 {
		t.Fatal(err)
	}
	f.startEchoes()
	waitNodeEvent(t, w, "echo2", admin.Connected, 2)
	var sawRolled bool
	for {
		e := nextEv(t, w)
		if e.Revision != nil && e.Revision.Revision == 2 && e.Revision.State == admin.RolledBack {
			sawRolled = true
		}
		if e.Revision != nil && e.Revision.Revision == 3 && e.Revision.State == admin.Confirmed {
			break
		}
	}
	if !sawRolled {
		t.Fatal("no rolledBack event before the confirmation of revision 3")
	}
	waitNodeEvent(t, w, "echo2", admin.Removed, 3)
	if err := c.Confirm(ctx, 2); session.Code(err) != status.NotFound {
		t.Fatalf("%v", err)
	}
	snap, _ := c.Get(ctx)
	if snap.Revision != 3 || !snap.Config.Equal(cfg) {
		t.Fatalf("%+v", snap)
	}
	if _, ok := f.h.Stats().Nodes["echo2"]; ok {
		t.Fatal("echo2 still configured")
	}
	// Explicit rollback.
	rev, _ = c.Commit(ctx, 3, cfg2, 60000)
	nrev, err := c.Rollback(ctx, rev)
	if err != nil || nrev != rev+1 {
		t.Fatalf("%d %v", nrev, err)
	}
	// Invalid documents carry their problems.
	bad := cfg.Clone()
	bad.Nodes["x"] = &admin.NodeConfig{Link: admin.Link{UnknownTag: 7, Unknown: cbor.Null}}
	_, err = c.Commit(ctx, nrev, bad, 0)
	if ps := admin.ProblemsOf(err); session.Code(err) != status.FailedPrecondition || len(ps) != 1 || ps[0].Path[1] != "x" {
		t.Fatalf("%v %v", err, ps)
	}
	ps, err := c.Validate(ctx, nrev, bad)
	if err != nil || len(ps) != 1 {
		t.Fatalf("%v %v", ps, err)
	}
	if _, err := c.Validate(ctx, 0, bad); session.Code(err) != status.Aborted {
		t.Fatalf("%v", err)
	}
	// Secrets.
	if err := c.SetSecret(ctx, "s1", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if err := c.SetSecret(ctx, "s1", []byte("w")); session.Code(err) != status.AlreadyExists {
		t.Fatalf("%v", err)
	}
	names, _ := c.ListSecrets(ctx)
	if len(names) != 3 || names[2] != "s1" { // and the echo nodes' credentials
		t.Fatal(names)
	}
	cfg3 := cfg.Clone()
	cfg3.Nodes["acme"] = &admin.NodeConfig{Link: admin.DialIn("s1")}
	if _, err := c.Commit(ctx, nrev, cfg3, 0); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteSecret(ctx, "s1"); session.Code(err) != status.FailedPrecondition {
		t.Fatalf("%v", err)
	}
	w.Close()
}

// TestBootstrapAdminAlwaysAllowed: a delegated administrator can commit a
// document that revokes every grant, including its own, and the bootstrap
// administrator still reaches the facet.
func TestBootstrapAdminAlwaysAllowed(t *testing.T) {
	f := newFixture(t, nil)
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{}, Extensions: policy(grant("user:alice", adminiface.Name, "manage"))})
	alice := f.client("websocket", aliceToken)
	waitFacet(t, alice, adminiface.Name)
	ac, err := admin.NewClient(alice.Session(), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := tctx(t)
	snap, err := ac.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ac.Commit(ctx, snap.Revision, &admin.Config{Nodes: map[string]*admin.NodeConfig{}}, 0); err != nil {
		t.Fatal(err)
	}
	waitNoFacet(t, alice, adminiface.Name)
	_, err = ac.Get(ctx)
	if c := session.Code(err); c != status.PermissionDenied && c != status.Unimplemented {
		t.Fatalf("alice still administers: %v", err)
	}
	boot, _ := f.adminClient("webtransport")
	if s, err := boot.Get(ctx); err != nil || s.Revision != snap.Revision+1 {
		t.Fatalf("%+v %v", s, err)
	}
	// "view" alone does not allow the manage methods.
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{}, Extensions: policy(grant("user:bob", adminiface.Name, "use"))})
	bob := f.client("webtransport", bobToken)
	waitFacet(t, bob, adminiface.Name)
	bc, _ := admin.NewClient(bob.Session(), "")
	_, err = bc.Get(ctx)
	mustCode(t, err, status.PermissionDenied)
}

// TestRestartPersistence restarts the hub on its data directory: config,
// revision, facet IDs and last known facets survive, a client reconnects
// with its cached schema and gets Unchanged, and a commit pending at the
// restart is rolled back.
func TestRestartPersistence(t *testing.T) {
	dir := t.TempDir()
	f := startFixture(t, dir, nil)
	f.secret("acme-1", "cred-one")
	cfg := &admin.Config{Nodes: map[string]*admin.NodeConfig{
		"echo": f.echo("echo"),
		"acme": dialInConfig("acme-1"),
	}, Extensions: policy(grant("user:alice", "*", "use"))}
	rev := f.commit(cfg)
	if _, err := dialInNode(t, f, "websocket", "acme", "cred-one", acmeFacet("acme", "1.0.0", true, false)); err != nil {
		t.Fatal(err)
	}
	waitNode(t, f.h, "acme", true)
	waitNode(t, f.h, "echo", true)
	cli := f.client("webtransport", aliceToken)
	waitFacet(t, cli, "acme")
	waitFacet(t, cli, "echo")
	cached := cli.Session().PeerSchema().Schema()
	ids := map[string]uint64{}
	for _, fc := range cached.Facets {
		ids[fc.Name] = fc.ID
	}
	// A pending commit when the hub stops.
	c, _ := f.adminClient("websocket")
	pending := cfg.Clone()
	pending.Nodes["echo2"] = f.echo("echo2")
	prev, err := c.Commit(tctx(t), rev, pending, 60000)
	if err != nil {
		t.Fatal(err)
	}
	f.startEchoes()
	waitNode(t, f.h, "echo2", true)
	f.stop()

	// The new hub listens where the old one did, so the echo processes,
	// which keep redialing, find it again.
	g := startFixtureOn(t, dir, f.wsAddr, nil)
	g.echoes = f.echoes
	g.stopEcho("echo2", false) // rolled back: no longer configured
	s := g.h.Admin().Get()
	if s.Revision != prev+1 || !s.Config.Equal(cfg) || s.State != admin.Confirmed {
		t.Fatalf("after restart: rev %d (pending was %d) state %v", s.Revision, prev, s.State)
	}
	waitNode(t, g.h, "echo", true)
	if g.h.Stats().Nodes["acme"].Connected {
		t.Fatal("acme connected?")
	}
	// The client reconnects with its cached schema: acme is offline but
	// its last known facets are listed, with the same IDs, so the schema
	// is unchanged.
	n := nd.New(nd.Options{Auth: bearer(aliceToken), Session: func(sc *session.Config) { sc.KnownSchema = cached }})
	if err := n.Dial(tctx(t), g.wtURL, nd.DialOptions{CertHashes: [][]byte{g.certHash}}); err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if k := n.Session().Welcome().ServerSchema.Kind; k != wire.OfferUnchanged {
		t.Fatalf("offer kind %v, want Unchanged", k)
	}
	for _, fc := range n.Session().PeerSchema().Schema().Facets {
		if ids[fc.Name] != fc.ID {
			t.Fatalf("facet %s moved %d -> %d", fc.Name, ids[fc.Name], fc.ID)
		}
	}
	// Calls to acme wait for it; it reconnects and serves them.
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, _ = dialInNode(t, g, "websocket", "acme", "cred-one", acmeFacet("acme", "1.0.0", true, false))
	}()
	if v, err := n.Call(tctx(t), "acme", "hello", "again"); err != nil || v != "hello again" {
		t.Fatalf("%v %v", v, err)
	}
	if v, err := n.Call(tctx(t), "echo", "echo", "e"); err != nil || v != "e" {
		t.Fatalf("%v %v", v, err)
	}
	// A removed node's IDs are retired: added again, it gets new ones.
	g.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{"echo": g.echo("echo")}, Extensions: policy(grant("user:alice", "*", "use"))})
	g.commit(cfg)
	if _, err := dialInNode(t, g, "websocket", "acme", "cred-one", acmeFacet("acme", "1.0.0", true, false)); err != nil {
		t.Fatal(err)
	}
	testutil.Eventually(t, 10*time.Second, func() bool {
		fc := n.Session().PeerFacet("acme")
		return fc != nil && fc.ID != ids["acme"]
	}, "acme kept its retired ID")
	_ = io.EOF
	_ = schema.Format
}

// flipPolicy allows everything except, while deny is set, alice on
// sparrow.hub.admin.
type flipPolicy struct{ deny atomic.Bool }

func (p *flipPolicy) Visible(a Actor, f FacetRef) bool { return true }
func (p *flipPolicy) Allowed(a Actor, f FacetRef, m *schema.Method) bool {
	return !(p.deny.Load() && a.Principal == "user:alice" && f.Name == adminiface.Name)
}

// TestRecheckSparesUnaryOwnCalls: a decision change ends running calls that
// are no longer allowed (10.4), but not a unary call to the hub's own facet
// that was authorized when it arrived: it may be the call whose effect
// changed the decision (a commit revoking its own grant, already applied),
// and ending it would report that change as permission_denied.
func TestRecheckSparesUnaryOwnCalls(t *testing.T) {
	pol := &flipPolicy{}
	f := newFixture(t, func(o *Options) { o.Policy = pol })
	alice := f.client("websocket", aliceToken)
	waitFacet(t, alice, adminiface.Name)
	ac, err := admin.NewClient(alice.Session(), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := tctx(t)
	stop := make(chan struct{})
	flipped := make(chan struct{})
	go func() {
		defer close(flipped)
		for {
			select {
			case <-stop:
				return
			default:
			}
			time.Sleep(50 * time.Microsecond)
			pol.deny.Store(true)
			f.h.recheckCalls()
			pol.deny.Store(false)
		}
	}()
	var wg sync.WaitGroup
	errs := make(chan error, 1)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_, err := ac.Get(ctx)
				if err != nil && strings.Contains(err.Error(), "permission withdrawn") {
					select {
					case errs <- err:
					default:
					}
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-flipped
	select {
	case err := <-errs:
		t.Fatalf("a unary admin call was ended by a recheck: %v", err)
	default:
	}
}
