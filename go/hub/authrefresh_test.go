package hub

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aiviarium/sparrow/go/admin"
	"github.com/aiviarium/sparrow/go/cbor"
	"github.com/aiviarium/sparrow/go/internal/testutil"
	nd "github.com/aiviarium/sparrow/go/node"
	"github.com/aiviarium/sparrow/go/session"
	"github.com/aiviarium/sparrow/go/status"
	"github.com/aiviarium/sparrow/go/wire"
)

// testTicket is the credential of the test authenticator:
// "tick:<principal>:<sid>:<expires unix>".
func testTicket(principal, sid string, exp time.Time) *wire.Auth {
	return bearer("tick:" + principal + ":" + sid + ":" + strconv.FormatInt(exp.Unix(), 10))
}

func ticketAuth(ctx context.Context, h *wire.Hello) (Actor, error) {
	tok, _ := credentialBytes(h.Auth.Credentials)
	parts := strings.Split(string(tok), ":")
	if len(parts) != 5 || parts[0] != "tick" {
		return Actor{}, &session.Error{Code: status.Unauthenticated, Message: "not a test ticket"}
	}
	exp, _ := strconv.ParseInt(parts[4], 10, 64)
	return Actor{Principal: parts[1] + ":" + parts[2], LoginSession: parts[3], Expires: time.Unix(exp, 0)}, nil
}

// TestAuthRefresh (5.5): a session whose authentication expires gets
// AuthStatus before the end and GoAway(unauthenticated) at the end; an
// AuthRefresh for the same principal and login session extends it, and one
// for another principal or login session closes the session.
func TestAuthRefresh(t *testing.T) {
	t.Parallel()
	clk := testutil.NewFakeClock()
	f := newFixture(t, func(o *Options) {
		o.Clock = clk
		o.Authenticate = ticketAuth
	})
	f.commit(&admin.Config{Nodes: map[string]*admin.NodeConfig{}})
	exp := clk.Now().Add(5 * time.Minute)
	statuses := make(chan *wire.AuthStatus, 10)
	dial := func() *nd.Node {
		n := nd.New(nd.Options{Auth: testTicket("user:alice", "sid-1", exp), Session: func(c *session.Config) {
			c.OnAuthStatus = func(s *session.Session, m *wire.AuthStatus) { statuses <- m }
		}})
		if err := n.Dial(tctx(t), f.wsURL, nd.DialOptions{}); err != nil {
			t.Fatal(err)
		}
		f.onCleanup(n.Close)
		return n
	}
	wantStatus := func(exp time.Time) {
		t.Helper()
		select {
		case m := <-statuses:
			if status.Code(m.Status) != status.OK || m.ExpiresAt == nil || m.ExpiresAt.Sec != exp.Unix() {
				t.Fatalf("AuthStatus %+v", m)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no AuthStatus")
		}
	}
	wantGoAway := func(s *session.Session) {
		t.Helper()
		select {
		case <-s.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("session not closed")
		}
		if g := s.GoAwayReceived(); g == nil || status.Code(g.Status) != status.Unauthenticated {
			t.Fatalf("GoAway %+v (%v)", g, s.Err())
		}
	}
	// Expiry: a warning 60 s before, the end at sexp.
	n := dial()
	s := n.Session()
	// The hub has armed the warning and the end.
	testutil.Eventually(t, 5*time.Second, func() bool { return clk.Pending() >= 2 }, "expiry not armed")
	clk.Advance(4*time.Minute + time.Second)
	wantStatus(exp)
	clk.Advance(time.Minute)
	wantGoAway(s)

	// A refresh for the same principal and login session extends it.
	exp = clk.Now().Add(5 * time.Minute)
	n = dial()
	s = n.Session()
	later := exp.Add(time.Hour)
	if err := s.RefreshAuth(*testTicket("user:alice", "sid-1", later)); err != nil {
		t.Fatal(err)
	}
	wantStatus(later)
	clk.Advance(10 * time.Minute) // past the first expiry
	testutil.Never(t, 50*time.Millisecond, func() bool { return s.Err() != nil }, "closed after a refresh: %v", s.Err())
	// Another login session, or another principal: GoAway(unauthenticated).
	if err := s.RefreshAuth(*testTicket("user:alice", "sid-2", later)); err != nil {
		t.Fatal(err)
	}
	wantGoAway(s)
	exp = clk.Now().Add(5 * time.Minute)
	n = dial()
	s = n.Session()
	if err := s.RefreshAuth(*testTicket("user:bob", "sid-1", exp)); err != nil {
		t.Fatal(err)
	}
	wantGoAway(s)
	// A credential the authenticator rejects.
	n = dial()
	s = n.Session()
	if err := s.RefreshAuth(wire.Auth{Scheme: "bearer", Credentials: cbor.AppendText(nil, "nonsense")}); err != nil {
		t.Fatal(err)
	}
	wantGoAway(s)
	// Logging out ends the login session's sessions (9.2).
	n = dial()
	s = n.Session()
	testutil.Eventually(t, 5*time.Second, func() bool { return f.h.EndLoginSession("sid-1") >= 1 }, "no session for sid-1")
	wantGoAway(s)
}
