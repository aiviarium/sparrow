package conformance

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aiviarium/sparrow-rpc/go/internal/vectors"
	"github.com/aiviarium/sparrow-rpc/go/names"
	"github.com/aiviarium/sparrow-rpc/go/schema"
	"github.com/aiviarium/sparrow-rpc/go/status"
	"github.com/aiviarium/sparrow-rpc/go/wire"
)

func TestStatus(t *testing.T) {
	each(t, "status.json", func(t *testing.T, v vectors.Vector) {
		if v.Int("websocket_reason_max_bytes") != status.MaxWebSocketReason ||
			v.Int("webtransport_reason_max_bytes") != status.MaxWebTransportReason {
			t.Fatal("reason limits")
		}
		var es []struct {
			Status uint64 `json:"status"`
			Name   string `json:"name"`
			WS     int    `json:"websocket_close_code"`
			WTS    uint32 `json:"webtransport_session_close_code"`
			WTR    uint32 `json:"webtransport_stream_reset_code"`
		}
		v.Into("entries", &es)
		if len(es) != 23 {
			t.Fatalf("%d entries", len(es))
		}
		for _, e := range es {
			c := status.Code(e.Status)
			ws, err := status.WebSocketCloseCode(c)
			wt, err2 := status.WebTransportCode(c)
			if c.Name() != e.Name || err != nil || err2 != nil || ws != e.WS || wt != e.WTS || wt != e.WTR {
				t.Errorf("status %d: %s %d %d", e.Status, c.Name(), ws, wt)
			}
			if back, ok := status.FromWebSocketCloseCode(ws); !ok || back != c {
				t.Errorf("status %d: websocket round trip", e.Status)
			}
			if back, ok := status.FromWebTransportCode(wt); !ok || back != c {
				t.Errorf("status %d: webtransport round trip", e.Status)
			}
			if byName, ok := status.ByName(e.Name); !ok || byName != c {
				t.Errorf("ByName(%s)", e.Name)
			}
		}
	}, "status_table")

	each(t, "status.json", func(t *testing.T, v vectors.Vector) {
		var es []struct {
			Status uint64 `json:"status"`
			Name   string `json:"name"`
			WS     int    `json:"websocket_close_code"`
		}
		v.Into("entries", &es)
		for _, e := range es {
			c := status.Code(e.Status)
			ws, err := status.WebSocketCloseCode(c)
			if err != nil || ws != e.WS || c.Name() != e.Name || !c.IsCore() || c.IsDefined() {
				t.Errorf("status %d: %d %v", e.Status, ws, err)
			}
		}
	}, "status_reserved")

	each(t, "status.json", func(t *testing.T, v vectors.Vector) {
		var cases []struct {
			Max       int    `json:"max_bytes"`
			Reason    string `json:"reason_utf8"`
			Len       int    `json:"reason_length"`
			Truncated string `json:"truncated_utf8"`
			TruncLen  int    `json:"truncated_length"`
		}
		v.Into("cases", &cases)
		for _, c := range cases {
			got := status.TruncateReason(c.Reason, c.Max)
			if len(c.Reason) != c.Len || got != c.Truncated || len(got) != c.TruncLen {
				t.Errorf("max %d: got %d bytes, want %d", c.Max, len(got), c.TruncLen)
			}
		}
	}, "reason_truncation")

	each(t, "status.json", func(t *testing.T, v vectors.Vector) {
		c := status.Code(v.Int("status"))
		carriers := map[string]status.Carrier{
			"Error": status.InError, "Cancel": status.InCancel, "GoAway": status.InGoAway,
			"AuthStatus": status.InAuthStatus, "webtransport_stream_reset": status.InWebTransportStreamReset,
			"webtransport_session_close": status.InWebTransportSessionClose, "websocket_close": status.InWebSocketClose,
		}
		var allowed, notAllowed []string
		v.Into("allowed_in", &allowed)
		v.Into("not_allowed_in", &notAllowed)
		for _, a := range allowed {
			if !c.AllowedIn(carriers[a]) {
				t.Errorf("%d not allowed in %s", c, a)
			}
		}
		for _, a := range notAllowed {
			if c.AllowedIn(carriers[a]) {
				t.Errorf("%d allowed in %s", c, a)
			}
		}
		if _, err := status.WebSocketCloseCode(c); err == nil {
			t.Error("websocket mapping of an application code")
		}
		// a decoder rejects the code where only core codes may appear
		for _, msg := range [][]byte{
			wire.Encode(&wire.Cancel{CallID: 2, Status: uint64(c)}),
			wire.Encode(&wire.GoAway{Status: uint64(c), Reason: "x"}),
			wire.Encode(&wire.AuthStatus{Status: uint64(c)}),
		} {
			if _, err := wire.Decode(msg); err == nil {
				t.Errorf("decoder accepted application status in %x", msg)
			}
		}
		if _, err := wire.Decode(wire.Encode(&wire.Error{CallID: 2, Status: uint64(c), Message: "x"})); err != nil {
			t.Error(err)
		}
	}, "status_scope")
}

type hubMsg struct {
	Message json.RawMessage `json:"message"`
	CBOR    string          `json:"cbor"`
}

func hubMessage(t *testing.T, v vectors.Vector, field string) (wire.Message, []byte) {
	t.Helper()
	var m hubMsg
	v.Into(field, &m)
	b := vectors.MustHex(m.CBOR)
	return checkMessageBytes(t, field, m.Message, b), b
}

func TestHub(t *testing.T) {
	each(t, "hub.json", func(t *testing.T, v vectors.Vector) {
		cm, _ := hubMessage(t, v, "client_request")
		fm, fb := hubMessage(t, v, "forwarded_request")
		req, fwd := cm.(*wire.Request), fm.(*wire.Request)
		var pm struct {
			Hub  uint64 `json:"hub_facet_id"`
			Node uint64 `json:"node_facet_id"`
			Hash string `json:"facet_hash"`
		}
		v.Into("facet_map", &pm)
		if req.FacetID != pm.Hub {
			t.Fatalf("caller facet %d", req.FacetID)
		}
		// Build the forwarded metadata as a hub does (10.5, 10.6).
		md := req.Metadata.Clone()
		dl, ok, err := md.Deadline()
		if err != nil || !ok {
			t.Fatal("deadline")
		}
		md.SetDeadline(dl - uint64(v.Int("elapsed_ms")))
		ctx, _, _ := fwd.Metadata.Context()
		md.SetContext(ctx) // the hub's fresh context replaces the caller's
		md.SetPrincipal(v.String("session_principal"))
		credit, _, _ := fwd.Metadata.Credit()
		if credit > uint64(v.Int("caller_default_credit")) {
			t.Fatalf("forwarded credit %d above the caller's default", credit)
		}
		md.SetCredit(credit)
		out := wire.ForwardRequest(req, fwd.CallID, pm.Node, md)
		if !bytes.Equal(out, fb) {
			t.Fatalf("forwarded request\n got %x\nwant %x", out, fb)
		}
		if !bytes.Equal(fwd.Input, v.Hex("payload_cbor")) || !bytes.Equal(req.Input, fwd.Input) {
			t.Fatal("payload not copied byte for byte")
		}
		if wire.CallerOf(fwd.CallID) != wire.Server {
			t.Fatal("hub call IDs on the link of a node that dialed in are odd")
		}
		facet := stateOf(t, "schema/node-acme-charts").Schema().Facet(pm.Node)
		if h, _ := facet.Hash(); hx(h) != pm.Hash {
			t.Fatal("facet hash")
		}
		_, nb := hubMessage(t, v, "node_response")
		_, rb := hubMessage(t, v, "relayed_response")
		got, err := wire.RewriteCallID(nb, req.CallID)
		if err != nil || !bytes.Equal(got, rb) {
			t.Fatalf("relayed response %x", got)
		}
		if !bytes.Contains(rb, v.Hex("response_payload_cbor")) {
			t.Fatal("response payload")
		}
	}, "forward")

	each(t, "hub.json", func(t *testing.T, v vectors.Vector) {
		cm, _ := hubMessage(t, v, "client_request")
		fm, fb := hubMessage(t, v, "forwarded_request")
		req, fwd := cm.(*wire.Request), fm.(*wire.Request)
		var pm struct {
			Hub  uint64 `json:"hub_facet_id"`
			Node uint64 `json:"node_facet_id"`
		}
		v.Into("facet_map", &pm)
		md := wire.Metadata{}
		md.SetPrincipal(v.String("session_principal")) // no context on notifications
		out := wire.ForwardRequest(req, wire.NotificationID, pm.Node, md)
		if req.CallID != 0 || !bytes.Equal(out, fb) || !bytes.Equal(fwd.Input, v.Hex("payload_cbor")) {
			t.Fatalf("forwarded notification %x", out)
		}
		if _, ok, _ := fwd.Metadata.Context(); ok {
			t.Fatal("context on a notification")
		}
	}, "forward_notification")

	each(t, "hub.json", func(t *testing.T, v vectors.Vector) {
		_, from := hubMessage(t, v, "from_node")
		_, to := hubMessage(t, v, "to_client")
		var ids struct{ Node, Client uint64 }
		v.Into("call_id_map", &ids)
		if k, id, err := wire.PeekCall(from); err != nil || k != wire.KindError || id != ids.Node {
			t.Fatal("PeekCall")
		}
		got, err := wire.RewriteCallID(from, ids.Client)
		if err != nil || !bytes.Equal(got, to) {
			t.Fatalf("relayed error %x", got)
		}
	}, "relay")

	each(t, "hub.json", func(t *testing.T, v vectors.Vector) {
		m, _ := hubMessage(t, v, "request")
		req := m.(*wire.Request)
		ctx, ok, err := req.Metadata.Context()
		if !ok || err != nil || len(ctx) < 16 {
			t.Fatal("context of at least 128 bits")
		}
		var acting []string
		v.Into("acting_principals", &acting)
		// a node with a valid context acts as the context's principal and itself
		if len(acting) != 2 || !names.IsPrincipal(acting[0]) || acting[1] != names.NodePrincipal("acme.charts") {
			t.Fatalf("acting %v", acting)
		}
		var refs map[string]string
		v.Into("refs", &refs)
		wm, err := wire.Decode(vector(t, refs["schema"]).Hex("cbor"))
		if err != nil {
			t.Fatal(err)
		}
		s, err := schema.DecodeSchema(wm.(*wire.Welcome).ServerSchema.Schema)
		if err != nil {
			t.Fatal(err)
		}
		if f := s.Facet(req.FacetID); f == nil {
			t.Fatal("facet not in the node's view")
		} else if meth, _ := f.Method(req.MethodID); meth == nil {
			t.Fatal("method not in the node's view")
		}
	}, "message_with_principals")

	each(t, "hub.json", func(t *testing.T, v vectors.Vector) {
		base := stateOf(t, v.String("from")).Schema()
		var omit []uint64
		v.Into("omitted_facet_ids", &omit)
		view := base.View(omit...)
		if err := view.Validate(); err != nil {
			t.Fatal(err)
		}
		if h, _ := view.Hash(); !bytes.Equal(h, v.Hex("hash")) {
			t.Fatalf("view hash %x", h)
		}
		w, _ := wire.Decode(vector(t, "welcome/node-dial-in").Hex("cbor"))
		if !bytes.Equal(w.(*wire.Welcome).ServerSchema.Hash, v.Hex("hash")) {
			t.Fatal("welcome/node-dial-in offers a different schema")
		}
	}, "schema_view")

	each(t, "hub.json", func(t *testing.T, v vectors.Vector) {
		var es []struct {
			ID    string `json:"node_id"`
			Valid bool   `json:"valid"`
		}
		v.Into("entries", &es)
		for _, e := range es {
			if names.IsNodeID(e.ID) != e.Valid {
				t.Errorf("IsNodeID(%q)", e.ID)
			}
		}
	}, "node_id_table")

	each(t, "hub.json", func(t *testing.T, v vectors.Vector) {
		var es []struct {
			Node    string `json:"node_id"`
			Name    string `json:"facet_name"`
			Allowed bool   `json:"allowed"`
		}
		v.Into("entries", &es)
		for _, e := range es {
			if names.OwnedBy(e.Node, e.Name) != e.Allowed {
				t.Errorf("OwnedBy(%q, %q)", e.Node, e.Name)
			}
		}
	}, "facet_owner_table")

	each(t, "hub.json", func(t *testing.T, v vectors.Vector) {
		got := names.Imported(v.String("peer_id"), v.String("facet_name"))
		if got != v.String("imported_name") || !names.IsFacetName(got) {
			t.Fatalf("Imported = %q", got)
		}
		if p, l := names.SplitPeer(got); p != v.String("peer_id") || l != v.String("facet_name") {
			t.Fatal("SplitPeer")
		}
	}, "imported_name")

	each(t, "hub.json", func(t *testing.T, v vectors.Vector) {
		var es []struct {
			P     string `json:"principal"`
			Valid bool   `json:"valid"`
		}
		v.Into("entries", &es)
		for _, e := range es {
			if names.IsPrincipal(e.P) != e.Valid {
				t.Errorf("IsPrincipal(%q)", e.P)
			}
		}
	}, "principal_table")

	each(t, "hub.json", func(t *testing.T, v vectors.Vector) {
		var es []struct {
			From      string   `json:"from"`
			Session   string   `json:"session_principal"`
			Node      string   `json:"node_id"`
			Context   *string  `json:"context"`
			Principal *string  `json:"principal"`
			Acting    []string `json:"acting"`
		}
		v.Into("entries", &es)
		for _, e := range es {
			var got []string
			switch e.From {
			case "client_session":
				got = []string{e.Session}
			case "node":
				if e.Context != nil {
					got = []string{"user:alice"} // the context's principal
				}
				got = append(got, names.NodePrincipal(e.Node))
			case "peer_hub":
				got = []string{names.NodePrincipal(e.Node)}
				if e.Principal != nil {
					p, ok := names.PeerPrincipal(e.Node, *e.Principal)
					if !ok {
						got = nil
					} else {
						got = append(got, p)
					}
				}
			}
			if !equalStrings(got, e.Acting) {
				t.Errorf("%+v: acting %v", e, got)
			}
		}
	}, "acting_principals_table")
}
