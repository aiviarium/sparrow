package main

import (
	"bytes"
	"regexp"
	"strings"
)

// Sparrow Hub Profile (section 10).

// A fixed TEST call context: 16 bytes (128 bits), normally random.
var hubContext = unhex("c0ffee00112233445566778899aabbcc")

const hubNodeID = "acme.charts"

// chartValue is a Chart struct of part acme.charts.
func chartValue() []any {
	return []any{64, "Sales", []any{[]any{"2026", []any{3, 5, 8}}}}
}

// nodeHello: the node acme.charts, spawned by the hub, speaks first on the
// pipe binding and publishes its parts in client_schema.
func nodeHello() []any {
	r := schemas()
	return []any{0, []any{1}, map[string]any{}, nil, nil, []any{2, r.nodeHash, r.node}, map[string]any{}, false}
}

// hubViewForNode: the schema the hub sends node acme.charts, i.e. the server
// schema without the node's own part 17 (section 10.3).
func hubViewForNode() []any {
	s := canonicalSchema(serverSchemaInput())
	parts := []any{}
	for _, p := range s[3].([]any) {
		if num(p.([]any)[pID]) != partCharts {
			parts = append(parts, p)
		}
	}
	s[3] = parts
	return s
}

var nodeIDRe = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)*$`)
var principalRe = regexp.MustCompile(`^(user|group|node):[A-Za-z0-9._@-]+$`)

func validPrincipal(p string) bool {
	if strings.HasPrefix(p, "peer:") {
		rest := strings.TrimPrefix(p, "peer:")
		i := strings.Index(rest, "/")
		if i < 0 {
			return false
		}
		return nodeIDRe.MatchString(rest[:i]) && principalRe.MatchString(rest[i+1:])
	}
	return principalRe.MatchString(p)
}

func partOwnedBy(node, part string) bool {
	return part == node || strings.HasPrefix(part, node+".")
}

func hubVectors() O {
	r := schemas()
	var vs []any
	add := func(v O) { vs = append(vs, v) }

	// Forwarding a unary call: client -> hub -> node and back.
	payload := chartValue()
	clientReq := []any{16, 4, partCharts, 0, map[any]any{32: 5000, 36: unhex("deadbeef"), 37: "user:mallory", "x-tenant": "acme"}, payload}
	fwdReq := []any{16, 1, 16, 0, map[any]any{32: 4950, 35: 65536, 36: hubContext, 37: "user:alice", "x-tenant": "acme"}, payload}
	svg := []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"/>")
	nodeRsp := []any{17, 1, svg}
	clientRsp := []any{17, 4, svg}
	pb, ob := enc(payload), enc(svg)
	for _, m := range [][]any{clientReq, fwdReq} {
		if !bytes.HasSuffix(enc(m), pb) {
			panic("payload not a suffix")
		}
	}
	msg := func(m []any) O { b := enc(m); return o("message", tj(m), "diag", diag(b), "cbor", hx(b)) }
	add(o(
		"name", "forward/unary",
		"description", "A client of session principal user:alice calls draw (method 0) of part 17, which belongs to node acme.charts. The hub authorizes it, then opens a call on the node's pipe link with a new call ID (1: the hub is the Sparrow server there, so odd), the node's own part ID (16), the same method ID and input bytes, deadline lowered by the 50 ms already spent, credit set to 64 KiB (no higher than the default for the caller's leased stream, 1 MiB, since the caller sent no credit), and context/principal set by the hub, replacing the values the caller sent. Every element except the call ID, the part ID and the Request's metadata is copied byte for byte. The node's Response is relayed with only the call ID changed.",
		"spec", "10.4, 10.5, 10.6",
		"type", "forward",
		"session_principal", "user:alice",
		"node_id", hubNodeID,
		"part_map", o("hub_part_id", partCharts, "node_part_id", 16, "part_hash", hx(partHash(chartsV1()))),
		"elapsed_ms", 50,
		"caller_stream", "leased",
		"caller_default_credit", 1048576,
		"client_request", msg(clientReq),
		"forwarded_request", msg(fwdReq),
		"payload_cbor", hx(pb),
		"node_response", msg(nodeRsp),
		"relayed_response", msg(clientRsp),
		"response_payload_cbor", hx(ob),
	))
	notifClient := []any{16, 0, partCharts, 3, map[any]any{36: unhex("deadbeef"), 37: "user:mallory"}, "dark"}
	notifNode := []any{16, 0, 16, 3, map[any]any{37: "user:alice"}, "dark"}
	add(o(
		"name", "forward/notification",
		"description", "A notification (setTheme, method 3, flag 0x2) is relayed with call ID 0 on both hops and no context (10.5); the caller's context and principal are dropped. The vector sets principal to the session principal, as step 2 of 10.5 still applies. The node handles it as itself.",
		"spec", "10.5, 10.6",
		"type", "forward_notification",
		"session_principal", "user:alice",
		"part_map", o("hub_part_id", partCharts, "node_part_id", 16),
		"client_request", msg(notifClient),
		"forwarded_request", msg(notifNode),
		"payload_cbor", hx(enc("dark")),
	))
	errNode := []any{20, 1, 66, "unsupported chart kind", nil}
	errClient := []any{20, 4, 66, "unsupported chart kind", nil}
	add(o(
		"name", "forward/error-relay",
		"description", "The node answers with its part's error sigil 66 instead; the hub relays the Error changing only the call ID. Sigil 66 means the same in the hub's part 17 because the part is the same part.",
		"spec", "10.5",
		"type", "relay",
		"from_node", msg(errNode),
		"to_client", msg(errClient),
		"call_id_map", o("node", 1, "client", 4),
	))
	nested := []any{16, 2, partNotes, 100, map[any]any{36: hubContext}, noteUUID}
	add(o(
		"name", "forward/node-call-with-context",
		"description", "While handling the forwarded call, the node calls get (100) of part 16 in the hub's schema for it, passing the hub's context. Its call ID is even (the node is the Sparrow client on the pipe). The hub checks both the context's principal and node:acme.charts.",
		"spec", "10.4, 10.6",
		"type", "message_with_principals",
		"request", msg(nested),
		"acting_principals", []any{"user:alice", "node:" + hubNodeID},
		"refs", o("schema", "welcome/node-pipe"),
	))
	hv := hubViewForNode()
	add(o(
		"name", "hub/view-for-node",
		"description", "The schema the hub sends node acme.charts: the server schema without the node's own part 17 (section 10.3).",
		"spec", "10.3",
		"type", "schema_view",
		"from", "schema/server-base",
		"omitted_part_ids", []any{partCharts},
		"hash", hx(schemaHash(hv)),
	))

	// Tables.
	var ids []any
	for _, id := range []string{"acme.charts", "acme", "my-node.v2", "hub-b", "Acme", "acme..charts", "acme/charts", ".acme", "acme.", "", "acme_charts"} {
		ids = append(ids, o("node_id", id, "valid", nodeIDRe.MatchString(id)))
	}
	add(o("name", "hub/node-ids", "description", "Node IDs match [a-z0-9-]+(\\.[a-z0-9-]+)* (section 10.2).", "spec", "10.2", "type", "node_id_table", "entries", ids))
	var owns []any
	for _, c := range [][2]string{{"acme.charts", "acme.charts"}, {"acme.charts", "acme.charts.admin"}, {"acme.charts", "acme.chartsx"}, {"acme.charts", "acme"}, {"acme.charts", "acme.notes"}} {
		owns = append(owns, o("node_id", c[0], "part_name", c[1], "allowed", partOwnedBy(c[0], c[1])))
	}
	add(o("name", "hub/part-names", "description", "Every part a node publishes is named after the node: equal to the node ID, or the node ID and a dot followed by more (section 10.2). Otherwise GoAway(invalid_argument).",
		"spec", "10.2", "type", "part_owner_table", "entries", owns))
	add(o("name", "hub/imported-name", "description", "An importing hub lists a part imported from peer hub-b as '<peer-id>/<name>'. Names are not hashed, so the part hash is unchanged (see schema/part-hash-invariance).",
		"spec", "10.8", "type", "imported_name", "peer_id", "hub-b", "part_name", "acme.notes", "imported_name", "hub-b/acme.notes"))
	var ps []any
	for _, p := range []string{"user:alice", "group:admins", "node:acme.charts", "user:alice@example.com", "user:a_b-c.d", "peer:hub-b/user:alice",
		"peer:hub-b/peer:hub-c/user:x", "admin:root", "user:", "user:a b", "peer:hub-b/", "peer:Hub/user:a", "peer:user:alice", "user:j\u00fcrgen"} {
		ps = append(ps, o("principal", p, "valid", validPrincipal(p)))
	}
	add(o("name", "hub/principals", "description", "Principal strings: kind:id with kind user, group or node and id of ASCII letters, digits and . _ - @; a peer principal is peer:<hub-id>/ followed by a non-peer principal, where <hub-id> follows the node-ID grammar (section 10.4).",
		"spec", "10.4", "type", "principal_table", "entries", ps))
	acting := []any{
		o("from", "client_session", "session_principal", "user:alice", "acting", []any{"user:alice"}),
		o("from", "node", "node_id", "acme.charts", "context", nil, "acting", []any{"node:acme.charts"}),
		o("from", "node", "node_id", "acme.charts", "context", "valid, issued for user:alice", "acting", []any{"user:alice", "node:acme.charts"}),
		o("from", "peer_hub", "node_id", "hub-b", "principal", nil, "acting", []any{"node:hub-b"}),
		o("from", "peer_hub", "node_id", "hub-b", "principal", "user:bob", "acting", []any{"node:hub-b", "peer:hub-b/user:bob"}),
		o("from", "peer_hub", "node_id", "hub-b", "principal", "peer:hub-c/user:x", "acting", nil, "note", "refused: a named principal may not already start with peer:"),
	}
	add(o("name", "hub/acting-principals", "description", "Acting principals the hub checks for a call, by where it arrives from (section 10.4). acting null means the hub refuses the call.",
		"spec", "10.4, 10.8", "type", "acting_principals_table", "entries", acting))
	_ = r
	return o("area", "hub", "vectors", vs)
}
