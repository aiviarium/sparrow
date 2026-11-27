package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

var kindNames = map[int]string{
	0: "Hello", 1: "Welcome", 2: "Ready",
	3: "SchemaUpdate", 4: "SchemaAck", 5: "AuthRefresh", 6: "AuthStatus", 7: "Ping", 8: "Pong", 9: "GoAway",
	16: "Request", 17: "Response", 18: "Item", 19: "End", 20: "Error", 21: "Progress",
	22: "Headers", 23: "Cancel", 24: "Credit", 25: "Bytes",
}

func msgVec(name, desc, spec string, msg []any, extra ...any) O {
	b := enc(msg)
	k := int(num(msg[0]))
	v := o(
		"name", name,
		"description", desc,
		"spec", spec,
		"type", "message",
		"kind", k,
		"kind_name", kindNames[k],
		"message", tj(msg),
		"diag", diag(b),
		"cbor", hx(b),
		"length", len(b),
		"framed", hx(cat(varint(uint64(len(b))), b)),
	)
	return append(v, o(extra...)...)
}

// Fixed, clearly fake values used across vectors.
var (
	testTicket    = "v4.public.TEST-ONLY-TICKET"
	testSessionID = unhex("000102030405060708090a0b0c0d0e0f")
	noteUUID      = cbor.Tag{Number: 37, Content: unhex("6f1c2e4a8b3d4f5e9a7b0c1d2e3f4a5b")}
	note2UUID     = cbor.Tag{Number: 37, Content: unhex("0b5e7d3c2a194f8e8d7c6b5a49382716")}
	traceBin      = unhex("00" + "4bf92f3577b34da6a3ce929d0e0e4736" + "00f067aa0ba902b7" + "01")
)

func ts(sec uint64) cbor.Tag { return cbor.Tag{Number: 1, Content: sec} }

// A Note value (struct 64): tags 0..4, tag 5 removed (null), tag 6 color,
// tag 7 pinned absent -> trailing slot omitted.
func noteValue() []any {
	return []any{noteUUID, "Groceries", "milk, eggs", []any{"home"}, ts(1795737600), nil, sgGreen}
}

// ---------------------------------------------------------------------------

func framingVectors() O {
	var vs []any
	for _, v := range []uint64{0, 37, 63, 64, 15293, 16383, 16384, 494878333, 1<<30 - 1, 1 << 30, 151288809941952652, 1<<62 - 1} {
		vs = append(vs, o(
			"name", fmt.Sprintf("varint/%d", v),
			"description", "QUIC variable-length integer, shortest form.",
			"spec", "4.1 (RFC 9000, section 16)",
			"type", "quic_varint",
			"value", tj(v),
			"encoded", hx(varint(v)),
		))
	}
	for _, nm := range []struct{ enc, desc string }{
		{"4025", "Two-byte encoding of 37 (RFC 9000, section A.1)."},
		{"80000025", "Four-byte encoding of 37."},
		{"c000000000000025", "Eight-byte encoding of 37."},
		{"4000", "Two-byte encoding of 0."},
	} {
		vs = append(vs, o(
			"name", "varint/non-minimal-"+nm.enc,
			"description", nm.desc+" Senders use the shortest form; receivers MUST accept any valid form (section 4.1).",
			"spec", "4.1 (RFC 9000, section 16)",
			"type", "quic_varint",
			"decode_only", true,
			"value", int(num(varintValue(unhex(nm.enc)))),
			"encoded", nm.enc,
		))
	}
	vs = append(vs, o(
		"name", "stream-header/table",
		"description", "Meaning of the first byte the opener of a stream sends. The other direction has no header.",
		"spec", "4.1",
		"type", "stream_header_table",
		"entries", []any{
			o("byte", "00", "shared_lane_open", false, "opener", "client", "result", "shared_lane", "note", "first shared lane"),
			o("byte", "00", "shared_lane_open", true, "opener", "client", "result", "protocol_error", "note", "a second shared lane"),
			o("byte", "00", "shared_lane_open", false, "opener", "server", "result", "protocol_error", "note", "shared lane opened by the server"),
			o("byte", "01", "shared_lane_open", false, "opener", "client", "result", "leased_stream"),
			o("byte", "01", "shared_lane_open", false, "opener", "server", "result", "leased_stream"),
			o("byte", "02", "shared_lane_open", false, "opener", "client", "result", "protocol_error"),
			o("byte", "3f", "shared_lane_open", false, "opener", "client", "result", "protocol_error"),
			o("byte", "40", "shared_lane_open", false, "opener", "client", "result", "profile_reserved"),
			o("byte", "7f", "shared_lane_open", false, "opener", "server", "result", "profile_reserved"),
			o("byte", "80", "shared_lane_open", false, "opener", "client", "result", "protocol_error"),
			o("byte", "ff", "shared_lane_open", false, "opener", "client", "result", "protocol_error"),
		},
	))
	var kinds []any
	for _, k := range []int{0, 25, 26, 47, 48, 63, 64, 111, 112, 127, 128, 1000} {
		owner, action := kindRange(k)
		kinds = append(kinds, o("kind", k, "owner", owner, "if_unknown", action))
	}
	vs = append(vs, o(
		"name", "envelope/kind-ranges",
		"description", "What a receiver does with a message whose kind it does not know. Kinds 0-9 and 16-25 are defined by this revision; every other kind in 0-47 is unknown.",
		"spec", "3.3",
		"type", "kind_range_table",
		"entries", kinds,
	))

	req := []any{16, 2, 16, 1042, map[string]any{}, []any{"settings", true}}
	rsp := []any{17, 2, nil}
	wantReq := unhex("13 86 10 02 10 19 04 12 a0 82 68 73 65 74 74 69 6e 67 73 f5")
	wantRsp := unhex("04 83 11 02 f6")
	gotReq := cat(varint(uint64(len(enc(req)))), enc(req))
	gotRsp := cat(varint(uint64(len(enc(rsp)))), enc(rsp))
	if !bytes.Equal(gotReq, wantReq) || !bytes.Equal(gotRsp, wantRsp) {
		panic(fmt.Sprintf("section 7.7 example mismatch: %x / %x", gotReq, gotRsp))
	}
	vs = append(vs, msgVec("example-7.7/request",
		"Section 7.7 example: unary Request, call ID 2, facet 16, method 1042 (Panels.open), empty metadata, input struct [\"settings\", true]: 19 bytes. Confirms the spec bytes exactly.",
		"7.7", req, "spec_framed", hx(wantReq), "matches_spec", true))
	vs = append(vs, msgVec("example-7.7/response",
		"Section 7.7 example: Response [17, 2, null] on the same leased stream. Confirms the spec bytes exactly.",
		"7.7", rsp, "spec_framed", hx(wantRsp), "matches_spec", true))

	long := strings.Repeat("x", 100)
	vs = append(vs, msgVec("framing/two-byte-prefix",
		"Item whose CBOR is longer than 63 bytes, so the length prefix takes two bytes.",
		"4.1, 7.2", []any{18, 6, long}))

	reqB := enc(req)
	vs = append(vs, o(
		"name", "framing/non-minimal-prefix",
		"description", "The 7.7 Request with its length 19 written as a two-byte varint (40 13). A receiver MUST accept it and read the same message; a sender would write 13.",
		"spec", "4.1",
		"type", "stream",
		"decode_only", true,
		"parts", []any{
			o("what", "length prefix, non-minimal", "hex", "4013"),
			o("what", "Request", "hex", hx(reqB), "ref", "example-7.7/request"),
		},
		"bytes", hx(cat(unhex("4013"), reqB)),
	))

	// Whole stream openings.
	hello := helloBasic()
	hb := enc(hello)
	vs = append(vs, o(
		"name", "stream/shared-lane-open",
		"description", "First bytes the client writes on the shared lane: header 0x00, then the length-prefixed Hello (handshake vector hello/basic).",
		"spec", "4.1, 5.2",
		"type", "stream",
		"parts", []any{
			o("what", "stream header (shared lane)", "hex", "00"),
			o("what", "length prefix", "hex", hx(varint(uint64(len(hb))))),
			o("what", "Hello", "hex", hx(hb), "ref", "hello/basic"),
		},
		"bytes", hx(cat([]byte{0}, varint(uint64(len(hb))), hb)),
	))
	vs = append(vs, o(
		"name", "stream/leased-open-7.7",
		"description", "The caller's direction of the leased stream in section 7.7 when it is newly opened: header 0x01, then the framed Request. The callee's direction carries only the framed Response (no header).",
		"spec", "4.1, 7.7",
		"type", "stream",
		"parts", []any{
			o("what", "stream header (leased stream)", "hex", "01"),
			o("what", "framed Request", "hex", hx(wantReq), "ref", "example-7.7/request"),
		},
		"bytes", hx(cat([]byte{1}, wantReq)),
		"reverse_bytes", hx(wantRsp),
	))
	vs = append(vs, o(
		"name", "websocket/7.7",
		"description", "WebSocket binding: each binary WebSocket message carries exactly one Sparrow message, with no length prefix and no stream header.",
		"spec", "4.6",
		"type", "websocket",
		"ws_messages", []any{hx(enc(req)), hx(enc(rsp))},
	))
	return o("area", "framing", "vectors", vs)
}

func kindRange(k int) (string, string) {
	switch {
	case k <= 47:
		return "core", "close_protocol_error"
	case k <= 63:
		return "core", "ignore"
	case k <= 111:
		return "profile", "close_protocol_error"
	case k <= 127:
		return "profile", "ignore"
	}
	return "invalid", "close_protocol_error"
}

// ---------------------------------------------------------------------------

func helloBasic() []any {
	return []any{0, []any{1}, map[string]any{}, []any{"bearer", testTicket}, nil, nil, map[string]any{}, false}
}

func handshakeVectors() O {
	r := schemas()
	props := map[string]any{"web.title": "Acme Notes", "server": "acme-host/2026.12.1"}
	wparams := map[string]any{"maxMessageSize": 4194304, "maxStreams": 32, "leaseCredit": 2097152, "idleTimeoutMs": 20000}
	var vs []any
	vs = append(vs, msgVec("hello/basic",
		"Minimal Hello: protocol version 1, no capabilities, a bearer ticket (fake), no cached schema, no client schema, default params, not optimistic.",
		"5.4", helloBasic()))
	vs = append(vs, msgVec("hello/full",
		"Hello speaking versions 2 and 1 (2 preferred), datagrams capability, bearer ticket, the cached server schema hash, the client's own schema inline as [2, hash, schema], and params limiting the server to 2 leased streams and 64 concurrent calls.",
		"5.4, 6.1", []any{0, []any{2, 1}, map[string]any{"datagrams": true}, []any{"bearer", testTicket},
			r.baseHash, []any{2, r.clientHash, r.client},
			map[string]any{"maxStreams": 2, "maxConcurrentCalls": 64}, false},
		"refs", o("known_schema", "schema/server-base", "client_schema", "schema/client")))
	vs = append(vs, msgVec("hello/optimistic",
		"Optimistic Hello (section 5.3): exactly one protocol version, the cached schema hash, optimistic = true.",
		"5.3, 5.4", []any{0, []any{1}, map[string]any{}, []any{"bearer", testTicket}, r.baseHash, nil, map[string]any{}, true},
		"refs", o("known_schema", "schema/server-base")))
	vs = append(vs, msgVec("welcome/unchanged",
		"Welcome choosing version 1, datagrams, a fixed TEST session_id (00..0f), server props, schema offer [0, hash] (client's cached schema is current) and server params.",
		"5.4", []any{1, 1, map[string]any{"datagrams": true}, testSessionID, props, []any{0, r.baseHash}, wparams},
		"refs", o("hash", "schema/server-base")))
	vs = append(vs, msgVec("welcome/delta",
		"Welcome with schema offer [1, hash, from, delta]: the delta of vector schema/delta-1-replace-facet from the schema the client named.",
		"5.4, 6.6", []any{1, 1, map[string]any{}, testSessionID, props, []any{1, r.hA, r.baseHash, deltaA()}, map[string]any{}},
		"refs", o("hash", "schema/delta-1-replace-facet", "from", "schema/server-base")))
	vs = append(vs, msgVec("welcome/full",
		"Welcome with the full canonical schema inline: [2, hash, schema].",
		"5.4, 6.2", []any{1, 1, map[string]any{}, testSessionID, props, []any{2, r.baseHash, r.base.doc}, wparams},
		"refs", o("hash", "schema/server-base")))
	vs = append(vs, msgVec("welcome/out-of-band",
		"Welcome telling the client to fetch the schema over HTTP: [3, hash, location]. The location uses the web profile URL with the hash in base64url without padding.",
		"5.4, 9.3", []any{1, 1, map[string]any{}, testSessionID, props, []any{3, r.baseHash, "/sparrow/schema/" + b64url(r.baseHash)}, wparams},
		"refs", o("hash", "schema/server-base")))
	vs = append(vs, msgVec("ready",
		"Ready naming the server schema hash the client loaded.",
		"5.4", []any{2, r.baseHash}, "refs", o("schema_hash", "schema/server-base")))
	vs = append(vs, msgVec("hello/node-dial-in",
		"Hello from node 'acme.charts', which dials in: it presents [\"link\", credential] (section 10.2), and its facets travel in client_schema.",
		"10.2", nodeHello(), "refs", o("client_schema", "schema/node-acme-charts")))
	hv := hubViewForNode()
	vs = append(vs, msgVec("welcome/node-dial-in",
		"The hub's Welcome to node 'acme.charts', which dialed in: the full schema of the hub's view the node may call, which leaves out the node's own facet (section 10.3).",
		"10.2, 10.3", []any{1, 1, map[string]any{}, testSessionID, map[string]any{}, []any{2, schemaHash(hv), hv}, map[string]any{}}))
	vs = append(vs, msgVec("goaway/unsupported-version",
		"GoAway(unsupported_version) listing the server's versions.",
		"5.4, 5.5", []any{9, 19, "no common protocol version", nil, []any{1}}))
	vs = append(vs, msgVec("goaway/unauthenticated",
		"GoAway(unauthenticated) after a rejected credential.",
		"5.4, 5.5", []any{9, 16, "credential rejected", nil, nil}))
	vs = append(vs, msgVec("goaway/schema-mismatch",
		"GoAway(schema_mismatch) with retry_after_ms 0, as after a rejected optimistic start (section 5.3).",
		"5.3, 5.5", []any{9, 18, "schema changed", 0, nil}))
	vs = append(vs, msgVec("goaway/draining",
		"GoAway(going_away) before a deploy, asking the client to reconnect after 15 s.",
		"5.5, 5.6", []any{9, 21, "server restarting for deploy", 15000, nil}))
	vs = append(vs, paramsVectors()...)
	return o("area", "handshake", "vectors", vs)
}

// ---------------------------------------------------------------------------

func callVectors() O {
	r := schemas()
	var vs []any
	add := func(name, desc, spec string, msg []any, extra ...any) {
		vs = append(vs, msgVec(name, desc, spec, msg, extra...))
	}
	md := map[any]any{32: 5000, 33: traceBin, 35: 262144, "x-tenant": "acme"}
	add("request/get-with-metadata", "Unary Request (call 2) to facet 16 (acme.notes), method get (100), with core metadata keys deadline (32) = 5000 ms, trace (33) = 26-byte packed traceparent, credit (35) = 256 KiB, plus an application text key. Input is a NoteId (uuid, tag 37).",
		"7.2", []any{16, 2, facetNotes, 100, md, noteUUID})
	add("response/get", "Response (call 2) carrying a Note struct: tag 5 is a tombstoned field (flag 0x4), sent as null; tag 7 'pinned' is absent so the trailing null is omitted.",
		"7.2, 3.4", []any{17, 2, noteValue()})
	add("request/put", "Unary Request (call 4) to put (101) with a Note.", "7.2", []any{16, 4, facetNotes, 101, map[string]any{}, noteValue()})
	add("response/put", "Response (call 4) with the NoteId.", "7.2", []any{17, 4, noteUUID})
	add("error/application", "Error (call 4) with the method's own error sigil conflict (65) of facet 16 and details as a dynamic value [type_id, value] (here type 6 string).",
		"7.2, 8", []any{20, 4, sgConflct, "note was modified concurrently", []any{6, "expected revision 7"}})
	add("error/core-no-details", "Error with a core status (deadline_exceeded, 4) and no details.", "7.2, 8", []any{20, 14, 4, "deadline exceeded", nil})
	add("request/watch", "Server-stream subscription Request (call 6) to watch (102, flag shared) with a sparse NoteFilter {1: green, 2: 50}.",
		"7.2, 7.3, 3.4", []any{16, 6, facetNotes, 102, map[string]any{}, map[any]any{1: sgGreen, 2: 50}})
	add("headers", "Headers (call 6) before the first Item.", "7.2", []any{22, 6, map[string]any{"x-cursor": "c-1842"}})
	add("item/upserted", "Item (call 6): union Change variant 0 'upserted' with a Note.", "7.2, 3.4", []any{18, 6, []any{0, noteValue()}})
	add("item/deleted", "Item (call 6): union Change variant 1 'deleted' with a NoteId.", "7.2, 3.4", []any{18, 6, []any{1, note2UUID}})
	add("item/cleared", "Item (call 6): union Change variant 2 'cleared' with unit (null).", "7.2, 3.4", []any{18, 6, []any{2, nil}})
	add("credit", "Credit (call 6) granting 32768 more bytes.", "7.2, 7.4", []any{24, 6, 32768})
	add("cancel", "Cancel (call 6) with status cancelled (1).", "7.2, 7.5", []any{23, 6, 1})
	add("error/cancelled", "The callee's final answer to the Cancel: Error(cancelled).", "7.5", []any{20, 6, 1, "cancelled", nil})
	add("request/export", "Download Request (call 8) to export (104, output [4]) with a sparse NoteFilter {0: \"groceries\"}.",
		"7.3, 7.8", []any{16, 8, facetNotes, 104, map[string]any{}, map[any]any{0: "groceries"}})
	add("progress/with-total", "Progress (call 8): 512 KiB of 2 MiB done, with a note.", "7.2", []any{21, 8, 524288, 2097152, "exporting"})
	add("progress/minimal", "Progress (call 8) with total and note null.", "7.2", []any{21, 8, 10, nil, nil})
	add("bytes/inline-chunk", "Bytes (call 8), token 0 (inline, output type is exactly [4]), not final.", "7.2, 7.8", []any{25, 8, 0, []byte("PK\x03\x04"), false})
	add("bytes/inline-final-empty", "Bytes (call 8), token 0, empty final chunk (allowed).", "7.8", []any{25, 8, 0, []byte{}, true})
	add("end/empty-trailers", "End (call 8) with empty trailers, finishing the callee's half (flag 0x10).", "7.2, 7.1", []any{19, 8, map[string]any{}})
	add("request/attach-by-reference", "Request (call 10) to attach (103, flag 0x8). The Attachment struct's [4] field (tag 2) carries byte token 1.",
		"7.8, 3.4", []any{16, 10, facetNotes, 103, map[string]any{}, []any{"photo.jpg", "image/jpeg", 1}})
	add("bytes/token-1-final", "Bytes (call 10) for token 1, final chunk.", "7.8", []any{25, 10, 1, unhex("ffd8ffe000104a464946"), true})
	add("end/with-trailers", "End (call 10) finishing the caller's half, with an application trailer.", "7.2", []any{19, 10, map[string]any{"x-bytes": 10}})
	add("response/attach", "Response (call 10): unit output (null).", "7.2", []any{17, 10, nil})
	add("request/import-client-stream", "Client-stream Request (call 12) to import (110): input null, Items follow.", "7.3", []any{16, 12, facetNotes, 110, map[string]any{}, nil})
	add("item/import", "Item (call 12) carrying a Note.", "7.2", []any{18, 12, noteValue()})
	add("response/import", "Response (call 12): uint count.", "7.2", []any{17, 12, 1})
	add("request/server-to-client", "Request from server to client (odd call ID 1) to facet 16 of the client schema, method navigate (65): IDs belong to the callee's (client's) schema.",
		"6.1, 7.1", []any{16, 1, 16, 65, map[string]any{}, "/notes/6f1c2e4a"})
	add("request/notification", "Notification: Request with call ID 0 to touch (113, flag 0x2), input unit. Sent on the shared lane, no reply.",
		"7.1, 7.3", []any{16, 0, facetNotes, 113, map[string]any{}, nil})

	add("request/module-rejected", "Client to server: notification moduleRejected (facet 1 sparrow.web, service 0, method 0) with [id, version, reason] for a module whose hostApi range excludes the client's host API.",
		"9.4", []any{16, 0, facetWeb, 0, map[string]any{}, []any{"acme.charts.ui", "1.4.2", "hostApi ^4.0 does not include 3.2.0"}})
	add("request/render", "Request (call 14) to facet 17 (acme.charts), method draw (0) of the Renderer interface, with a Chart struct.",
		"7.2, 6.5", []any{16, 14, facetCharts, 0, map[string]any{}, chartValue()})
	add("control/schema-update", "SchemaUpdate epoch 1 with the new hash and the delta of vector schema/delta-1-replace-facet.",
		"5.5, 6.6", []any{3, 1, r.hA, deltaA()}, "refs", o("hash", "schema/delta-1-replace-facet"))
	add("control/schema-ack", "SchemaAck acknowledging epoch 1.", "5.5, 6.6", []any{4, 1})
	add("control/auth-refresh", "AuthRefresh with a fresh (fake) bearer ticket.", "5.5", []any{5, []any{"bearer", "v4.public.TEST-ONLY-REFRESHED"}})
	add("control/auth-status-ok", "AuthStatus ok with the session expiry as a timestamp (tag 1, integer seconds).", "5.5", []any{6, 0, ts(1795766400)})
	add("control/auth-status-expiring", "AuthStatus warning: unauthenticated (16), no expiry.", "5.5", []any{6, 16, nil})
	add("control/ping", "Ping with nonce 42.", "5.5", []any{7, 42})
	add("control/pong", "Pong echoing nonce 42.", "5.5", []any{8, 42})
	add("control/goaway", "GoAway(protocol_error) outside any call.", "5.5, 8", []any{9, 17, "unknown message kind 26", nil, nil})
	msg := func(m []any) O { b := enc(m); return o("message", tj(m), "diag", diag(b), "cbor", hx(b)) }
	for _, u := range []struct {
		name, desc string
		req, err   []any
	}{
		{"unimplemented/unknown-method", "A Request naming method 99, which facet 16 of the callee's schema does not have, is answered with Error(unimplemented) (7.1).",
			[]any{16, 16, facetNotes, 99, map[string]any{}, nil}, []any{20, 16, 12, "unknown method 99 in part 16", nil}},
		{"unimplemented/unknown-facet", "A Request naming facet 40, which the callee's schema does not have, is answered with Error(unimplemented) (7.1).",
			[]any{16, 18, 40, 0, map[string]any{}, nil}, []any{20, 18, 12, "unknown part 40", nil}},
	} {
		vs = append(vs, o("name", u.name, "description", u.desc, "spec", "7.1, 8", "type", "unimplemented",
			"schema", "schema/server-base", "request", msg(u.req), "error", msg(u.err)))
	}
	return o("area", "calls", "vectors", vs)
}

// ---------------------------------------------------------------------------

func creditCount(msg []any) int {
	switch num(msg[0]) {
	case 18, 21:
		return len(enc(msg))
	case 25:
		return len(msg[3].([]byte))
	}
	return 0
}

func creditVectors() O {
	var vs []any
	cases := []struct {
		name, desc string
		msg        []any
	}{
		{"item/small", "Item with a small union value.", []any{18, 6, []any{1, note2UUID}}},
		{"item/note", "Item with a Note.", []any{18, 6, []any{0, noteValue()}}},
		{"item/long-string", "Item whose length prefix takes two bytes: the prefix is not counted.", []any{18, 6, strings.Repeat("x", 100)}},
		{"progress", "Progress counts like Item.", []any{21, 8, 524288, 2097152, "exporting"}},
		{"bytes/4", "Bytes counts only the length of data (4), not the message.", []any{25, 8, 0, []byte("PK\x03\x04"), false}},
		{"bytes/empty-final", "Empty final chunk counts 0.", []any{25, 8, 0, []byte{}, true}},
		{"bytes/300", "Bytes with 300 bytes of data (0xab); the 3-byte CBOR header on data is not counted.", []any{25, 8, 0, bytes.Repeat([]byte{0xab}, 300), false}},
		{"request", "Request does not count.", []any{16, 2, 16, 1042, map[string]any{}, []any{"settings", true}}},
		{"response", "Response does not count.", []any{17, 2, nil}},
		{"headers", "Headers does not count.", []any{22, 6, map[string]any{"x-cursor": "c-1842"}}},
		{"end", "End does not count.", []any{19, 8, map[string]any{}}},
		{"error", "Error does not count.", []any{20, 6, 1, "cancelled", nil}},
		{"cancel", "Cancel does not count.", []any{23, 6, 1}},
		{"credit", "Credit does not count.", []any{24, 6, 32768}},
	}
	for _, c := range cases {
		b := enc(c.msg)
		vs = append(vs, o(
			"name", "credit/"+c.name,
			"description", c.desc,
			"spec", "7.4",
			"type", "credit_count",
			"message", tj(c.msg),
			"cbor", hx(b),
			"framed_length", len(varint(uint64(len(b))))+len(b),
			"counted_bytes", creditCount(c.msg),
		))
	}
	// Sequences on one call direction with a tiny initial credit set by the
	// caller's `credit` metadata key.
	type step struct {
		action string
		msg    []any
		grant  int
	}
	sequence := func(name, desc string, callID int, steps []step) {
		remaining := 100
		var out []any
		for _, s := range steps {
			switch s.action {
			case "send":
				n := creditCount(s.msg)
				if remaining <= 0 && n > 0 {
					panic("credit sequence: send with no credit")
				}
				remaining -= n
				out = append(out, o("action", "send", "message", tj(s.msg), "cbor", hx(enc(s.msg)), "counted_bytes", n, "remaining_after", remaining))
			case "grant":
				remaining += s.grant
				out = append(out, o("action", "receive_credit", "message", tj([]any{24, callID, s.grant}), "amount", s.grant, "remaining_after", remaining))
			case "blocked":
				out = append(out, o("action", "check", "may_send", remaining > 0, "remaining", remaining))
			case "violation":
				n := creditCount(s.msg)
				if remaining > 0 || n == 0 {
					panic("credit sequence: not a violation")
				}
				// The callee's half is the sender here, so the caller answers.
				ans := []any{23, callID, 17}
				out = append(out, o("action", "violation", "message", tj(s.msg), "cbor", hx(enc(s.msg)), "counted_bytes", n, "remaining", remaining,
					"answer", o("message", tj(ans), "cbor", hx(enc(ans)), "note", "the caller sends Cancel(protocol_error); a callee detecting a violation answers Error(protocol_error) instead")))
			}
		}
		vs = append(vs, o("name", name, "description", desc, "spec", "7.4", "type", "credit_sequence", "initial_credit", 100, "steps", out))
	}
	item := []any{18, 6, strings.Repeat("y", 54)}
	sequence("credit/sequence-small-window", "Callee's half of call 6 with initial credit 100 (set by the caller with metadata key credit (35) = 100). A sender may send while its remaining credit is above zero, even if the message is larger, and the credit then goes negative. Grants add up.",
		6, []step{{"send", item, 0}, {"send", item, 0}, {"blocked", nil, 0}, {"grant", nil, 50}, {"send", item, 0}, {"blocked", nil, 0}})
	sequence("credit/sequence-zero-byte-messages", "Callee's half of download call 8 with initial credit 100. A 150-byte chunk takes the credit to -50, so no more data may be sent, but messages that count zero bytes are never held back and are never a violation: the empty final Bytes chunk and the End that follows go out at once (7.4).",
		8, []step{{"send", []any{25, 8, 0, bytes.Repeat([]byte{0x61}, 150), false}, 0}, {"blocked", nil, 0},
			{"send", []any{25, 8, 0, []byte{}, true}, 0}, {"send", []any{19, 8, map[string]any{}}, 0}})
	sequence("credit/sequence-violation", "Callee's half of call 6 with initial credit 100. After two Items the credit is -16; a third Item sent anyway is a credit violation. The caller, as receiver, ends the call with Cancel(protocol_error) (7.4).",
		6, []step{{"send", item, 0}, {"send", item, 0}, {"blocked", nil, 0}, {"violation", item, 0}})
	return o("area", "credit", "vectors", vs)
}

// Params (section 5.4): defaults, unknown keys, minimums.
var paramDefaults = []struct {
	key string
	def int
	min int
}{
	{"maxMessageSize", 1048576, 16384},
	{"maxInlineBytes", 65536, 16384},
	{"maxConcurrentCalls", 100, 1},
	{"maxStreams", -1, 0}, // 16 in Welcome, 4 in Hello
	{"sharedCredit", 65536, 16384},
	{"leaseCredit", 1048576, 16384},
	{"idleTimeoutMs", 30000, 0},
}

// checkParams returns the effective limits, or the first key below its
// minimum. Unknown keys are ignored.
func checkParams(p map[string]any, sentIn string) (O, string) {
	eff := O{}
	for _, d := range paramDefaults {
		v := d.def
		if d.key == "maxStreams" {
			v = 16
			if sentIn == "Hello" {
				v = 4
			}
		}
		if x, ok := p[d.key]; ok {
			v = int(num(x))
			if v < d.min {
				return nil, d.key
			}
		}
		eff = append(eff, kv{d.key, v})
	}
	return eff, ""
}

func paramsVectors() []any {
	cases := []struct {
		sentIn string
		params map[string]any
		note   string
	}{
		{"Welcome", map[string]any{}, "every key missing: the defaults, maxStreams 16 in Welcome"},
		{"Hello", map[string]any{}, "every key missing: maxStreams defaults to 4 in Hello"},
		{"Hello", map[string]any{"maxStreams": 2, "x-future-limit": 7}, "an unknown key is ignored"},
		{"Welcome", map[string]any{"x-future": "text"}, "an unknown key is ignored whatever its value"},
		{"Welcome", map[string]any{"maxMessageSize": 16384, "maxInlineBytes": 16384, "maxConcurrentCalls": 1, "maxStreams": 0, "sharedCredit": 16384, "leaseCredit": 16384, "idleTimeoutMs": 1000},
			"every limit at its minimum; maxStreams and idleTimeoutMs have none"},
		{"Welcome", map[string]any{"maxMessageSize": 16383}, "maxMessageSize below 16384"},
		{"Hello", map[string]any{"maxInlineBytes": 1024}, "maxInlineBytes below 16384"},
		{"Welcome", map[string]any{"sharedCredit": 0}, "sharedCredit below 16384"},
		{"Hello", map[string]any{"leaseCredit": 16383}, "leaseCredit below 16384"},
		{"Welcome", map[string]any{"maxConcurrentCalls": 0}, "maxConcurrentCalls below 1"},
	}
	var entries []any
	for _, c := range cases {
		eff, bad := checkParams(c.params, c.sentIn)
		e := o("sent_in", c.sentIn, "params", tj(c.params), "params_cbor", hx(enc(c.params)), "note", c.note)
		if bad == "" {
			e = append(e, o("expected", "ok", "effective", eff)...)
		} else {
			e = append(e, o("expected", "goaway", "status", 3, "status_name", "invalid_argument", "key", bad)...)
		}
		entries = append(entries, e)
	}
	return []any{
		o("name", "params/validation", "description", "Params as received in Hello or Welcome: a missing key means the default, unknown keys are ignored, and maxMessageSize, maxInlineBytes, sharedCredit and leaseCredit MUST be at least 16384 and maxConcurrentCalls at least 1. A peer that receives a smaller value closes the session with GoAway(invalid_argument) (5.4).",
			"spec", "5.4", "type", "params_table", "minimums", o("maxMessageSize", 16384, "maxInlineBytes", 16384, "maxConcurrentCalls", 1, "sharedCredit", 16384, "leaseCredit", 16384), "entries", entries),
		msgVec("hello/unknown-params-key", "Hello whose params carry an unknown key 'x-future-limit' next to maxStreams 2. The server ignores the unknown key (5.4).",
			"5.4", []any{0, []any{1}, map[string]any{}, []any{"bearer", testTicket}, nil, nil, map[string]any{"maxStreams": 2, "x-future-limit": 7}, false}),
		msgVec("goaway/params-too-small", "GoAway(invalid_argument) from a client whose server sent sharedCredit 1024 in Welcome.params: below the minimum of 16384 (5.4).",
			"5.4", []any{9, 3, "sharedCredit 1024 is below 16384", nil, nil}),
	}
}
