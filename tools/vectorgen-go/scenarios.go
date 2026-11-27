package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Behaviour scenarios: scripted message sequences between a client and a
// server (test-vectors/scenarios/README.md). The generator checks that every
// message encodes as stated; the behaviour is executed by session tests.

const scenarioFormat = 1

// ---- the scenario schema: one facet, test.echo ----

const (
	tyUpload   = 64
	tyEchoNote = 65

	mEcho   = 0
	mCount  = 1
	mSum    = 2
	mUpload = 3
	mLog    = 4
	mEvents = 5
	mNote   = 6

	facetEcho = 16
)

func echoFacet(v11 bool) []any {
	types := list(structDef(tyUpload, "Upload", list(field(0, "name", tString, 0, nil), field(1, "data", tByteStream(), 0, nil)), 0, nil))
	methods := list(
		method(mEcho, "echo", tString, tString, nil, fIdempotent, ann{"doc": "Returns its input."}),
		method(mCount, "count", tUint, tStream(tUint), nil, fOutputEnd, ann{"doc": "Streams the items 1, 2, ..., n, then End."}),
		method(mSum, "sum", tStream(tUint), tUint, nil, fInputEnd, ann{"doc": "Returns the sum of the items. Fails at once with out_of_range on an item above 1000."}),
		method(mUpload, "upload", tyUpload, tUint, nil, fInputEnd, ann{"doc": "Returns the number of bytes received for the data token."}),
		method(mLog, "log", tString, tUnit, nil, fNotification, ann{"doc": "Notification: records the text."}),
		method(mEvents, "events", tUnit, tStream(tDynamic), nil, fShared|fOutputEnd, ann{"doc": "Subscription: streams dynamic values until cancelled or drained."}),
	)
	version := "1.0.0"
	if v11 {
		version = "1.1.0"
		types = append(types, structDef(tyEchoNote, "Note", list(field(0, "title", tString, 0, nil)), 0, nil))
		methods = append(methods, method(mNote, "note", tString, tyEchoNote, nil, 0, ann{"doc": "Returns a Note with the given title."}))
	}
	return facetDoc(facetEcho, "test.echo", version, types, list(service(0, "Echo", methods, nil)), nil, nil, nil, nil)
}

func scenarioSchema() []any { return schemaDoc("test.host", "1.0.0", list(echoFacet(false)), nil) }
func scenarioDelta() []any  { return []any{[]any{0, echoFacet(true)}} }

// scenarioSchemaVectors are added to schema.json so that scenarios can
// refer to them by name.
func scenarioSchemaVectors(add func(O), schemaVec func(name, desc string, input []any)) {
	schemaVec("schema/scenario-host", "The schema of the server in every behaviour scenario (test-vectors/scenarios): facet 16 test.echo with methods echo (unary), count (server stream), sum (client stream), upload (byte upload by reference), log (notification) and events (shared subscription of dynamic values). The annotations document each method's behaviour.", scenarioSchema())
	st := newState(scenarioSchema())
	res, e := st.apply(scenarioDelta())
	if e != nil {
		panic(e)
	}
	h := schemaHash(res.doc)
	upd := []any{3, 1, h, scenarioDelta()}
	ub := enc(upd)
	add(o("name", "schema/scenario-delta-1", "description", "Epoch 1 of the scenario schema: test.echo 1.1.0 adds type 65 Note and method 6 note. Used by scenario schema-update-ack-gating.",
		"spec", "6.6", "type", "delta", "from", "schema/scenario-host", "from_hash", hx(schemaHash(st.doc)), "epoch", 1, "delta", tj(scenarioDelta()),
		"expected_valid", true, "removed_facet_ids_after", res.removedIDs(), "canonical_cbor", hx(enc(res.doc)), "facet_hashes", facetHashes(res.doc), "hash", hx(h),
		"schema_update", o("message", tj(upd), "diag", diag(ub), "cbor", hx(ub))))
}

// ---- scenario builder ----

type scenario struct {
	name, desc, spec string
	given            O
	steps            []any
	opened           map[string]bool
	credit           map[string]int64 // "callID/from" -> remaining
}

func newScenario(name, desc, spec string, given O) *scenario {
	sc := &scenario{name: name, desc: desc, spec: spec, given: given, opened: map[string]bool{}, credit: map[string]int64{}}
	for _, e := range given {
		if e.k == "session" && strings.HasPrefix(e.v.(string), "established") {
			sc.opened["shared"] = true // the shared lane is already open
		}
	}
	return sc
}

// msg adds a message step. Extra key/value pairs are appended to the step.
func (s *scenario) msg(from, stream string, m []any, extra ...any) {
	b := enc(m)
	k := int(num(m[0]))
	st := o("step", len(s.steps)+1, "from", from, "stream", stream)
	if from == "client" && !s.opened[stream] {
		hdr := "01"
		if stream == "shared" {
			hdr = "00"
		}
		st = append(st, kv{"opens_stream", true}, kv{"header", hdr})
		s.opened[stream] = true
	}
	st = append(st, kv{"kind_name", kindNames[k]}, kv{"message", tj(m)}, kv{"diag", diag(b)}, kv{"cbor", hx(b)})
	st = append(st, o(extra...)...)
	s.steps = append(s.steps, st)
}

// counted adds a message step for a call direction with credit accounting.
func (s *scenario) counted(from, stream string, m []any, extra ...any) {
	call := num(m[1])
	key := fmt.Sprintf("%d/%s", call, from)
	rem, ok := s.credit[key]
	if !ok {
		panic(s.name + ": no initial credit for " + key)
	}
	n := int64(creditCount(m))
	if rem <= 0 && n > 0 {
		panic(s.name + ": send with no credit")
	}
	rem -= n
	s.credit[key] = rem
	s.msg(from, stream, m, append([]any{"counted_bytes", n, "credit_after", rem}, extra...)...)
}

func (s *scenario) grant(from, stream string, m []any) {
	call := num(m[1])
	to := "server"
	if from == "server" {
		to = "client"
	}
	key := fmt.Sprintf("%d/%s", call, to)
	s.credit[key] += num(m[2])
	s.msg(from, stream, m, "credit_after", s.credit[key])
}

func (s *scenario) expect(outcome string, kvs ...any) {
	s.steps = append(s.steps, append(o("step", len(s.steps)+1, "expect", outcome), o(kvs...)...))
}

func (s *scenario) doc() O {
	return o("format", scenarioFormat, "spec_revision", specRevision, "generator", "tools/vectorgen-go",
		"name", s.name, "description", s.desc, "spec", s.spec, "given", s.given, "steps", s.steps)
}

// ---- the scenarios ----

func scenarios() []*scenario {
	r := schemas()
	_ = r
	base := canonicalSchema(scenarioSchema())
	h := schemaHash(base)
	st := newState(scenarioSchema())
	st1, _ := st.apply(scenarioDelta())
	h1 := schemaHash(st1.doc)
	stale := schemas().baseHash // a hash the scenario server does not serve
	auth := []any{"bearer", testTicket}
	none := map[string]any{}
	req := func(call int, m int, md any, in any) []any { return []any{16, call, facetEcho, m, md, in} }
	after := func(extra ...any) O {
		return append(o("schema", "schema/scenario-host", "session", "established as in scenario handshake-normal (steps 1-3), with no call open"), o(extra...)...)
	}
	var out []*scenario

	s := newScenario("handshake-normal", "A normal session start: Hello, then Welcome with the full schema inline, then Ready. The client then makes one unary call on a new leased stream.", "4.1, 5.2, 5.4, 7.3",
		o("schema", "schema/scenario-host", "session", "none: the client has just opened the transport", "client_cache", nil))
	s.msg("client", "shared", []any{0, []any{1}, none, auth, nil, nil, none, false})
	s.msg("server", "shared", []any{1, 1, none, testSessionID, none, []any{2, h, base}, none})
	s.msg("client", "shared", []any{2, h})
	s.expect("session_ready", "note", "the server dispatches calls only after Ready (5.2)")
	s.msg("client", "lease:1", req(2, mEcho, none, "hello"))
	s.msg("server", "lease:1", []any{17, 2, "hello"})
	s.expect("call_ended", "call_id", 2)
	s.expect("stream_idle", "stream", "lease:1")
	out = append(out, s)

	s = newScenario("handshake-optimistic-match", "Optimistic start (5.3) with a cached schema the server still serves: Hello, Ready and a call to an idempotent method go out in one flight on the shared lane, before Welcome. The server's schema matches, so it dispatches the call after Ready.", "5.2, 5.3",
		o("schema", "schema/scenario-host", "session", "none", "client_cache", o("schema_hash", hx(h), "params", "defaults")))
	s.msg("client", "shared", []any{0, []any{1}, none, auth, h, nil, none, true})
	s.msg("client", "shared", []any{2, h})
	s.msg("client", "shared", req(2, mEcho, none, "early"), "note", "sent before Welcome arrives: shared lane only, within 64 KiB after Hello, default params")
	s.msg("server", "shared", []any{1, 1, none, testSessionID, none, []any{0, h}, none})
	s.expect("dispatched", "call_id", 2)
	s.msg("server", "shared", []any{17, 2, "early"})
	s.expect("call_ended", "call_id", 2)
	out = append(out, s)

	s = newScenario("handshake-optimistic-mismatch", "Optimistic start with a stale cached schema hash. The server MUST NOT dispatch any call of the session: it sends Welcome with its current schema so the client can update its cache, then GoAway(schema_mismatch) with retry_after_ms 0, and closes. The client reconnects and resends its calls; none of them ran (5.3).", "5.3, 5.6",
		o("schema", "schema/scenario-host", "session", "none", "client_cache", o("schema_hash", hx(stale), "note", "the hash of schema/server-base, which this server does not serve")))
	s.msg("client", "shared", []any{0, []any{1}, none, auth, stale, nil, none, true})
	s.msg("client", "shared", []any{2, stale})
	s.msg("client", "shared", req(2, mEcho, none, "early"))
	s.msg("server", "shared", []any{1, 1, none, testSessionID, none, []any{2, h, base}, none})
	s.msg("server", "shared", []any{9, 18, "schema changed", 0, nil}, "compare", "status")
	s.expect("not_dispatched", "call_id", 2)
	s.expect("session_closed", "by", "server")
	s.expect("client_retries", "call_id", 2, "note", "on a new session, not optimistically against the cached hash it just learned was stale: the client may start optimistically with the new hash from this Welcome")
	out = append(out, s)

	s = newScenario("unary-lease-reuse", "Two unary calls one after the other on the same leased stream. The first Request opens the stream (header 0x01); when the call ends the stream is idle and the next call reuses it without a header and without opening another stream (4.2).", "4.1, 4.2, 7.1, 7.3",
		after())
	s.msg("client", "lease:1", req(2, mEcho, none, "first"))
	s.msg("server", "lease:1", []any{17, 2, "first"})
	s.expect("call_ended", "call_id", 2)
	s.expect("stream_idle", "stream", "lease:1")
	s.msg("client", "lease:1", req(4, mEcho, none, "second"), "note", "reuses the idle stream: no header")
	s.msg("server", "lease:1", []any{17, 4, "second"})
	s.expect("call_ended", "call_id", 4)
	s.expect("stream_idle", "stream", "lease:1")
	s.expect("streams_open", "by", "client", "count", 1)
	out = append(out, s)

	s = newScenario("server-stream-credit", "A server stream with initial credit 10 for the callee's half, set by the caller with metadata key credit (35). Each Item [18, 2, n] counts 4 bytes. The server sends while its credit is above zero, so the third Item takes it to -2 and the server holds the rest back until the client grants 8 more. End counts zero bytes and is never held back (7.4).", "7.2, 7.3, 7.4",
		after("initial_credit", o("2/server", 10, "2/client", 1048576)))
	s.credit["2/server"], s.credit["2/client"] = 10, 1048576
	s.msg("client", "lease:1", req(2, mCount, map[any]any{35: 10}, 5))
	for i := 1; i <= 3; i++ {
		s.counted("server", "lease:1", []any{18, 2, i})
	}
	s.expect("held_back", "by", "server", "call_id", 2, "reason", "credit", "note", "remaining credit -2: no Item until a Credit arrives")
	s.grant("client", "lease:1", []any{24, 2, 8})
	s.counted("server", "lease:1", []any{18, 2, 4})
	s.counted("server", "lease:1", []any{18, 2, 5})
	s.counted("server", "lease:1", []any{19, 2, none}, "note", "End counts zero bytes, so it goes out with negative credit")
	s.expect("call_ended", "call_id", 2)
	s.expect("stream_idle", "stream", "lease:1")
	out = append(out, s)

	s = newScenario("client-stream-cancel", "The client cancels a client-stream call. Cancel finishes the caller's half; the callee answers with its final message, normally Error(cancelled); the call ends and the leased stream is idle again in a clean state, so the next call reuses it (7.1, 7.5).", "7.1, 7.3, 7.5, 4.2",
		after())
	s.msg("client", "lease:1", req(2, mSum, none, nil))
	s.msg("client", "lease:1", []any{18, 2, 1})
	s.msg("client", "lease:1", []any{18, 2, 2})
	s.msg("client", "lease:1", []any{23, 2, 1})
	s.expect("half_finished", "call_id", 2, "half", "caller")
	s.msg("server", "lease:1", []any{20, 2, 1, "cancelled", nil}, "compare", "status")
	s.expect("call_ended", "call_id", 2)
	s.expect("stream_idle", "stream", "lease:1")
	s.msg("client", "lease:1", req(4, mEcho, none, "after cancel"))
	s.msg("server", "lease:1", []any{17, 4, "after cancel"})
	s.expect("call_ended", "call_id", 4)
	out = append(out, s)

	s = newScenario("upload-referenced-token", "An upload whose input struct carries byte token 1 in its [4] field (7.8). The caller sends the Request, the data for token 1 in two chunks (the last with fin), then End, because the method has flag 0x8. The callee answers with the number of bytes received.", "7.3, 7.8, 7.4",
		after("initial_credit", o("2/client", 1048576, "2/server", 1048576)))
	s.credit["2/client"] = 1048576
	s.msg("client", "lease:1", req(2, mUpload, none, []any{"photo.jpg", 1}))
	s.counted("client", "lease:1", []any{25, 2, 1, unhex("ffd8ff"), false})
	s.counted("client", "lease:1", []any{25, 2, 1, unhex("e000"), true})
	s.msg("client", "lease:1", []any{19, 2, none})
	s.expect("half_finished", "call_id", 2, "half", "caller")
	s.msg("server", "lease:1", []any{17, 2, 5})
	s.expect("call_ended", "call_id", 2)
	s.expect("stream_idle", "stream", "lease:1")
	out = append(out, s)

	s = newScenario("callee-error-while-streaming", "The callee fails a client-stream call while input is still arriving. It MUST keep reading and discarding the caller's input until the caller's half is finished. An Item already on its way when the Error was sent is discarded; when the Error arrives the caller sends End next, with no further Item or Bytes (7.1).", "7.1, 7.3",
		after())
	s.msg("client", "lease:1", req(2, mSum, none, nil))
	s.msg("client", "lease:1", []any{18, 2, 5})
	s.msg("client", "lease:1", []any{18, 2, 5000})
	s.msg("server", "lease:1", []any{20, 2, 11, "item 5000 exceeds 1000", nil}, "compare", "status")
	s.expect("half_finished", "call_id", 2, "half", "callee")
	s.msg("client", "lease:1", []any{18, 2, 7}, "crossed", true, "note", "sent before the Error reached the client")
	s.expect("discarded", "by", "server", "call_id", 2)
	s.msg("client", "lease:1", []any{19, 2, none}, "note", "the caller's next message after receiving the Error")
	s.expect("call_ended", "call_id", 2)
	s.expect("stream_idle", "stream", "lease:1")
	out = append(out, s)

	big := bytes.Repeat([]byte{0x61}, 16384)
	s = newScenario("credit-violation", "The server set sharedCredit and leaseCredit to the minimum, 16384. The client's first Bytes chunk uses all of it (remaining 0); sending another chunk with data is a credit violation. The callee answers Error(protocol_error), which finishes its half, and the caller sends End next (7.1, 7.4).", "7.4, 7.1, 5.4",
		after("server_params", o("sharedCredit", 16384, "leaseCredit", 16384), "initial_credit", o("2/client", 16384, "2/server", 1048576)))
	s.credit["2/client"] = 16384
	s.msg("client", "lease:1", req(2, mUpload, none, []any{"big.bin", 1}))
	s.counted("client", "lease:1", []any{25, 2, 1, big, false})
	s.msg("client", "lease:1", []any{25, 2, 1, []byte("x"), true}, "counted_bytes", 1, "credit_before", 0, "violation", true)
	s.expect("violation", "by", "client", "call_id", 2)
	s.msg("server", "lease:1", []any{20, 2, 17, "credit exceeded", nil}, "compare", "status")
	s.msg("client", "lease:1", []any{19, 2, none})
	s.expect("call_ended", "call_id", 2)
	s.expect("stream_idle", "stream", "lease:1")
	out = append(out, s)

	s = newScenario("schema-update-ack-gating", "The server's schema changes while a subscription runs. After sending SchemaUpdate for epoch 1 it MUST NOT send any message that uses an ID added in epoch 1, here an Item carrying a dynamic value of the new type 65, until it has received SchemaAck(1). The client acks as soon as it has applied the delta and checked the hash, and may then call the new method (6.6 rule 1).", "5.5, 6.6",
		after("delta", "schema/scenario-delta-1"))
	s.msg("client", "shared", req(2, mEvents, none, nil), "note", "events is flagged shared, so the subscription runs on the shared lane")
	s.msg("server", "shared", []any{18, 2, []any{tString, "boot"}})
	s.msg("server", "shared", []any{3, 1, h1, scenarioDelta()})
	s.expect("held_back", "by", "server", "call_id", 2, "reason", "schema_ack", "epoch", 1, "note", "the Item below uses type 65, added in epoch 1; the server queues it until SchemaAck(1), and closes the session with GoAway(schema_mismatch) if the ack has not arrived within 10 s")
	s.msg("client", "shared", []any{4, 1})
	s.msg("server", "shared", []any{18, 2, []any{tyEchoNote, []any{"first note"}}})
	s.msg("client", "lease:1", req(4, mNote, none, "second note"))
	s.msg("server", "lease:1", []any{17, 4, []any{"second note"}})
	s.expect("call_ended", "call_id", 4)
	out = append(out, s)

	s = newScenario("goaway-drain", "A graceful drain. The server sends GoAway(going_away) with retry_after_ms; neither peer opens new calls. A Request that crosses the GoAway is answered with Error(going_away). Running calls continue until they finish (or a grace period, RECOMMENDED 30 s, ends), then the transport is closed (5.6).", "5.6",
		after())
	s.msg("client", "shared", req(2, mEvents, none, nil))
	s.msg("server", "shared", []any{18, 2, []any{tString, "tick"}})
	s.msg("server", "shared", []any{9, 21, "draining for deploy", 15000, nil}, "compare", "status")
	s.msg("client", "lease:1", req(4, mEcho, none, "late"), "crossed", true, "note", "sent before the GoAway reached the client")
	s.msg("server", "lease:1", []any{20, 4, 21, "going away", nil}, "compare", "status")
	s.expect("not_dispatched", "call_id", 4)
	s.expect("call_ended", "call_id", 4)
	s.msg("server", "shared", []any{18, 2, []any{tString, "tock"}}, "note", "the running call continues")
	s.msg("server", "shared", []any{19, 2, none})
	s.expect("call_ended", "call_id", 2)
	s.expect("transport_closed", "by", "server", "note", "once no call is open, or when the grace period ends")
	out = append(out, s)

	s = newScenario("notification-shared-lane", "A notification: a Request with call ID 0 on the shared lane to a method flagged 0x2. The callee sends nothing back, and the notification does not count toward maxConcurrentCalls (7.1, 7.3, 7.6).", "4.3, 7.1, 7.3",
		after())
	s.msg("client", "shared", req(0, mLog, none, "hello from the client"))
	s.expect("no_reply", "call_id", 0)
	s.msg("client", "lease:1", req(2, mEcho, none, "ping"))
	s.msg("server", "lease:1", []any{17, 2, "ping"})
	s.expect("call_ended", "call_id", 2)
	out = append(out, s)

	s = newScenario("notification-unknown-dropped", "Notifications naming a facet or a method the callee does not have are dropped: no Error is sent (there is no call to answer), and the session goes on (7.1).", "7.1, 7.3",
		after())
	s.msg("client", "shared", []any{16, 0, 40, 0, none, "x"}, "note", "facet 40 does not exist")
	s.expect("no_reply", "call_id", 0)
	s.msg("client", "shared", []any{16, 0, facetEcho, 99, none, "x"}, "note", "facet 16 has no method 99")
	s.expect("no_reply", "call_id", 0)
	s.msg("client", "lease:1", req(2, mEcho, none, "still here"))
	s.msg("server", "lease:1", []any{17, 2, "still here"})
	s.expect("call_ended", "call_id", 2)
	out = append(out, s)

	s = newScenario("unknown-facet-or-method", "A Request naming a facet or a method the callee does not have is answered with Error(unimplemented); the call ends and the stream is idle (7.1).", "7.1, 8",
		after())
	s.msg("client", "lease:1", []any{16, 2, 40, 0, none, nil}, "note", "facet 40 does not exist")
	s.msg("server", "lease:1", []any{20, 2, 12, "unknown facet 40", nil}, "compare", "status")
	s.expect("call_ended", "call_id", 2)
	s.msg("client", "lease:1", []any{16, 4, facetEcho, 99, none, nil}, "note", "facet 16 has no method 99")
	s.msg("server", "lease:1", []any{20, 4, 12, "unknown method 99", nil}, "compare", "status")
	s.expect("call_ended", "call_id", 4)
	s.expect("stream_idle", "stream", "lease:1")
	out = append(out, s)
	return out
}

func writeScenarios(dir string) {
	sd := filepath.Join(dir, "scenarios")
	must(os.MkdirAll(sd, 0o755))
	list := scenarios()
	for _, s := range list {
		writeJSON(filepath.Join(sd, s.name+".json"), s.doc())
	}
	fmt.Printf("%-16s %3d scenarios\n", "scenarios/", len(list))
}
