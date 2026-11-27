# Sessions, transports and nodes (phase 2)

This phase adds the session layer of the core spec (sections 4, 5, 7 and 8) on top of the phase-1
packages, the three transport bindings, and a library for writing nodes. A hub (phase 3) builds on
the raw API described below.

| Package | Purpose |
| --- | --- |
| `transport` | The `Conn` / `Stream` abstraction (4.1, 4.4): whole messages per stream, stream headers, read limit, resets with core status codes, close with code and reason. |
| `transport/webtransport` | WebTransport over HTTP/3 (4.5) on quic-go and webtransport-go: shared lane (header `0x00`), leased streams (`0x01`) in both directions, header rules, resets and session close carrying core codes, a server you mount on an `http3.Server`, a dialer with `serverCertificateHashes`-style pinning, `SelfSigned` certificates. |
| `transport/websocket` | WebSocket (4.6) on coder/websocket: subprotocol `sparrow.v1`, one binary message per Sparrow message, Origin check hook, close codes 1000 / 4000+code with the reason cut to 123 bytes. |
| `transport/mem` | In-memory binding with leased streams, for tests. |
| `session` | One session in either role: handshake, control messages, schemas, calls, credit, leases. |
| `node` | Facet builder, node runtime (dial, serve, reconnect, `Shutdown`), calls by name, runtime publishing. |
| `examples/echo-node` | An example node that dials in to a hub (`-hub URL -credential ...`) or waits to be dialed (`-listen ADDR`, printing its URL and SPKI pin). |

## Session API

```go
cli, err := session.NewClient(ctx, conn, session.Config{Auth: ..., KnownSchema: cached, Optimistic: true})
srv, err := session.NewServer(ctx, conn, session.Config{Schema: mySchema, Handler: mux, Authenticate: ...})
```

`NewServer` returns once `Ready` has arrived; `NewClient` returns once `Ready` is sent (immediately for
an optimistic start, whose `Welcome` is handled in the background; see `Welcomed()`).
`Config` holds this peer's schema, the params it imposes, the handler, and hooks: `Authenticate`,
`AcceptClientSchema`, `SchemaByHash` (for `Delta` offers), `OfferLocation` (out-of-band offers),
`FetchSchema` and `OnServerSchema` on the client, `OnPeerSchemaUpdate` (runs before `SchemaAck`),
`OnAuthRefresh` / `OnAuthStatus`, `OnGoAway`, plus every timeout and a `Clock`: `HelloTimeout`,
`SchemaAckTimeout`, `CancelGiveUp`, `CancelBroken`, `GracePeriod`, `LeaseIdle`, `Linger`, `ResetWait`
and `GoAwayWait` (how long a GoAway being written may take before the transport closes anyway).

### Typed level

Serving: register `HandlerFunc`s on a `Mux` per (facet, method). A handler gets a `context` (cancelled
on `Cancel`, the deadline, the end of the call or the session) and a `*ServerCall`:
`Input()`, `Recv()` (input stream), `Reader(token)` (input bytes), `Send()` (output stream),
`Writer(token)` (output bytes), `SendHeaders()`, `Progress()`, `Respond()`, `End()`, `Fail()`,
`Metadata()`, `Principal()`, `CallContext()`, `Deadline()`. The returned value finishes the call:
an error becomes `Error` (an `*session.Error` keeps its code, message and details), a stream or byte
output gets `End`, anything else `Response` (then `End` for a 0x10 method with byte tokens). A typed
handler's `Cancel` and deadline are answered by the session at once.

Calling: `Call(ctx, facet, method, input, opts)` returns a `*ClientCall` with `Send`, `CloseSend`,
`Recv`, `Response`, `Headers`, `Trailers`, `Wait`, `Reader(token)`, `Writer(token)`, `Cancel`;
`Unary` and `Notify` are shortcuts. The context's deadline becomes the `deadline` key, and the end of
the context sends `Cancel(cancelled | deadline_exceeded)`. `CallOptions` choose the lane
(`LaneAuto`, `LaneShared`, `LaneLeased`), the `credit` key, and metadata.

### Raw level (for a hub)

- `ServerCall.Request()` / `RequestRaw()` give the `Request` as received (facet, method, metadata,
  input as raw CBOR). `RecvRaw()` returns every later caller message (`Item`, `Bytes`, `End`,
  `Cancel`) as `*Msg{Kind, Raw, Message}`, exactly as received, and `io.EOF` once the caller's half is
  finished and no `Cancel` can follow. `SendRaw()` sends any encoded callee message.
- `Session.OpenRaw(ctx, RawRequest{FacetID, MethodID, Metadata, Input}, opts)` starts a call whose
  input is copied byte for byte; its `RecvRaw()` returns `Headers`, `Response`, `Item`, `Progress`,
  `Bytes`, `End`, `Error`; `SendRaw()` sends caller messages. `ForwardRequest(in, facet, md)` builds the
  forwarded request.
- `SendRaw` rewrites the call ID with `wire.RewriteCallID` and keeps every other byte. `Credit` is
  never relayed (dropped by `SendRaw`): each hop has its own credit. A `Bytes` message too large for
  the next hop is split (token data and the final `fin` unchanged); any other oversized message
  fails with `message_too_large`.
- Per-hop credit: with `CallOptions.ManualCredit` / `ServerCall.SetManualCredit`, a message taken with
  `RecvRaw` returns no credit until `Release(m)`, so a relay grants upstream only as it forwards
  downstream. `Relay(ctx, in, out)` runs both directions this way until both calls end, ending the
  other call with `unavailable` (or `message_too_large`, `cancelled`) when one side fails.
  `ServerCall.CallerCredit()` gives the upper bound for the forwarded `credit` key.
- Notifications reach a raw handler as a `ServerCall` with ID 0; forward them with `NotifyRaw`.
- Schemas: `LocalSchema()` / `PeerSchema()` (`*schema.State`, with epochs), `PeerFacet(name)`,
  `UpdateSchema(newSchema, SchemaUpdateOptions{AckTimeout})` returning a `PendingUpdate` whose `Wait`
  returns at the ack; `Unacked(timeout)` returns the latest update still unacknowledged and gives the
  peer at most timeout to ack it (a relaying hub joins an update already on its way). `Config.OnPeerSchemaUpdate` lets a hub relay a node's update and ack it only after
  its downstream sessions have (10.3). `MaxClientSchemaSize: -1` lifts the 64 KiB client-schema limit
  between a hub and its nodes (10.2).
- Session facts: `Principal()`, `Hello()`, `Welcome()`, `SessionID()`, `PeerLimits()`,
  `LocalLimits()`, `GoAwayReceived()`, `Stats()`, `GoAway()`, `Close()`, `Done()`, `Err()`.

`relay_test.go` relays every call shape between two sessions over different bindings and checks,
from captured frames, that every message of the call is identical on both hops except the call ID
(and the `Request` metadata the hub changes), that `Credit` is not relayed and that the hub holds at
most its credit plus one message.

## Design choices

- **One reader per stream, always reading** (4.4). Messages are queued per call; a counted message
  waits only on the sending side. The receiver detects credit violations with the same
  `wire.CreditWindow` arithmetic and grants credit back once half of its window has been consumed by
  the application (or `Release`d). Received data per call direction stays within the granted credit
  plus one message (`ClientCall.MaxBuffered`, checked by the tests).
- **Writes** are serialized per stream with a mutex; each call's messages are ordered by a per-call
  send lock. Fairness on the shared lane relies on the mutex (Go's starvation mode) and on chunking
  bytes to 16 KiB there.
- **Halves** follow the method flags captured at the start of the call. For a `Request` naming a
  method the callee does not have, the callee uses the flags of the method if this side ever
  published it in the session (flags 0x2/0x8/0x10 never change), else none; a later `End` is
  ignored as a message for an ended call. When the callee finishes first, it forgets the call (7.1):
  later input is ignored and earns no credit, and a leased stream keeps one flag until the caller's
  `End` or `Cancel` arrives (a `Request` before it is a protocol error); as caller the session sends
  `End` on the application's behalf.
- **Cancel** may arrive after the caller's half is finished (a unary call). After 5 s without a final
  message the caller resets a leased stream, or keeps the shared-lane call counted and closes the
  session with `GoAway(protocol_error)` at 30 s.
- **Leases**: a pool per side of the streams it opened; a stream counts until both directions are
  finished or reset. Calls go to an idle or new leased stream unless the method is flagged `shared`;
  when the pool is full they fall back to the shared lane (`Config.WaitForLease` waits instead).
  Streams idle for 30 s are finished, keeping two. A stream this side reset (only its sending
  direction, where the binding allows) stays counted until
  the peer has ended its own direction too (it does so as soon as it sees the reset), up to
  `ResetWait` (5 s), so a replacement never reaches a peer that still counts the old stream (4.2 rule 5).
  An acceptor stops counting a stream before it sends its end, and a callee stops counting a call
  toward `maxConcurrentCalls` before its final message goes out, even while the caller's half is
  still open, so the peer's next stream or call, started the moment it sees that end, is never
  refused (7.6). A caller counts a call until it has both sent its own last message and seen the
  callee's final one (a cancelled call stays counted until the callee answers), and a call on a
  stream it reset as long as it counts the stream (7.5). `CallOptions.NoWait` refuses a call with
  `resource_exhausted` instead of waiting for a slot.
- **Schema gating** (6.6 rule 1): after `UpdateSchema`, every later callee message of a call to a facet
  the delta adds or replaces waits for `SchemaAck`; calls to other facets are not held. Core `Error`s
  without details never wait.
- **Handshake**: the server reads and buffers at most 64 KiB after `Hello` while `Authenticate` runs,
  then replays the buffered messages in order. Calls on the shared lane before `Ready` get
  `Error(not_ready)`; calls on leased streams wait for `Ready`. An optimistic client sends only on the
  shared lane and at most 64 KiB before `Welcome`; on a mismatch (or limits below the defaults) its
  calls fail with `NotDispatched` set.
- **Shutdown**: `GoAway` drains; the session closes once no call is open, or after the grace period.
  On close the WebTransport binding finishes the shared lane and waits (up to 2 s) for the peer to
  finish its own before closing the session, so messages written just before are not cut off; a
  peer that sees the shared lane end gives its open calls up to 1 s to finish.
- **Idle**: a Ping goes out when nothing has been received for half of the smaller
  `idleTimeoutMs`; after the full timeout the session closes with `GoAway(unavailable)`.

## Not implemented here

- `maxInlineBytes` is not enforced on typed values (a SHOULD for senders).
- Credit windows are fixed at the initial credit; they do not grow toward the bandwidth-delay product.
- The client's optimistic-start bookkeeping across sessions (stop after two rejections) and
  transport memory per origin are left to the application; `node.DialOptions` does the WebTransport
  then WebSocket fallback, `node.RunDial` the reconnect backoff.
- Datagrams and profile stream headers (`0x40`-`0x7F`, treated as `protocol_error`).
- webtransport-go's dialer closes the QUIC connection right after a client-side session close, which
  can overtake the close capsule: the server may then see a plain connection close (`unavailable`).
  `GoAway` carries the status in every case.

## Testing

```sh
go vet ./session/... ./transport/... ./node/... ./examples/...
go test -race ./session/... ./transport/... ./node/...
go test -race -count=3 ./session/                     # flakiness check
go test ./session -run '^$' -fuzz FuzzServerMessages -fuzztime 60s -fuzzminimizetime 3s
```

The session tests run real sessions over the mem, WebSocket (`httptest`) and
WebTransport (QUIC on localhost, self-signed certificate) bindings, a fake clock for the timers, raw
scripted peers for protocol violations (timeouts are checked by advancing the fake clock, never by
sleeping), and every behaviour scenario in `../../test-vectors/scenarios`
(`TestScenarios`; set `SPARROW_VECTORS` to use another vector directory).
