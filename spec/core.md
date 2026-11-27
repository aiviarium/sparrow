# Sparrow — Core Protocol Specification (Draft)

Nov 26, 2026 · Christoph Feuerer

> Snapshot of the draft specification. The live document is the source of truth; diagrams are not included here.

## 1. Overview

Sparrow is a binary, bidirectional, streaming RPC protocol. At session start the server sends a schema describing its services and types. After that, every message refers to methods, types and enum values by compact numeric IDs, and a client that understands the schema can call services it was never compiled against.

### 1.1 Goals

- **Self-describing:** a fixed client can discover and call any service the host exposes, including services plugins add while the session is open.
- **Compact and fast:** CBOR encoding, positional structs, numeric IDs instead of repeated strings; raw byte streams with no re-encoding.
- **Streaming in both directions:** unary, server-stream, client-stream and bidi-stream calls, plus raw binary streams, initiated by either peer.
- **Browser-first, Go-canonical:** the reference server is Go; the primary client is a browser over WebTransport.
- **Neutral core:** the core spec says nothing about authentication methods, HTTP endpoints or UI. Those belong to profiles.

### 1.2 Non-goals

- Defining an IDL or source-code generators. Schemas are runtime data; generators are optional tooling.
- Encrypting payloads. Confidentiality comes from TLS (QUIC or WSS).
- Replacing HTTP for cacheable static assets. Profiles should use plain HTTP for those.

### 1.3 Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as described in RFC 2119 and RFC 8174. Message layouts are written in CDDL (RFC 8610). All integers on the wire are CBOR integers unless stated otherwise.

### 1.4 Terminology

| Term | Meaning |
| --- | --- |
| Peer | Either endpoint. The **server** accepts connections; the **client** opens them. |
| Session | One authenticated connection, from `Hello` to close. Schema IDs are scoped to a session. |
| Schema | The document describing a peer's types, services, methods and sigils. |
| Schema hash | 0x01 followed by the SHA-256 of a schema's canonical form (section 6.6); identifies a schema across sessions. |
| Epoch | A counter that goes up by one each time the schema changes within a session. |
| TypeId | Numeric ID of a type within a facet. |
| MethodId | Numeric ID of a method within a facet. A facet is a self-contained unit of a schema, usually one plugin (section 6). |
| Sigil | Numeric ID of a named constant: an enum value, error code or well-known string. |
| Call | One RPC invocation and all its messages. Identified by a call ID; runs on the shared lane or on a leased stream. |
| Shared lane | The one stream every session has, carrying the handshake, session messages and small multiplexed calls. Other calls lease a stream from a pool (section 4). |
| Profile | A companion spec that binds the core to a concrete environment (the Sparrow Web Profile, section 9, and the Sparrow Hub Profile, section 10). |

## 2. Architecture

The protocol has four core layers on top of two interchangeable transport bindings. Profiles add environment-specific pieces on top without changing the core.

> *Diagram (not included in this snapshot): protocol layers, 1 profile, 4 core layers, 2 transport bindings.*

The dashed box is replaceable: a server-to-server deployment could use an mTLS profile instead, and every layer below it stays the same.

## 3. Encoding

Every message is a single CBOR data item (RFC 8949) in preferred serialization. Schemas and anything hashed or signed also use Core Deterministic Encoding, so Go and JavaScript produce identical bytes. The only non-CBOR bytes on the wire are length prefixes and the one-byte stream header (section 4.1).

### 3.1 Allowed CBOR

| CBOR feature | Rule |
| --- | --- |
| Integers | MUST use the shortest form. Every integer a message defines itself (IDs, counts, lengths, credit, durations, timestamps) MUST lie within ±(2^53 − 1), so JavaScript holds it exactly; a larger one is a `protocol_error`. Application values of type `int` or `uint` (section 6.3) keep their full 64-bit range. |
| Floats | SHOULD use the shortest width that keeps the value exact (RFC 8949, section 4.1). Decoders MUST accept any float width, and MUST accept an integer where a float type is declared, because JavaScript cannot tell 3 from 3.0. |
| Byte strings, text strings | MUST be definite length. Text MUST be valid UTF-8. |
| Arrays, maps | MUST be definite length. Map keys MUST be unique. |
| Tags | Only the tags in section 3.5. An unknown tag is a decode error. |
| Simple values | `false`, `true`, `null` only. `undefined` MUST NOT appear. |
| Nesting | Decoders MUST reject a message nested deeper than 64 levels, counting arrays, maps and tags, with the message's own array as level 1; a scalar adds no level. Receivers accept any other valid encoding of an ordinary message, shortest or not; canonical data is checked by recomputing its hash. |

### 3.2 Canonical encoding

Schema documents (section 6.6), signed module data (section 9.5) and any other value that is hashed or signed MUST use Core Deterministic Encoding (RFC 8949, section 4.2.1): the rules above plus map keys sorted by the bytewise order of their encoded form. Canonical data MUST NOT contain floats, because JavaScript encoders cannot tell 1.0 from 1; timestamps in it are integer seconds. Both sides therefore need a canonical encoder. Ordinary messages need not sort map keys, since structs are arrays and maps are rare.

### 3.3 Envelope

Each message is a CBOR array whose first element is the message kind:

```
message = [kind: uint, * field]
```

| Kinds | Owner | Unknown kind received |
| --- | --- | --- |
| 0–47 | Core spec | Close the session with `protocol_error` |
| 48–63 | Core spec | Ignore the message |
| 64–111 | Profiles | Close the session with `protocol_error` |
| 112–127 | Profiles | Ignore the message |
| 128 and above | Invalid | Close the session with `protocol_error` |

### 3.4 Values described by a schema

Payloads are encoded according to their schema type (section 6.3), with exactly one encoding per value:

- **Struct:** a CBOR array where element i holds the field with tag i. Tags start at 0 and SHOULD be dense. A removed field or an absent optional field is encoded as `null`, so later fields never shift. Trailing `null`s MUST be omitted.
- **Sparse struct:** a struct declared `sparse` is encoded as a map from field tag (uint) to value, with absent fields left out. Use it for types with many optional fields that are usually empty.
- **Enum:** the sigil as a uint.
- **Union:** `[variant_tag: uint, value]`.
- **List:** a CBOR array. **Map:** a CBOR map with keys of the declared key type.
- **Bytes:** a byte string. Values larger than the session's `maxInlineBytes` (default 64 KiB) SHOULD use a byte stream instead (section 7.8).
- **Dynamic:** `[type_id: uint, value]`, for a field whose type is only known at run time.

A decoder MUST skip array elements beyond the fields it knows and map entries whose tag it does not know. This rule lets a schema add fields without breaking older peers (section 6.7).

Message envelopes (sections 5 and 7) are fixed arrays: every field is present, `null` when empty, and the trailing-null rule applies only to struct values. Keys of protocol maps such as `params` are text strings.

### 3.5 Tags used

| Tag | Meaning |
| --- | --- |
| 1 | Epoch time (timestamp type). |
| 37 | UUID, 16-byte byte string. |
| 55799 | Self-described CBOR. MAY prefix a stored schema file; MUST NOT appear on the wire. |

The core spec defines no other tags. Profiles MAY register more.

## 4. Streams and transport bindings

A session uses one **shared lane** for control messages and small, long-lived calls, plus a pool of **leased streams** that calls take one at a time and give back. The number of streams follows peak concurrency rather than the number of calls, and large transfers do not share a stream with other calls. Servers MUST support both network bindings; clients MUST support WebTransport and SHOULD support WebSocket. The pipe binding (section 4.7) is optional and only for peers on one machine.

### 4.1 Two kinds of stream

|  | Shared lane | Leased stream |
| --- | --- | --- |
| Count | Exactly one per session | 0 up to the peer's `maxStreams`, per direction |
| Opened by | The client, first | The peer that makes calls on it |
| Calls at a time | Many, told apart by call ID | One |
| Default credit per call | 64 KiB (`sharedCredit`) | 1 MiB (`leaseCredit`) |
| Typical use | Handshake, control messages, notifications, subscriptions, small calls | Most calls, byte transfers, large result streams |
| Lifetime | The whole session | Until idle for a while (section 4.2) |

- The opener of a stream sends one header byte before anything else: `0x00` for the shared lane, `0x01` for a leased stream. The other direction has no header. `0x40`–`0x7F` are reserved for profiles; any other value, a second shared lane, or a shared lane opened by the server is a `protocol_error`.
- After the header, each message is preceded by its length as a QUIC variable-length integer (RFC 9000, section 16). Senders use the shortest form; receivers MUST accept any valid form. Receivers MUST reject a message longer than `maxMessageSize`.
- All messages of a call travel on the stream that carried its `Request`, in both directions. A call's messages are therefore ordered; separate calls have no ordering relation.
- Closing or resetting the shared lane ends the session.

### 4.2 Leasing

1. **Ownership.** A peer leases only streams it opened. The client's pool carries client-to-server calls and the server's pool, if it has one, carries server-to-client calls, so two peers can never claim the same idle stream.
2. **Start.** The caller leases an idle stream by sending a `Request` on it. If none is idle and fewer than the peer's `maxStreams` are open, it opens a new one. A peer that receives more leased streams than it allowed resets the extra ones with `resource_exhausted`. The opener counts a stream as open until both directions have finished or been reset, and the peer closes its direction only after it has seen the opener close, so both sides always count the same streams.
3. **Release.** The call ends as defined in section 7.1, after both peers have finished their halves, including any byte data. The stream is then idle and back in the pool. No message marks the release: each direction is ordered, so both peers see the same boundary.
4. **Shrink.** The opener SHOULD close streams that stay idle for about 30 s, by finishing its direction, and SHOULD keep one or two idle streams to avoid reopening. The peer then finishes its own direction.
5. **Abort.** Resetting a leased stream fails the call on it and removes the stream from the pool. Peers do this only when a `Cancel` goes unanswered (section 7.5) or the stream is broken. A reset aborts only the resetting side's sending direction (QUIC `RESET_STREAM`, never `STOP_SENDING`). A peer that sees a reset ends its own direction too. Each side counts the stream as open until it has both sent and seen the end of each direction, except that an acceptor that starts a reset stops counting it as soon as it has sent its end, because QUIC does not order streams and a replacement can arrive before the old stream's end. The opener therefore never opens a replacement the acceptor would still count. A side that has not seen the peer's end 5 s after resetting stops counting the stream. A call on a stream refused with `resource_exhausted` fails with that status.
6. **Pool exhausted.** When all `maxStreams` streams are leased, the caller either waits for one to be released or sends the call on the shared lane. Any call may fall back to the shared lane, including one with byte data, so a full pool never blocks progress.

### 4.3 Where a call goes

The caller decides. One rule is firm: notifications always use the shared lane. Recommended policy for the rest:

| Call | Stream |
| --- | --- |
| Notification | Shared lane (required) |
| Method flagged `shared` (section 6.4), typically a subscription of small events | Shared lane |
| Call with byte data in its input or output | Leased stream; shared lane only when no lease is available |
| Call that may send or return large messages or long streams | Leased stream |
| Any other call | Leased stream if one is idle or can be opened, otherwise the shared lane |

The server sets the `shared` flag on methods whose messages are small, so a client can hold dozens of subscriptions without spending a stream on each. Messages on the shared lane SHOULD NOT exceed 16 KiB, because a large message delays every call behind it.

### 4.4 Flow control

All streamed data, on every stream and both bindings, is paced by per-call credit counted in bytes (section 7.4). Two rules follow:

- **Always read.** A receiver MUST keep reading every stream and buffer each call's data within the credit it granted. It MUST NOT slow a call by leaving data unread in the transport.
- **Fairness.** On the shared lane, senders SHOULD alternate between calls that have data waiting, so no call holds the others up for long.

Because receivers always read, QUIC flow control only guards against broken peers. It never holds back data for long, so leased streams cannot use up the QUIC connection window and stall the shared lane. Memory per call is bounded by its credit plus one message (section 7.4).

### 4.5 WebTransport binding (primary)

- Transport: WebTransport over HTTP/3 (RFC 9114, draft-ietf-webtrans-http3). HTTP/2 WebTransport is out of scope.
- The shared lane and every leased stream are WebTransport bidirectional streams.
- `maxStreams` is enforced by the protocol (section 4.2). QUIC stream limits are fixed before the handshake and cannot be set from the browser API, so they are only a backstop. Servers SHOULD allow at least `maxStreams + 2` incoming bidirectional streams per connection, since the WebTransport CONNECT request and the shared lane also use streams.
- A stream reset carries a status code (section 8) as its WebTransport error code; browsers limit these codes to 0–255.
- WebTransport datagrams MAY carry profile-defined unreliable messages when both peers advertise the `datagrams` capability. The core spec defines none.
- Clients MAY pin a server certificate with `serverCertificateHashes` for development. Production servers SHOULD use a publicly trusted certificate.

### 4.6 WebSocket binding (fallback)

Used when WebTransport is unavailable, for example on networks that block UDP. A WebSocket is a single ordered connection, so this binding has a shared lane and nothing else:

- The client connects with subprotocol `sparrow.v1`. All data uses binary WebSocket messages.
- Each WebSocket message carries exactly one Sparrow message, with no length prefix and no stream header.
- Every call runs as it would on the shared lane, with `sharedCredit`. `maxStreams` does not apply.
- `maxMessageSize` applies to the WebSocket message size.
- Servers MUST check the `Origin` header on the upgrade request.

### 4.7 Pipe binding

For a single ordered byte stream between peers on one machine, such as a child process's standard input and output, a unix socket or an SSH channel. A supervisor can use it to talk to processes it starts, for example a tool that runs extensions as child processes. The binding is optional; a hub never starts processes (section 10.2).

- The side that sends `Hello` is the client. A started process is the client, on its standard input and output.
- There is only a shared lane: each message is preceded by its length as a QUIC variable-length integer (shortest form when sending, any valid form when receiving), with no stream header. Every call runs as on the shared lane, with `sharedCredit`; `maxStreams` does not apply.
- `maxMessageSize` applies to the length in the prefix: a receiver rejects a longer message before reading its body.
- Closing the byte stream ends the session. Status and reason travel only in `GoAway`.
- Standard error, where there is one, is not part of the protocol.

### 4.8 Transport selection

Transport choice is the client's job. A client SHOULD try WebTransport first, fall back to WebSocket after a short timeout (a value around 3 s is RECOMMENDED), and MAY remember the result per origin. Endpoint URLs come from the profile (for the web profile, from `/connect`, section 9.1).

## 5. Session lifecycle

A session is three shared-lane messages (`Hello`, `Welcome`, `Ready`) followed by any number of calls. Authentication methods and endpoint discovery happen before the session, in a profile; the core only carries an opaque credential in `Hello`.

### 5.1 Before the session (profile)

The core spec does not define how a client gets its endpoint URLs or credential. The Sparrow Web Profile does this with an HTTP `POST /connect` that returns a short-lived ticket and the endpoints (section 9.1). Other profiles MAY use mTLS, a static token, or no authentication.

### 5.2 Handshake

1. The client opens the transport and the shared lane, and sends `Hello`.
2. The server checks the protocol version and credential, then sends `Welcome` with its schema offer.
3. The client loads the schema (from cache, delta, inline or out of band) and sends `Ready`.
4. The client MAY start calls immediately after sending `Ready`, without waiting for a reply. The server MAY call the client, or open leased streams to it, only after receiving `Ready`, which shows the client has `Welcome` and its limits.

> *Diagram (not included in this snapshot): session start with the web profile, 1 HTTP request, 3 handshake messages.*

The first two messages belong to the web profile; the core begins at the transport. With a cached schema, `Hello`, `Ready` and the first calls go out together.

Rules for the server:

- `Hello` MUST arrive within 10 s of the transport opening, or the server closes the connection with `deadline_exceeded`.
- The client MUST NOT open leased streams before `Welcome` arrives. Until the credential is verified, the server buffers at most 64 KiB of shared-lane data after `Hello` and closes the session with `GoAway(resource_exhausted)` if the client sends more, so unauthenticated peers cannot make it hold much memory. On a failed check it closes the session with `unauthenticated`.
- The server MUST NOT dispatch a call before it has received `Ready`. Calls sent on the shared lane after `Ready` arrive in order. Calls on leased streams can arrive first; the server holds them until `Ready` arrives, up to `maxConcurrentCalls`. A call on the shared lane before `Ready` is answered with `Error(not_ready)`, and a `Ready` naming a hash other than the one offered closes the session with `GoAway(schema_mismatch)`.

If a session that did not start optimistically closes before `Welcome` arrives, no call was dispatched, and the client MAY retry all of them. In every other case, calls still open at the close fail with `unavailable`; the client retries only those whose method is flagged idempotent.

### 5.3 Optimistic start

A client with a cached schema can send `Hello`, `Ready` and its first calls in one flight, saving a round trip:

- It sets `Hello.optimistic = true`, puts the cached hash in both `Hello.known_schema` and `Ready`, and lists exactly one protocol version.
- Until `Welcome` arrives, it sends only on the shared lane, at most 64 KiB after `Hello`, and stays within the default `params`.
- It SHOULD send only calls to methods flagged idempotent this way: if the connection drops, the client cannot tell whether they ran.
- If the server's schema hash differs, the server MUST NOT dispatch any call from the session. It sends `Welcome`, so the client can update its cache, then `GoAway(schema_mismatch)` with `retry_after_ms` 0, and closes. The client reconnects and resends its calls; none of them ran.
- If the server's limits are below the defaults, it does the same with `GoAway(failed_precondition)`, again dispatching nothing. The client caches `Welcome.params` next to the schema and does not start optimistically against a server whose cached limits are below the defaults.
- After two rejected optimistic starts in a row, the client stops trying them for that server until its cached schema or limits change.
- Otherwise the session continues as a normal one.

Closing the session on a mismatch, rather than rejecting single calls, rules out a stale request being run against a newer schema whose IDs mean something else.

### 5.4 Handshake messages

```
Hello = [0,
  versions:       [+ uint],          ; protocol versions the client speaks, preferred first
  caps:           caps,
  auth:           auth / null,
  known_schema:   bstr / null,       ; hash of the server schema the client has cached
  client_schema:  [2, hash: bstr, schema: schema] / null,  ; the client's callable services, inline
  params:         params,            ; limits the client imposes on the server
  optimistic:     bool
]

Welcome = [1,
  version:        uint,              ; chosen protocol version
  caps:           caps,              ; capabilities both peers support
  session_id:     bstr,              ; 16 random bytes, for logs and auth refresh
  props:          { * tstr => any }, ; server properties and configuration
  server_schema:  schema-offer,
  params:         params             ; limits the server imposes on the client
]

Ready = [2, schema_hash: bstr]

auth = [scheme: tstr, credentials: any]   ; e.g. ["bearer", "<ticket>"]
caps = { * tstr => any }                    ; e.g. {"datagrams": true}

schema-offer =
    [0, hash: bstr]                              ; Unchanged: use the cached schema
  / [1, hash: bstr, from: bstr, delta: delta]    ; Delta from the schema the client named
  / [2, hash: bstr, schema: schema]              ; Full schema inline
  / [3, hash: bstr, location: tstr]              ; Fetch out of band (profile-defined, e.g. an HTTP URL)

params = {
  ? maxMessageSize:       uint,  ; default 1048576
  ? maxInlineBytes:       uint,  ; default 65536
  ? maxConcurrentCalls:   uint,  ; default 100
  ? maxStreams:           uint,  ; leased streams the peer may open (defaults below)
  ? sharedCredit:         uint,  ; initial credit per call on the shared lane, bytes; default 65536
  ? leaseCredit:          uint,  ; initial credit per call on a leased stream, bytes; default 1048576
  ? idleTimeoutMs:        uint   ; default 30000
}
```

Each peer's `params` are the limits it imposes on the other, like QUIC transport parameters: `Hello.params` bind the server and `Welcome.params` bind the client. A missing key means the default. `maxStreams` defaults to 16 in `Welcome` (streams the client may open) and 4 in `Hello` (streams the server may open). Both peers use the smaller `idleTimeoutMs`. Unknown keys are ignored. `maxMessageSize`, `maxInlineBytes`, `sharedCredit` and `leaseCredit` MUST be at least 16384 and `maxConcurrentCalls` at least 1; a peer that receives a smaller value closes the session with `GoAway(invalid_argument)`.

The client schema is always sent inline and is small for typical clients. A client that sends no client schema cannot publish one later in the session; a `SchemaUpdate` from it closes the session with `GoAway(schema_mismatch)`. The server parses it only after verifying the credential, and MAY reject one larger than 64 KiB or with type references nested deeper than 32 levels with `GoAway(invalid_argument)`.

If no version matches, the server sends `GoAway(unsupported_version)` with its versions in the `versions` field. If the credential is rejected, it sends `GoAway(unauthenticated)`.

### 5.5 Control messages

| Kind | Message | Direction | Purpose |
| --- | --- | --- | --- |
| 3 | `SchemaUpdate [3, epoch, hash, delta]` | either | The sender's own schema changed (section 6.6). |
| 4 | `SchemaAck [4, epoch]` | either | The sender has applied the peer's schema up to this epoch. |
| 5 | `AuthRefresh [5, auth]` | C→S | Present a fresh credential for the same principal. |
| 6 | `AuthStatus [6, status, expires_at: timestamp / null]` | S→C | Result of a refresh, or a warning that the session credential expires soon. |
| 7 | `Ping [7, nonce: uint]` | either | Liveness check. |
| 8 | `Pong [8, nonce: uint]` | either | Reply to `Ping`. |
| 9 | `GoAway [9, status, reason: tstr, retry_after_ms / null, versions: [* uint] / null]` | either | Graceful shutdown (section 5.6). This layout is fixed across all protocol versions. |

Authentication during a session:

- **Expiry** is defined by the profile, not by the credential's own lifetime. For the web profile it is the end of the login session (`sexp`, section 9.2); the ticket's short lifetime only limits when it can be presented.
- The server SHOULD send `AuthStatus` with status `ok` and the expiry at least 60 s before expiry. `AuthRefresh` is for client sessions. A hub that receives one from a node or peer that dialed in closes that session with `GoAway(unauthenticated)`. On a link the hub dialed, the node or peer is the server, so an `AuthRefresh` from it is a `protocol_error`, like any message sent in the wrong direction. At expiry it closes the session with `GoAway(unauthenticated)`.
- `AuthRefresh` MUST carry a credential for the same principal and login session as the original one. Otherwise the server closes the session with `GoAway(unauthenticated)`, so a session can never switch users.
- When the principal's permissions change, the server ends open calls that are no longer allowed with `Error(permission_denied)`, and sends a `SchemaUpdate` if the visible schema changes.

A peer SHOULD send `Ping` when it has received nothing for half of `idleTimeoutMs`. A peer that receives nothing for `idleTimeoutMs` closes the session with `GoAway(unavailable)`.

### 5.6 Shutdown

`GoAway` starts a graceful shutdown. Once it has been sent or received, neither peer opens new calls; a `Request` that crosses it is answered with `Error(going_away)`. Calls already running continue until they finish or a grace period (RECOMMENDED 30 s) ends, and then the transport is closed: the closing peer finishes its direction of the shared lane and waits for the peer's finish, or 2 s, before closing the transport, so messages in flight are not lost. `retry_after_ms` tells the client when to reconnect, which lets a server drain before a deploy.

`GoAway` carries only core status codes, normally `going_away` for a drain. The transport close repeats it as section 8 describes. An abrupt close with no `GoAway` is treated as `unavailable`. The client SHOULD reconnect with exponential backoff and jitter, starting around 500 ms and capped around 30 s.

## 6. Schema model

A schema is a set of **facets**. Each facet is self-contained, usually one plugin or one facility, with its own types, services, methods and sigils. A call names its method by facet ID and method ID, and its payload is read entirely within that facet. A hub can therefore combine facets from many peers and forward calls without decoding their payloads (section 10).

### 6.1 Ownership and IDs

- Each peer publishes its own schema: the server in `Welcome`, the client (optionally) in `Hello`.
- **All IDs in a call belong to the callee's schema.** The facet ID picks a facet of the callee's schema; method, type and sigil IDs are local to that facet.
- **No reference crosses a facet.** Every type reference, sigil and `dynamic` value refers to the facet of the method being called. Facets that share a contract each carry identical copies of its definitions (section 6.5).
- **Facet IDs** are unique within a schema. 0–15 are reserved for facets this spec defines: facet 1 is `sparrow.web` (section 9.4), which MUST match its definition exactly, by name and facet hash. The other reserved IDs MUST NOT appear. Other facets use 16 and up, and a schema lists its facets sorted by ID.
  - **Names** of facets and node IDs match `[a-z0-9-]+(\.[a-z0-9-]+)*`, ASCII only, except that a hub may prefix imported facet names with `<peer-id>/` (section 10.8). Names of types, services, methods, fields, variants and sigils are ASCII as well.
- **IDs inside a facet:**

| Space | Reserved, same meaning in every facet | Free |
| --- | --- | --- |
| TypeIds | 0–31 built-in types (section 6.3), 32–63 reserved | 64 and up |
| Sigils | 0–31 status codes (section 8), 32–47 core metadata keys (section 7.2), 48–63 reserved | 64 and up |
| ServiceIds, MethodIds | none | any; MethodIds are unique within the facet |

- Reserved IDs are never defined in a facet. Within a session a removed facet ID comes back only for a facet with the same name and major version that is a compatible successor of the last version the session saw (section 6.7), with its `retired` carried over. An ID listed in a facet's `retired` is never defined again in that facet.

### 6.2 Document layout

```
schema = [
  format:      2,
  name:        tstr,             ; e.g. "sparrow.host"
  version:     tstr,             ; informative
  facets:      [* facet],
  annotations: annotations
]

facet = [
  id:          uint,
  name:        tstr,             ; unique within the schema, e.g. "acme.charts"
  version:     tstr,             ; semver of the facet
  types:       [* type-def],
  services:    [* service-def],
  sigils:      [* sigil-def],
  implements:  bstr / null,      ; hash of the interface this facet implements (section 6.5)
  retired:     [* [space: uint, id: uint]],  ; space: 0 type, 1 service, 2 method, 3 sigil
  annotations: annotations
]

annotations = { * tstr => any }  ; profile-defined metadata; unknown keys MUST be ignored
```

In CDDL, `any` means any CBOR value. Sparrow's run-time typed value is the built-in type `dynamic` (section 6.3). Annotation keys starting with `sparrow.` are reserved for this spec: `sparrow.defaults` (section 10.3) and the hint `sparrow.level` (section 10.4).

### 6.3 Types

Built-in types:

| TypeId | Name | CBOR encoding |
| --- | --- | --- |
| 0 | `unit` | `null` |
| 1 | `bool` | `true` / `false` |
| 2 | `int` | integer, signed 64-bit range |
| 3 | `uint` | unsigned integer, 64-bit range |
| 4 | `float32` | float |
| 5 | `float64` | float |
| 6 | `string` | text string |
| 7 | `bytes` | byte string |
| 8 | `timestamp` | tag 1 + integer or float seconds (integer when there is no fraction; implementations keep at least millisecond precision; one that keeps exactly milliseconds rounds to the nearest, halves toward the later time) |
| 9 | `uuid` | tag 37 + 16-byte byte string |
| 10 | `dynamic` | `[type_id, value]`, where `type_id` is a built-in or a named type of the same facet |
| 11 | `symbol` | sigil (uint) or text string |

`symbol` is for strings that repeat often (event names, CSS classes, keys): the encoder sends the sigil when the string has one and the text otherwise. A `dynamic` value can only name a type by ID, so a composite such as a list needs an alias (below).

Type references compose built-in and user types:

```
type-ref = uint                                 ; a TypeId
         / [0, type-ref]                        ; list
         / [1, key: type-ref, value: type-ref]  ; map
         / [2, type-ref]                        ; optional (nullable)
         / [3, type-ref]                        ; stream of values: only as a method's whole input or output
         / [4]                                  ; byte stream (section 7.8)
```

User-defined types:

```
type-def =
    [0, id, name, fields: [* field], flags: uint, annotations]  ; struct (flag 0x1 = sparse)
  / [1, id, name, values: [* sigil-id], annotations]             ; enum
  / [2, id, name, variants: [* variant], annotations]            ; union
  / [3, id, name, target: type-ref, annotations]                 ; alias (named, same encoding)

field   = [tag: uint, name: tstr, type: type-ref, flags: uint, annotations]
          ; flags: 0x1 optional, 0x2 deprecated, 0x4 removed
variant = [tag: uint, name: tstr, type: type-ref, flags: uint, annotations]
          ; flags: 0x4 removed
id      = uint
name    = tstr   ; dot-separated, e.g. "PanelConfig"
```

A removed field or variant stays in the list as a tombstone, so its tag is never reused; encoders send `null` in a removed field's slot.

### 6.4 Services and methods

```
service-def = [id: uint, name: tstr, methods: [* method-def], annotations]

method-def = [
  id:      uint,          ; MethodId, unique within the facet
  name:    tstr,          ; e.g. "openPanel"
  input:   type-ref,      ; [3, T] = client stream, [4] = byte stream
  output:  type-ref,      ; [3, T] = server stream, [4] = byte stream
  errors:  [* sigil-id],  ; error codes this method may return, beyond the core set
  flags:   uint,          ; 0x1 idempotent, 0x2 notification, 0x4 shared,
                          ; 0x8 input ends with End, 0x10 output ends with End
  annotations
]
```

The call shape follows from the types: plain input and output is unary, and `[3, T]` on either side makes that side a stream.

Flags 0x8 and 0x10 say whether each half of a call is finished by `End` (section 7.1). The owner MUST set 0x8 when the input is a stream or contains `[4]` anywhere, following referenced types, and 0x10 likewise for the output. It MAY set them in other cases, which leaves room to add byte fields later. `[4]` MUST NOT appear inside a `dynamic` value. A method with flag 0x2 (notification) MUST have output `unit` and no `[4]` in its input. A method's `input`, `output` and flags 0x2, 0x8 and 0x10 never change once defined. Type IDs 12–31 are reserved for built-ins of later core versions, so a schema that uses them is invalid under this version.

### 6.5 Sigils and interfaces

```
sigil-def = [id: uint, name: tstr, kind: uint, annotations]  ; kind: 0 enum value, 1 error code, 2 symbol
```

Every enum value, error code and interned symbol is a sigil. Enum values MUST be kind-0 sigils and error codes other than the core ones MUST be kind-1 sigils. Sigil names MUST be unique within a facet or interface. An enum value's sigil is named after its enum, `<enum name>.<value name>` (for example `Color.green`), so two enums can both have a value `none`; language bindings MAY show the value name alone. A kind-0 sigil is a value of exactly one enum.

An **interface** is a contract that several facets can implement, such as an extension point every chart plugin provides. A facet implements at most one interface; a node that implements several publishes one facet for each.

```
interface = [name: tstr, version: tstr, types: [* type-def], services: [* service-def], sigils: [* sigil-def]]
```

It contains its services and exactly the types and sigils those services reach, not counting references inside tombstones. Its hash is computed like a facet's (section 6.6). Conformance compares **wire shapes**: the canonical encoding of a definition with every `name` replaced by an empty string, every `annotations` by an empty map, the hint flags cleared (method flags 0x1 and 0x4, field flag 0x2), and, for a service, its list of methods left out. A facet implements an interface when every type, sigil and service of the interface appears in the facet with the same ID and the same wire shape, and every method of each interface service appears in the facet's service with the same ID and the same wire shape. The facet may add definitions of its own, including further methods in an implemented service. The check is a byte comparison, and names, documentation and annotations such as access hints stay free. A facet names the interface it implements in `implements`, and a peer that receives a facet SHOULD verify each claim.

### 6.6 Canonical form, hashes, epochs and deltas

- **Canonical form:** within a facet or interface, types, services and sigils are sorted by ID, methods by ID within their service, fields and variants by tag, enum values and errors by sigil ID, and `retired` by space then ID; a schema's facets are sorted by ID. Every other array, including those inside annotations, keeps its order. The result is encoded with Core Deterministic Encoding (section 3.2).
- **Hashes** are all `0x01 || SHA-256(canonical bytes)`, 33 bytes; the leading byte names the algorithm.
  - A **facet hash** covers the canonical facet with its `name` set to an empty string and its `id` set to 0, so a facet keeps its hash under any facet ID or name a hub gives it.
  - An **interface hash** covers the canonical interface.
  - The **schema hash** covers `[format, name, version, [* [facet_id, facet_name, facet_hash]], annotations]`, with the entries sorted by facet ID.
- **Epoch:** each schema has its own epoch, starting at 0 when the session starts and going up by one with each `SchemaUpdate` from its owner. `SchemaAck(N)` acknowledges every epoch up to N. A peer only ever acknowledges the other peer's schema, so an ack is never ambiguous.
- **Delta:** facets change as whole units:

```
delta = [* delta-op]
delta-op =
    [0, facet]           ; add a facet, or replace the facet with the same ID
  / [1, facet_id: uint]  ; remove a facet
  / [2, annotations]     ; replace top-level annotations
  / [3, version: tstr]   ; replace the version string
```

Rules for live updates:

1. The owner MUST NOT send any message that uses a facet or ID added in epoch N, whether a request, response, item or error detail, until it has received `SchemaAck` for N. This holds for responses too, even on a call whose request already used those IDs. Such messages wait in a queue. If the ack has not arrived within 10 s, the owner closes the session with `GoAway(schema_mismatch)`. The receiver MUST send `SchemaAck` as soon as it has applied the delta and checked the hash (a hub relaying a node's facets acks as section 10.3 describes); downloading modules, writing snapshots and other follow-up work happen afterwards.
2. A replacing facet MUST be a compatible change of the facet it replaces (section 6.7); a receiver MAY verify this, and a hub MUST verify it for facets it receives from nodes, and every top-level ID it drops MUST appear in its `retired`. Methods that disappear, with their facet or alone, reject new calls with `unimplemented`; calls already running finish, and receivers keep the old definitions until those calls end.
3. After applying a delta, the receiver MUST check that every facet is valid (every reference resolves within its facet, references inside tombstones excepted; no reserved or retired ID is defined; no facet ID outside the rules of section 6.1; no float anywhere) and that the new schema hash matches the one in `SchemaUpdate`. On any failure it closes the session with `GoAway(schema_mismatch)`, and the next connection fetches the full schema.

Facet IDs and the IDs inside facets SHOULD stay stable across restarts, rebuilds and every server of a deployment, so reconnecting clients usually get `Unchanged` or a small delta. A server sends a delta only if it still has the schema the client named; otherwise it sends the full schema. Reference implementations MUST publish test vectors for facets, interfaces, schemas, deltas and their hashes.

### 6.7 Evolution rules

| Change inside a facet | Allowed? | Notes |
| --- | --- | --- |
| Add a struct field with a new tag | Only if optional | Older readers skip it. |
| Add an enum value or union variant | Yes | Readers MUST handle unknown values. |
| Add a type, service, method or sigil | Yes | New IDs. |
| Move a method to another service of the facet | Yes | Methods are identified by ID. |
| Change annotations, anywhere in the facet | Yes |  |
| Rename a type, field, service, method or sigil | Yes | Names are informational on the wire. |
| Mark a field deprecated, or change method flags 0x1 and 0x4 | Yes | Hints only. |
| Remove a type, service, method or sigil that is not an enum value | Yes | Its ID goes into `retired`, which only ever grows. |
| Remove an optional field or a variant | Yes | It stays as a tombstone with flag 0x4, permanently. |
| Remove an enum value or a required field | No | Old senders would still send it. |
| Change a definition's kind, a struct's sparse flag, an alias target, a field's or variant's type, or a sigil's kind | No | Add a new definition. |
| Make an optional field required, or reuse a tag | No | Add a new field. |
| Change a method's input, output, or flags 0x2, 0x8, 0x10 | No | Add a new method. |
| Make `[4]` reachable from a method half whose End flag is not set | No | Peers would disagree on how the call ends. |
| Change the major version, which is the first number of `version` (0 included) | No | A new major version is a new facet (section 10.3). |
| Rename the facet | No | A facet's name identifies it. |
| Make a required field optional | No | Older readers still require it. |
| Change a field's or variant's type when it becomes a tombstone | No | A tombstone keeps its last definition and never changes again, apart from its name and annotations. |

## 7. RPC messages

Every call has a call ID chosen by the caller, whether it runs on the shared lane or a leased stream. Each side of a call finishes its half with a defined message, and the call ends when both halves are finished. Cancellation is a message rather than a stream reset, so a leased stream survives it and returns to the pool.

### 7.1 Call IDs and call lifetime

- The caller assigns the ID. Client IDs are even and server IDs are odd, so they never collide. ID 0 is reserved for notifications, which get no reply.
- A sender's IDs, apart from 0, MUST strictly increase. A callee tracks the IDs of calls it has not finished. A `Request` whose ID belongs to one of them, or that arrives on a leased stream that is not idle (both halves of its last call finished), is a `protocol_error`. Receivers need not detect reuse of IDs they no longer track, which would take unbounded memory.
- The **caller's half** is finished by the `Request` itself, unless the method has flag 0x8 (*input ends with End*, section 6.4); then by `End` or `Cancel`.
- The **callee's half** is finished by `Response`, unless the method has flag 0x10 (*output ends with End*); then by `End`. `Error` finishes it at any time. These flags are fixed for the life of the method, so both peers always agree whether `End` is coming, even while the schema changes.
- `End`, `Error` and `Cancel` also close every byte token their sender opened in the call. Data not yet marked `fin` is cut off, and the receiver discards any later `Bytes` for the call. A referenced token that was cut off or never sent reaches the application as data_loss.
- The call **ends** when both halves are finished. The caller then forgets its ID, and a leased stream it ran on is idle again.
- If the callee finishes first while input is still arriving, it forgets the call ID, ignores that input and grants no more credit for it (section 7.6). On a leased stream it still notes when the caller's half finishes (`End` or `Cancel`, or the `Request` itself for a method without flag 0x8), since only then is the stream idle: one flag per stream. When the callee's final message arrives, the caller MUST send `End` (or `Cancel`) next, with no further `Item` or `Bytes`.
- Messages for an unknown or ended call ID are ignored. A `Request` naming a facet or method the callee does not have is answered with `Error(unimplemented)`; a notification naming one is dropped. The callee remembers the flags of every method it has published in the session and decides from them whether the caller's half is still open; for a method it never published it assumes no flags. A call-ID-0 `Request` for a method without flag 0x2 is dropped, and a `Request` with another ID for a method with flag 0x2 is answered with `Error(invalid_argument)`.

### 7.2 Call messages

| Kind | Message | Sent by | Layout |
| --- | --- | --- | --- |
| 16 | `Request` | caller | `[16, call_id, facet_id, method_id, metadata, input]` |
| 17 | `Response` | callee | `[17, call_id, output]` (unary result) |
| 18 | `Item` | either | `[18, call_id, value]` (one stream element) |
| 19 | `End` | either | `[19, call_id, trailers]` (finishes the sender's half) |
| 20 | `Error` | callee | `[20, call_id, status: sigil, message: tstr, details: any / null]` |
| 21 | `Progress` | callee | `[21, call_id, done: uint, total: uint / null, note: tstr / null]` |
| 22 | `Headers` | callee | `[22, call_id, metadata]` (optional, before the first `Item` or `Bytes`) |
| 23 | `Cancel` | caller | `[23, call_id, status: sigil]` |
| 24 | `Credit` | either | `[24, call_id, amount: uint]` (bytes) |
| 25 | `Bytes` | either | `[25, call_id, token: uint, data: bstr, fin: bool]` |

`metadata` and `trailers` are `{ * symbol => any }`. Core keys use reserved sigils; applications use their own sigils or text keys. Unknown keys MUST be ignored.

| Sigil | Key | Type | Meaning |
| --- | --- | --- | --- |
| 32 | `deadline` | uint | Milliseconds the caller will wait. The callee answers `Error(deadline_exceeded)` when it passes. |
| 33 | `trace` | bytes | W3C `traceparent` packed into 26 bytes: version (1), trace ID (16), parent ID (8), flags (1). |
| 34 | `(reserved)` | — | Reserved. (Rule 1 of section 6.6 already prevents a peer from using IDs its partner has not acknowledged.) |
| 35 | `credit` | uint | Initial credit in bytes the caller grants for the callee's half, replacing the default. Any value is allowed; 0 makes the callee wait for a `Credit`. |
| 36 | `context` | bytes | Hub Profile: opaque call context issued by a hub (section 10.6). |
| 37 | `principal` | string | Hub Profile: the principal a forwarded call acts for (section 10.6). |

### 7.3 Call shapes

| Shape | Input type | Output type | Caller sends | Callee sends |
| --- | --- | --- | --- | --- |
| Unary | `T` | `U` | `Request(input)` | `Response(output)` |
| Server stream | `T` | `[3, U]` | `Request(input)` | `Headers`?, `Item`…, `End` |
| Client stream | `[3, T]` | `U` | `Request(null)`, `Item`…, `End` | `Response(output)` |
| Bidi stream | `[3, T]` | `[3, U]` | `Request(null)`, `Item`…, `End` | `Headers`?, `Item`…, `End` |
| Upload | `[4]` | `U` | `Request(null)`, `Bytes`… (last with `fin`), `End` | `Response(output)` |
| Download | `T` | `[4]` | `Request(input)` | `Headers`?, `Bytes`… (last with `fin`), `End` |
| Notification | `T` | `unit`, flag 0x2 | `Request` with call ID 0, on the shared lane | nothing |

- In every shape the callee MAY send `Error` instead of its normal final message.
- When a `Request` or `Response` value references byte tokens (section 7.8), its sender follows it with the `Bytes` for those tokens and finishes its half with `End`.
- A subscription is a server-stream call that stays open until either side ends it. On the shared lane it costs no stream of its own.
- Notifications MUST NOT carry byte data and are best-effort: a callee MAY drop notifications it cannot buffer, and MAY close a session that floods it with `GoAway(resource_exhausted)`. Use a unary call when delivery matters.

### 7.4 Flow control

Every call is flow-controlled with credit, per direction, on every stream.

- **Unit:** bytes. Each `Item` and `Progress` message counts the length of its CBOR data item, that is, of the whole message without its length prefix (so the count is the same over WebSocket), and each `Bytes` message counts the length of `data`. `Request`, `Response`, `Headers`, `End`, `Error`, `Cancel` and `Credit` do not count; each is bounded by `maxMessageSize` and occurs at most once per call or carries no data.
- **Initial credit:** each direction of a call starts with `sharedCredit` (default 64 KiB) on the shared lane or `leaseCredit` (default 1 MiB) on a leased stream. The caller MAY set the callee's initial credit with the `credit` metadata key.
- **Granting more:** the receiver sends `Credit [24, call_id, amount]`; grants add up. It SHOULD grant more once about half of its credit is used.
- **Sending:** a sender MAY send a message whenever its remaining credit is above zero, even if the message is larger; the credit then goes negative until more is granted. This guarantees progress for messages bigger than the window. A sender with zero or negative credit waits, except for messages that count zero bytes, such as an empty final `Bytes` chunk, which are never held back.
- **Violation:** a peer that sends with no credit left has broken the protocol for that call. The callee answers `Error(protocol_error)` and the caller sends `Cancel(protocol_error)`.
- **Memory bound:** a receiver buffers at most its granted credit plus one `maxMessageSize` per call direction, so a session needs at most about `maxConcurrentCalls` × (credit + `maxMessageSize`) for buffered data, plus one Request and one Headers per call, each up to maxMessageSize. Receivers SHOULD grow the credit they grant toward the bandwidth-delay product, so the 64 KiB shared-lane default does not cap throughput on fast links.

### 7.5 Cancellation and deadlines

- The caller cancels with `Cancel(status)`, normally `cancelled`. `Cancel` may be sent while the callee's half is open. It finishes the caller's half if that was still open, closes its byte tokens, and asks the callee to stop.
- The callee SHOULD stop work and MUST answer with a final message, normally `Error(cancelled)`, unless it has already sent one. The call then ends as in section 7.1, so a leased stream returns to the pool in a clean state.
- If no final message arrives within about 5 s, the caller gives up. On a leased stream it resets the stream (section 4.2), which also tells the callee, and counts the call as long as it counts the stream (section 4.2, rule 5). On the shared lane it keeps counting the call toward `maxConcurrentCalls` until the final message arrives; if none arrives within 30 s, the peer is broken and the caller closes the session with `GoAway(protocol_error)`.
- When a `deadline` passes, the callee sends `Error(deadline_exceeded)`. The caller MAY also send `Cancel(deadline_exceeded)` when its own timer fires.

### 7.6 Concurrency

- A peer MUST NOT have more than `maxConcurrentCalls` calls open as caller, counting the shared lane and leased streams together. The caller counts a call until it has both sent its own last message and seen the callee's final one. The callee counts a call from its `Request` until it has sent its own final message or ended its direction of the call's stream, and then forgets it: later messages for it are ignored (section 7.1). Because the callee always stops counting first, a caller within its limit is never refused, even though QUIC does not order streams (as in section 4.2, rule 5), except by a callee that left a `Cancel` unanswered past the 5 s of section 7.5; the callee answers excess requests with `Error(resource_exhausted)`. Notifications do not count.
- Messages of one call are ordered because they share a stream. Calls are independent of each other.

### 7.7 Example

A unary call with call ID 2 to method 1042 (`Panels.open`) of facet 16, with input struct `["settings", true]`, on an idle leased stream:

```
; caller -> callee
13                                  ; message length 19 (varint)
86                                  ; array(6)
   10                               ;   16  Request
   02                               ;   2  call_id
   10                               ;   16  facet_id
   19 04 12                         ;   1042  method_id
   a0                               ;   {}  metadata
   82 68 73 65 74 74 69 6e 67 73 f5 ;   ["settings", true]

; callee -> caller, same stream
04 83 11 02 f6                      ; length 4, [17, 2, null]
```

The `Request` finished the caller's half and the `Response` finished the callee's, so the call has ended and the stream is idle again. The same call in JSON-RPC carries the method name and field names as strings; here the whole request is 19 bytes.

### 7.8 Byte streams

Byte data travels in `Bytes` messages: `[25, call_id, token, data, fin]`. The CBOR header on `data` is 1–9 bytes per chunk, and decoders SHOULD return views into the receive buffer instead of copying.

- **Inline:** when a method's input or output type is exactly `[4]`, the data uses token 0 (section 7.3 shows the shapes).
- **By reference:** a `[4]` nested inside a struct, list or union is encoded as a nonzero `uint` token. The sender picks it, unique within the call for that sender, and sends the data as `Bytes` with that token. A sender MUST NOT open more than 64 tokens in one call.
- **Order:** data for a token MAY arrive before the message that mentions it. Chunks of different tokens MAY be interleaved; each token ends with a chunk that has `fin = true`, and an empty final chunk is allowed.
- **Chunk size:** on a leased stream a chunk may be as large as `maxMessageSize` allows. On the shared lane chunks SHOULD be at most 16 KiB. All byte data counts against the call's credit (section 7.4).

## 8. Errors and status codes

One set of status codes is used everywhere. Codes 0–16 have the same numbers and meanings as gRPC status codes, so bridging to gRPC or mapping to HTTP is direct. Core codes use the reserved sigils 0–31 and need no schema entry; methods declare any extra error sigils they return in `method-def.errors`.

| Sigil | Name | Meaning | Retry? |
| --- | --- | --- | --- |
| 0 | `ok` | Success. | — |
| 1 | `cancelled` | The caller cancelled. | No |
| 2 | `unknown` | Error with no better code. | Maybe |
| 3 | `invalid_argument` | Input failed validation. | No |
| 4 | `deadline_exceeded` | The deadline passed. | Yes, with a longer deadline |
| 5 | `not_found` | A named resource does not exist. | No |
| 6 | `already_exists` | Create conflicted with an existing resource. | No |
| 7 | `permission_denied` | Authenticated but not allowed. | No |
| 8 | `resource_exhausted` | Rate limit, quota, `maxConcurrentCalls` or `maxStreams` hit. | Yes, with backoff |
| 9 | `failed_precondition` | System not in the required state. | No |
| 10 | `aborted` | Concurrency conflict. | Yes |
| 11 | `out_of_range` | Value outside the valid range. | No |
| 12 | `unimplemented` | Method unknown or retired. | No |
| 13 | `internal` | Callee bug. | No |
| 14 | `unavailable` | Temporarily unavailable. | Yes, with backoff |
| 15 | `data_loss` | Data lost or corrupted, such as a failed hash check. | No |
| 16 | `unauthenticated` | Credential missing, invalid or expired. | After re-auth |
| 17 | `protocol_error` | Malformed message or broken rule of this spec. | No |
| 18 | `schema_mismatch` | IDs or hash do not match the peer's schema. | After reloading the schema |
| 19 | `unsupported_version` | No common protocol version. | No |
| 20 | `not_ready` | Call arrived before `Ready`. | Yes |
| 21 | `going_away` | Peer is shutting down (`GoAway`). | Yes, on a new session |
| 22 | `message_too_large` | Exceeded `maxMessageSize`. | No |

Codes 23–31 are reserved for later core versions. Stream resets and transport closes carry only core codes; an application error code always travels in an `Error` message.

| Where | How the status is carried |
| --- | --- |
| `Error`, `Cancel`, `GoAway`, `AuthStatus` | The `status` field. `Error` may carry any status sigil of the method's facet; `Cancel`, `GoAway` and `AuthStatus` carry core codes only. |
| WebTransport stream reset | The stream error code: a core status code. |
| WebTransport session close | The session close code: a core status code; the reason holds at most 1024 bytes of UTF-8. |
| WebSocket close | 1000 for `ok`, otherwise 4000 + the core status code; the reason holds at most 123 bytes of UTF-8. A sender shortens a longer reason at a character boundary. The mapping covers all core codes 0–31. |

A peer that detects a `protocol_error` inside a call ends that call with `Error` (as callee) or `Cancel` (as caller). Outside any call, it sends `GoAway(protocol_error)` and closes the session.

`Error.details` is any CBOR value. It SHOULD be a `dynamic` value (`[type_id, value]`) from the method's facet, so clients can decode structured errors such as a list of invalid fields.

## 9. Sparrow Web Profile

The web profile binds the core to browsers: users log in with normal HTTP authentication, `/connect` trades that login for a short-lived ticket, schemas and modules are cacheable HTTP resources, and the client keeps a signed offline snapshot. Everything here is optional for non-browser uses of the core.

### 9.1 Connect endpoint

`POST /sparrow/connect` uses whatever authentication the host already has: session cookie, `Authorization` header, OIDC. Request (JSON):

```json
{
  "client": { "name": "sparrow-web", "version": "1.4.0", "hostApi": "3.2" },
  "knownSchemaHash": "AbC..."
}
```

Response `200`:

```json
{
  "ticket": "v4.public.eyJ...",
  "ticketExpiresAt": "2026-11-26T12:00:45Z",
  "sessionExpiresAt": "2026-11-26T20:00:00Z",
  "endpoints": {
    "webtransport": "https://edge-3.example.com/sparrow/wt",
    "websocket": "wss://edge-3.example.com/sparrow/ws"
  },
  "protocolVersions": [1],
  "schemaHash": "AbC...",
  "schemaUrl": "/sparrow/schema/AbC...",
  "serverCertificateHashes": null
}
```

Hashes in JSON and in URLs (the `{hash}` in section 9.3) are base64url without padding. `401` means log in again; `426` means the client's `hostApi` is below the minimum the host is configured with (section 9.4). `serverCertificateHashes`, when not `null`, is a list of base64url SHA-256 hashes of certificates the client may pin. The endpoint MUST require a CSRF-safe request: a JSON body with `Content-Type: application/json`, and an origin check: a request whose `Origin` header names an origin the host does not allow is refused, whatever its authentication. The refresh response holds only `ticket`. The schema and module resources (section 9.3) require the same HTTP authentication as `/connect`, except `public` modules.

Because `/connect` returns the schema hash, the client can compare it with its snapshot and send an optimistic `Hello` (section 5.2) without waiting for `Welcome`.

### 9.2 Tickets

- The ticket goes in `Hello` as `["bearer", ticket]`. WebTransport sends no cookies and browsers cannot set headers on WebTransport or WebSocket, so it has to travel inside the protocol.
- A ticket is a signed token (PASETO `v4.public` or a JWT with EdDSA), so edge servers verify it without calling the host. Claims: `sub`, `sid` (the login session), `aud`, `iat`, `exp`, `jti`, `sexp` (when the login session ends), and optionally `groups` (a list of group names for the host's authorization). A ticket without `iat` is refused.
- `exp` MUST be no earlier than `iat` and at most 60 s after it. It only limits when the ticket may be presented in `Hello` or `AuthRefresh`; the session itself lasts until `sexp` (section 5.5).
- A ticket MUST be single-use: the edge records its `jti` until `exp`. Because one edge cannot see another's records, `aud` MUST name the specific edge instance whose endpoints `/connect` returned; it is a string the edge chooses (the reference uses its WebTransport URL), and each edge accepts only its own. Instances that share one hostname behind a load balancer MUST share a `jti` store.
- **Refresh:** before `sexp`, the client posts `{"refresh": {"endpoint": "<URL of the endpoint it is connected to>"}}` to `/connect` with its normal HTTP authentication. The response holds only a new ticket with the same `sub` and `sid` and the current edge as `aud`. The client sends it in `AuthRefresh`.
- Logging out SHOULD close live sessions: the host revokes `sid`, and edges send `GoAway(unauthenticated)`.

### 9.3 Schema and module resources

| Resource | Content type | Caching |
| --- | --- | --- |
| `GET /sparrow/schema/{hash}` | `application/cbor` | `immutable`, 1 year. `private` if the schema differs per user. |
| `GET /sparrow/mods/{hash}.js` | `text/javascript` | `immutable`, 1 year. `public` only if every user may load the module, otherwise `private`. |
| `GET /sparrow/mods/{hash}.{ext}` | by extension | Assets (CSS, WASM, images), same rules. |

The server MAY use `Welcome.server_schema = [3, hash, url]` to tell the client to fetch the schema over HTTP. Since a hash never changes meaning, Service Workers and CDNs can cache these forever.

Schemas that vary by permission (a user who cannot see the admin plugin gets a schema without it) have different hashes, so caching stays correct. They MUST be served `private`.

### 9.4 Modules and the host API

Each facet declares the client modules it ships in its own `web.modules` annotation, so a module arrives and leaves with its facet. The client gathers them from all facets:

```
web-module = {
  id:        tstr,            ; "acme.charts"
  version:   tstr,            ; semver
  hash:      bstr,            ; schema hash format: 0x01 || SHA-256 of the file
  url:       tstr,            ; usually /sparrow/mods/{hash}.js
  deps:      [* tstr],        ; module ids that must load first
  hostApi:   tstr,            ; semver range, e.g. "^3.1"
  ? assets:  [* {path: tstr, hash: bstr}],
  ? load:    "eager" / "lazy",
  sig:       [key_id: bstr, signature: bstr]   ; section 9.5
}
```

A module is an ES module whose default export is a factory:

```ts
export default function register(host: HostApi): ModuleInstance
```

Rules:

- Modules MUST NOT bundle their own copy of SolidJS or other shared runtime libraries; they get them from `host`. Two copies of Solid would mean two reactive systems that cannot see each other's signals.
- The client MUST skip any module whose `hostApi` range does not include its own host API version, and report it with the `moduleRejected` notification of facet 1, `sparrow.web` (below).
- The `hostApi` version is the client's real compatibility contract. It MUST follow semver: removing or changing anything in `HostApi` is a major version.
- Configuration for the client (layout, routes, feature flags) goes in `Welcome.props` or in top-level schema annotations under `web.*`, whose shape the host API defines. A facet's own annotations may carry only `web.modules` (a hub refuses a node facet whose `web.modules` is malformed or breaks the rule below with `GoAway(invalid_argument)`), and every module `id` in it MUST equal the facet's name or start with it followed by a dot, ignoring any `<peer-id>/` prefix a hub added (section 10.8). Module ids follow the same ASCII grammar as facet names. A client ignores any other `web.*` key in a facet; `web.keys`, `web.revoked` and client configuration are read from top-level schema annotations only. A facet therefore cannot change client-wide settings or ship modules under another facet's name.

Facet 1, `sparrow.web`, is defined by this spec with version `1.0.0`, no types, sigils, interface, retired IDs or annotations, and every server implementing the web profile includes it exactly. It has one service, 0 `Client`, with one method, 0 `moduleRejected`: a notification (flag 0x2) whose input is a list of strings (`[0, 6]`) holding the module's `id`, its `version` and a reason, and whose output is `unit`.

### 9.5 Module signing

Signing protects clients against a compromised plugin publisher, build pipeline, CDN or module store, and lets one frozen client trust modules from several publishers. It does not protect against a compromised origin that serves the client shell itself (`index.html` and the Service Worker), because whoever controls the shell controls the trusted keys. If that threat is in scope, serve the shell from a separate, locked-down origin.

- **Root keys:** the client build embeds one or more root public keys. Root keys are never added, replaced or removed at runtime.
- **Publisher certificates:** the schema annotation `web.keys` carries `[publisher_key, namespace, expires, root_key_id, root_sig]` entries. Each lets a publisher key sign modules whose `id` starts with `namespace`, which MUST end with a dot (for example `acme.`), until `expires`. Expiry is checked when a module is accepted into a snapshot, not each time a stored snapshot boots, so an offline client keeps working. A certificate is valid while the current time is strictly before `expires`; when several certificates name the same key, one valid certificate is enough. A namespace covers a module `id` when the `id`'s UTF-8 bytes start with the namespace's bytes.
- **Per-module signatures:** each `web-module` carries `sig`, an Ed25519 signature over the canonical CBOR (section 3.2) of the entry without `sig`. The client MUST reject a module unless the key is a root key, or a certified publisher key whose namespace covers the module `id`, that has not expired and is not revoked. The file hashes in the entry then cover every byte.
- **Rollback protection:** after a snapshot has booted successfully, the client records the highest version of each module in it, and afterwards rejects lower versions, except in the one previous snapshot it keeps for rollback (section 9.6). A publisher or operator undoes a bad release by publishing a higher version.
- **Revocation:** the annotation `web.revoked` carries `[seq, [* key_id], root_key_id, root_sig]`. The client keeps the list with the highest `seq` and rejects modules signed by any key on it. Only a list signed by a root key counts. Root keys themselves cannot be revoked this way: an entry naming a root key is ignored and the rest of the list applies. Replacing a root key takes a new client build.
- **Stored state:** certificates are re-verified against the build-embedded root keys every time they are used, so a module that tampers with stored data cannot add trusted keys. At worst it can erase version and revocation records, which the next verified schema restores.
- **Scope:** namespaces limit what each publisher can sign. Once loaded, all modules share one JavaScript realm, so a module can still affect others unless modules are sandboxed (section 12.3).
- A development build MAY accept unsigned modules behind an explicit flag that a production build cannot enable.

Signed formats, which the reference test vectors also cover:

- **Keys:** keys are raw 32-byte Ed25519 public keys. `key_id` is the first 16 bytes of SHA-256 of the key. The `key_id` in a module's `sig` is that of the key that signed it, root or publisher.
  - **Verdicts:** a module is accepted only if every rule in this section holds. The order in which a client checks them does not change the verdict.
- **What each signature covers:** the canonical CBOR (section 3.2) of the two-element array [domain, value], where value is the signed array or map without its signature element. The domain string keeps one kind of signature from being replayed as another. The module `sig` uses `"sparrow-module-v1"`, certificates use `"sparrow-cert-v1"`, and revocation lists use `"sparrow-revoked-v1"`.
- **Times:** `expires` is tag 1 with integer seconds.
- **Versions:** module versions are semver 2.0 and compared by semver precedence, including pre-releases.

### 9.6 Offline snapshots

A snapshot is everything the client needs to boot without a network. It lives only in the client's own storage, so its encoding is the client's choice:

```
snapshot = { schemaHash, schema, props, modules: [web-module], files: {hash => bytes}, createdAt }
```

1. **Boot:** load the newest valid snapshot, verify file hashes, load modules, render.
2. **Connect** in the background (`/connect`, then the session). If the snapshot's schema hash is current, nothing more happens.
3. **Update:** if it differs, download the new schema and missing files, verify hashes and the signature, and write a new snapshot in one IndexedDB transaction. A half-written snapshot is never used.
4. **Apply** according to the annotation `web.apply`: `"hot"` (swap modules now), `"reload"` (on the next start) or `"prompt"` (ask the user).
5. **Keep** the previous snapshot until the new one has booted successfully once, so a bad update can roll back.

Before running any module, the loader MUST check its bytes against the signed hash, whether they come from the snapshot store or the network. Modules MUST be single-file ES module bundles: they import shared libraries from `host` and fetch assets through the host API, which checks asset hashes, so they need no relative imports. The RECOMMENDED loader fetches the bytes, verifies the hash and imports them from a `blob:` URL, which needs `blob:` in `script-src`. An import map with `integrity` metadata MAY be used instead, but only after a runtime self-test shows the browser enforces it: importing a module whose integrity entry deliberately does not match must fail. A Service Worker SHOULD serve `/sparrow/mods/*` from the snapshot store so modules load offline; it is a cache, not a security boundary, because a hard reload bypasses it.

## 10. Sparrow Hub Profile

A hub is a Sparrow server that hosts and routes facets published by other peers, called **nodes**: plugin processes, app services, remote machines and other hubs. A node publishes its facets like any Sparrow peer publishes a schema. The hub combines them into the schema each session sees, authorizes every call, and forwards calls by rewriting envelopes, never payloads. Supporting a new plugin language therefore takes a Sparrow library, not a new server.

### 10.1 Roles

| Role | What it is |
| --- | --- |
| Hub | Hosts and routes facets, issues call contexts, authorizes every call. |
| Node | Publishes facets and handles calls to them: a plugin process, an app service, a remote machine, or another hub (section 10.8). |
| Client | Calls facets. Any facets it publishes belong to its own session (section 10.3). |

Every link is an ordinary Sparrow session. The profile defines no new message kinds, only what a hub does with the messages it receives.

### 10.2 Node links

A node publishes its facets in whichever schema it owns on the link, and the hub publishes the facets the node may call in the other:

| How the link starts | Binding | Sparrow client | Node's facets travel in |
| --- | --- | --- | --- |
| The node dials in | WebTransport or WebSocket | node | `Hello.client_schema` |
| The hub dials a configured node at its URL | WebTransport or WebSocket | hub | `Welcome.server_schema` |

- **Identity** comes from the link, never from message content. The side that opens a link presents `["link", credential]` in `Hello`, and the accepting side maps the credential to the configured node or hub it belongs to. Each configured node has exactly one link direction, so only a node configured to dial in has a dial-in credential; any other credential, or one of a disabled node, is refused with `GoAway(unauthenticated)`. When the hub dials, it checks that the SHA-256 of the node's SubjectPublicKeyInfo equals the configured pin, which replaces certificate-chain validation, and it always sends `Hello.client_schema`, empty if the node may call nothing yet. Which nodes exist, with their credentials, URLs and pins, is the hub's configuration (section 10.9); a node listed there is a configured node. A node MUST honour `principal` and `context` only on a link authenticated as its hub.
- **Node IDs** are stable, part of the hub's configuration, and match `[a-z0-9-]+(\.[a-z0-9-]+)*`.
- **Facet names belong to their node.** Every facet a node publishes MUST be named after the node: the name equals the node ID or starts with the node ID and a dot. The hub closes a session that breaks this with `GoAway(invalid_argument)`. Two nodes therefore can never claim the same facet. Node IDs `sparrow` and `sparrow.*` are reserved, and a hub names its own facets `sparrow.*`, so a node's facets never collide with the hub's.
- **One session per node.** A node that dials in again supersedes its existing session, so a reconnect and an upgrade are the same event.
- **New sessions.** Before the hub routes calls to any new node session, dialed or dial-in, it compares the session's facets with those it lists. If they differ, it first relays the change as in section 10.3 and waits until every session that sees it has acknowledged it; until then calls keep going to the old session if there is one, or wait as in section 10.7. When it switches, it routes new calls to the new session and sends `GoAway(going_away)` to any old one, whose running calls finish there. If the new facets are refused (section 10.3), any old session is kept.
- **Limits:** the 64 KiB limit on client schemas (section 5.4) does not apply between a hub and its nodes, in either direction; either side MAY set its own. When the configuration removes or disables a node, or changes its credential, link or `peer` setting, the hub ends the node's session at once, without the grace period of section 5.6: it ends every call running on it with `Error(unavailable)` toward each caller, ends every call the node made through the hub (sending `Cancel(unavailable)` downstream), sends `GoAway(unauthenticated)` to a node that dialed in or `GoAway(going_away)` to a node the hub dialed, and closes the transport. If the node is still configured and enabled, a dial-in node must dial in again and the hub redials a dialed node; until a new session is ready the node is offline (section 10.7). When the node link is at the node's `maxConcurrentCalls`, the hub answers further calls with `Error(resource_exhausted)` and does not queue them.

### 10.3 Composition

- **Schemas:** for each session the hub builds its schema from the hub's own facets and every node facet `visible` to the session's principal (section 10.4). A node's own facets are left out of the schema the hub sends to that node.
- **Facet IDs** are stable for the triple (node ID, facet name, major version) across sessions and restarts. A new major version is a new facet: one delta removes the old facet and adds the new one. A node moves its own facet to a new major version the same way, by removing it and adding it under a new node-local facet ID, or by reconnecting. A hub never reuses a facet ID: removing a node retires its facet IDs, and a node added again gets new ones. A disabled node's facets are hidden but keep their IDs. Within a major version a replacement MUST be compatible (section 6.6, rule 2); the hub verifies this and closes a node session whose update is not with `GoAway(schema_mismatch)`.
- **Interfaces:** the hub MUST verify a facet's `implements` claim (section 6.5) against the interface document, and treats a failed claim, or a claim to an interface it holds no document for, like an incompatible update. How a hub obtains interface documents is its configuration. Clients find every implementation of an interface by reading `implements` in their schema. For every interface with at least one visible implementation, the hub names one as the default in the top-level schema annotation `sparrow.defaults`, a map from interface hash (bytes) to facet ID; a caller with no reason to choose calls the default.
- **Client facets** are scoped to their session. The hub may call them itself, but never adds them to another session's schema. Nodes reach a client only through calls the client makes, such as responses and server streams.
- **Relaying updates:** when a node's `SchemaUpdate` changes what other sessions see, the hub sends each of them a `SchemaUpdate` and acks the node only once each has acked or been closed. Each downstream session gets 5 s to ack an update from a node, and 2 s to ack one the hub relays from a peer hub, before the hub closes it with `GoAway(schema_mismatch)`. A node gives its hub at least 10 s to ack, so a hub's limit runs out before its node's, and an update crossing a peer link still finishes within it. The same limits apply to the change a new node session brings (section 10.2). Until the node receives the ack it uses no new IDs (section 6.6, rule 1), so no session ever receives an ID it cannot decode.

### 10.4 Authorization

The profile defines two decisions and leaves the policy behind them to the hub:

- `visible(principal, facet)`: the facet appears in the principal's schema.
- `allowed(principal, facet, method)`: the principal may call the method. A method can only be allowed if its facet is visible.

Every call the hub receives is checked before it is handled or forwarded: each of its **acting principals** must be allowed, or the hub answers `Error(permission_denied)` itself.

| Call arrives from | Acting principals |
| --- | --- |
| A client session | The session's authenticated principal, such as `user:<id>` |
| A node, without `context` | `node:<id>` |
| A node, with a valid `context` | The context's principal and `node:<id>` |
| A peer hub (section 10.8) | `node:<peer-id>`, and `peer:<peer-id>/<principal>` if the call names a principal |

Because a node's own principal is always checked, a node can never do more than it may do itself, even while acting for an administrator. The hub derives principals only from the link and from contexts it issued, and ignores `principal` and `context` metadata everywhere else.

When a decision changes, the hub sends `SchemaUpdate` deltas to the sessions affected and ends calls that are no longer allowed: `Error(permission_denied)` toward the caller and `Cancel(permission_denied)` toward the node.

Principals are strings of the form `kind:id`, where `kind` is `user`, `group` or `node`, and `id` uses ASCII letters, digits and `.`, `_`, `-`, `@`. A peer principal is `peer:<hub-id>/` followed by a non-peer principal, where `<hub-id>` follows the node-ID grammar. How the hub stores grants and evaluates the two decisions is its own design; a common choice is grants of `view`, `use` and `manage` on facets. Methods may carry the hint annotation `"sparrow.level"` (`"use"` or `"manage"`) to help such a policy.

### 10.5 Forwarding

When a call arrives for a node's facet, the hub:

1. Authorizes it (section 10.4).
2. Opens a call on the node's link with a new call ID, the node's own facet ID, and the same method ID, metadata and input. It sets `context` (towards a node that is not a peer hub) and `principal` (section 10.6), replacing any values the caller sent. It lowers `deadline` by the time already spent, including any wait for the node (section 10.7), and may set `credit` to any value no higher than the caller's, or than the default for the caller's stream if the caller sent none.
3. Relays every later message of the call except `Credit`, changing only the call ID.

The rules for the two calls, caller to hub and hub to node:

- **Payloads** are copied byte for byte: every element of every message except the call ID, the facet ID and a `Request`'s metadata, which the hub re-encodes with its changes. The only other exception is `Bytes`, which the hub MAY split or join into different chunks, keeping each token's data and its final `fin` unchanged.
- **Streams and credit** are chosen per hop (sections 4.3 and 7.4). The hub grants credit to a sender only as it forwards that sender's data, so per call and direction it holds at most the credit it granted plus one message.
- **Size:** if a message is larger than the next hop's `maxMessageSize`, the hub ends both calls: `Error(message_too_large)` toward the caller and `Cancel(message_too_large)` toward the node.
- **Endings:** the method flags, identical on both hops, decide how each half ends. If either link drops, the hub ends the other call: `Error(unavailable)` toward the caller and `Cancel(unavailable)` toward the node. When the node's final message arrives, the hub forwards it and, if the caller's half is still open, sends `End` to the node itself; it then forgets both calls and relays nothing more for them.
- **No retries:** the hub never retries a call by itself; retrying is the caller's decision (section 5.2).
- **Notifications** are relayed best-effort, with call ID 0 on both hops and no `context`, since no call stays open to bind one to. The hub still sets `principal`, and a node handling a notification calls the hub as itself.

A call from a node to any facet is handled the same way: authorized, then answered by the hub or forwarded to the node that owns the facet.

### 10.6 Call context

- **`context`** (metadata sigil 36) holds opaque bytes the hub issues for every call it forwards to a node: at least 128 random bits, mapped on the hub to the call and its principal. **`principal`** (sigil 37) names that principal, so the node can make its own finer decisions, such as access to single records.
- While handling the call, the node includes the context in its own calls to act for the same principal (section 10.4).
- A context is valid only on the link it was issued on, while its call is open and for 2 s after the call ends, so nested calls already sent are not lost to message reordering. It is never valid after the call's deadline.
- A call with an unknown or expired context fails with `Error(permission_denied)`. It never falls back to the node's own principal.
- When the grace period ends, the hub ends every call still open that carries the context: it answers the node with `Error(permission_denied)` and sends `Cancel` for the forwarded call.

### 10.7 Offline nodes

The hub lists the **last known facets** of every enabled configured node, the facets it last published, whether or not it is connected, so caches stay valid; a node never seen has none yet. Removing a node discards them, and a disabled node's are hidden (section 10.3). A call to a facet ID of a removed or disabled node fails with `Error(unimplemented)`.

- The hub keeps a session open to every enabled node it dials: it dials when the node is configured or enabled, or the hub starts, and after a session ends it redials with exponential backoff and jitter, as a client reconnects (section 5.6).
- A call to a facet of a node that is not connected waits until that node's session is ready (its `Ready`, or the hub's own `Ready` when the hub dialed), for at most a connect timeout (RECOMMENDED 10 s), and then fails with `Error(unavailable)`. For a node the hub dials, a call that starts waiting makes the hub dial at once unless an attempt is already under way (from the dial until the attempt fails or the session it produced ends). If an attempt fails while calls still wait, the hub dials again promptly, without its usual backoff. A call whose deadline passes while it waits fails with `Error(deadline_exceeded)`, and one the caller cancels is never forwarded. Calls waiting for a node that is removed or disabled fail with `Error(unimplemented)`. Notifications to a node that is not connected are dropped.
- A node that comes back with a facet that is not a compatible successor of its last known version, such as an older minor release, is refused (section 10.3) until it publishes a compatible one or moves the facet to a new major version.

### 10.8 Federation

A peer hub is a node of another hub. As for every node, exactly one side opens the link (section 10.2), and each side publishes the facets it exports in the schema it owns. On top of the node rules:

- **Exports** are the facets `visible` to `node:<peer-id>`.
- **Names:** the importing hub lists each imported facet as `<peer-id>/<name>`, instead of requiring the node-ID prefix. `/` cannot occur in node IDs, so imported names never collide with local ones. Names are not hashed, so facet hashes stay the same.
- **Principals:** a call from a peer may name the principal it acts for in `principal`. The receiving hub checks both `node:<peer-id>` and `peer:<peer-id>/<principal>` (section 10.4). It refuses with `Error(permission_denied)` a call whose named principal already starts with `peer:`, and a call from a peer that carries a `context`. A hub never forwards a call acting for a `peer:` principal to another peer; such a call fails with `Error(permission_denied)`.
- **No re-export:** a hub MUST NOT export a facet it imported from a peer. With the previous rule, every call crosses at most one peer link, so routing loops and identity chains cannot occur.
- A failed peer link behaves like an offline node.

### 10.9 Administration

Administering a hub is a facet like any other. An operator or a controlling application calls it over an ordinary session and is authorized like any caller, and the hub applies changes through the mechanisms above: schema deltas and ending node sessions (section 10.2). A hub never replaces its own program this way; upgrading the hub is the job of whatever runs it. The standard administration interface, `sparrow.hub.admin`, is specified in the companion document *Sparrow Hub Administration*, so any controller can drive any hub that implements it.

### 10.10 Out of scope

Facilities such as storage, jobs, blobs, secrets and events are ordinary facets, provided by the hub or by nodes. Standard contracts for them are interfaces published separately from this spec, never protocol sections. High availability, spreading one facet over several nodes, and resumable streams are implementation or application concerns. A hub never installs, starts or supervises nodes. A separate system (an orchestrator, a service manager, a person) provisions and runs them, and registers each with the hub: for a node that dials in, the credential it handed the node; for a node the hub dials, its URL and pin and the credential the hub will present to it. The administration interface standardizes only this registration. The credentials a hub keeps for its own links are part of its configuration, not a secrets facility. An application that needs to resume passes a cursor in its own methods.

## 11. Security considerations

The biggest risk is code push: a compromised server or plugin can run code in every client unless modules are signed (section 9.5). The rest of the risks are the usual ones for a binary protocol that parses untrusted input.

| Threat | Mitigation |
| --- | --- |
| Malicious or compromised module reaches clients | Per-module signatures chained to root keys in the client build, rollback protection, revocation, and a hash check before every load (section 9.5). A compromised origin serving the shell is out of scope. |
| One plugin abusing another | Out of scope for the protocol. Hosts SHOULD give each plugin its own service namespace and check permissions per method. Clients MAY load untrusted modules in a sandboxed iframe or worker instead of the main window. |
| Stolen ticket | 60 s presentation window, single use, bound to one edge instance; refresh only for the same user and login session. The RPC session ends at `sexp`. |
| Cross-site connection with the user's cookies | `/connect` requires a JSON body and checks `Origin`. WebSocket servers MUST check `Origin` too. WebTransport sends no cookies. |
| Memory exhaustion from large messages | `maxMessageSize` enforced before buffering; nesting depth limit of 64; collection lengths checked against remaining bytes before allocating; buffered data per call bounded by credit (section 7.4). |
| Too many calls or streams | `maxConcurrentCalls`; extra leased streams reset with resource_exhausted; notifications are best-effort and a flooding peer is disconnected. |
| Schema bomb (huge or deeply nested schema) | Clients SHOULD cap server schemas at 8 MiB and 32 levels of type nesting. Servers cap client schemas at 64 KiB, except between a hub and its nodes (section 10.2), and parse them only after authentication. |
| Peer sending IDs for methods it should not see | IDs are not secrets. Authorization MUST be checked on every call, never by hiding a method from the schema alone. |
| Downgrade to WebSocket | Both transports use TLS. The protocol is identical on both, so a downgrade costs performance but not security. |
| Tracking via schema hash | A per-user schema hash can identify a user across sessions on a shared device. Snapshots SHOULD be cleared on logout. |
| A node acting beyond its rights while handling a privileged user's call | Calls made with a context are checked against both the user and the node (section 10.4). Contexts are random, bound to one link and one call, and expire 2 s after it (section 10.6). |
| A node taking over another plugin's facet or a client-wide setting | Facet names must start with the node ID (section 10.2); facets may carry only their own web.modules, named after the facet (section 9.4). |
| Spoofed principals and identity chains across hubs | Hubs derive principals from links and their own contexts only; peer principals are prefixed and may not nest, and nothing imported is re-exported (section 10.8). |
| Someone other than the hub connecting to a node or service and forging principal metadata | The hub authenticates to every service it dials, and nodes honour principal and context only on an authenticated hub link (section 10.2). |
| Replaying a link credential or impersonating a node | Each node has one link direction; the hub verifies a dialed node's key pin on every connection; credentials named in the hub's configuration are pairwise distinct, so none presented to one party is accepted from another (section 10.2, Hub Administration section 3). |

Decoders MUST treat every field as untrusted, including values from a peer that passed authentication. Go and TypeScript reference implementations SHOULD be fuzzed (Go native fuzzing, and a property-based tester for TypeScript) against the decoder and the schema loader.

## 12. Implementation notes and decisions

The draft is implementable with existing libraries on both sides. The main unknown is whether a schema-driven CBOR decoder in JavaScript beats `JSON.parse` on real payloads, so benchmark that first.

### 12.1 Go reference server

- Transport: `quic-go` with `webtransport-go` for HTTP/3; `coder/websocket` (or `gorilla/websocket`) for the fallback. Both adapters implement one `Stream` interface.
- Encoding: `fxamacker/cbor` with preferred serialization for messages and Core Deterministic Encoding for schemas and signed data.
- Schema building: plugins register services into a registry, from Go types with struct tags (`sparrow:"1,optional"`) or hand-written definitions. The registry persists its name-to-ID table so IDs stay stable across restarts, and emits a `SchemaUpdate` delta when a plugin loads or unloads.
- Dispatch: one reader goroutine per stream routes messages by call ID to one goroutine per active call; `context.Context` carries deadline, cancellation and auth identity.

### 12.2 Browser client

- Encoding: `cbor-x` is a fast choice for messages, but only with record extensions and undefined disabled, and with 64-bit integers outside the safe range decoded as BigInt. It does not sort map keys, so schemas and signatures also need a canonical encoder. Measure it against `JSON.parse` on string-heavy payloads.
- Decoders: build lookup-table decoders from the schema when it loads. Generating code with `new Function` is faster but needs `unsafe-eval` in the CSP; keep it optional.
- Transport: try `WebTransport` first with a timeout of about 3 s, then `WebSocket`. Remember the winner per origin.
- Solid integration: expose server streams as signals or stores, and calls as async functions. Keep this binding outside the core library so the protocol stays framework-neutral.

### 12.3 Decisions on earlier questions

- **ID assignment:** the schema owner assigns IDs and keeps them stable (sections 6.6 and 10.3). IDs derived from name hashes would be larger and could collide.
- **Session resumption:** not part of the protocol. A reconnect starts a new session; applications resume with cursors in their own methods (section 10.10).
- **Datagrams:** the core defines none. A profile may define them behind the `datagrams` capability (section 4.5).
- **Compression:** none. Numeric IDs and positional structs already remove most redundancy; a later profile may negotiate compression through `caps`.
- **Module isolation:** every accepted module runs in the client's own realm (section 9.5). Running untrusted publishers' code in sandboxed iframes or workers is a host API matter outside this spec.
- **Host API:** its surface and versioning belong to the client product that defines it; the protocol only carries `hostApi` ranges (section 9.4).
- **Several schemas per session:** not needed. A session has one schema per peer, and facets provide the modularity (section 6).
