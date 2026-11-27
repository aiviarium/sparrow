# Sparrow RPC — Core Protocol Specification (Draft)

Nov 26, 2026 · Christoph Feuerer

> Snapshot of the live draft, revision 108, exported for this repository. The live document is the source of truth; diagrams are not included here.

## 1. Overview

Sparrow RPC is a binary, bidirectional, streaming RPC protocol. At session start the server sends a schema describing its services and types. After that, every message refers to methods, types and enum values by compact numeric IDs, and a client that understands the schema can call services it was never compiled against.

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
| Schema hash | SHA-256 of a schema's canonical encoding; identifies a schema across sessions. |
| Epoch | A counter that goes up by one each time the schema changes within a session. |
| TypeId | Numeric ID of a type within a session. |
| MethodId | Numeric ID of a method within a session. |
| Sigil | Numeric ID of a named constant: an enum value, error code or well-known string. |
| Call | One RPC invocation and all its messages. Identified by a call ID; runs on the shared lane or on a leased stream. |
| Shared lane | The one stream every session has, carrying the handshake, session messages and small multiplexed calls. Other calls lease a stream from a pool (section 4). |
| Profile | A companion spec that binds the core to a concrete environment (for example the Sparrow Web Profile, section 9). |

## 2. Architecture

The protocol has four core layers on top of two interchangeable transport bindings. Profiles add environment-specific pieces on top without changing the core.

> *Diagram (not included in this snapshot): protocol layers, 1 profile, 4 core layers, 2 transport bindings.*

The dashed box is replaceable: a server-to-server deployment could use an mTLS profile instead, and every layer below it stays the same.

## 3. Encoding

Every message is a single CBOR data item (RFC 8949) in preferred serialization. Schemas and anything hashed or signed also use Core Deterministic Encoding, so Go and JavaScript produce identical bytes. The only non-CBOR bytes on the wire are length prefixes and the one-byte stream header (section 4.1).

### 3.1 Allowed CBOR

| CBOR feature | Rule |
| --- | --- |
| Integers | MUST use the shortest form. |
| Floats | SHOULD use the shortest width that keeps the value exact (RFC 8949, section 4.1); canonical data (section 3.2) MUST. Decoders MUST accept any float width, and MUST accept an integer where a float type is declared, because JavaScript cannot tell 3 from 3.0. |
| Byte strings, text strings | MUST be definite length. Text MUST be valid UTF-8. |
| Arrays, maps | MUST be definite length. Map keys MUST be unique. |
| Tags | Only the tags in section 3.5. An unknown tag is a decode error. |
| Simple values | `false`, `true`, `null` only. `undefined` MUST NOT appear. |
| Nesting | Decoders MUST reject values nested deeper than 64 levels. |

### 3.2 Canonical encoding

Schema documents (section 6.6), signed module data (section 9.5) and any other value that is hashed or signed MUST use Core Deterministic Encoding (RFC 8949, section 4.2.1): the rules above plus map keys sorted by the bytewise order of their encoded form. Both sides therefore need a canonical encoder. Ordinary messages need not sort map keys, since structs are arrays and maps are rare.

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

- **Struct:** a CBOR array where element i holds the field with tag i. Tags start at 0 and SHOULD be dense. A removed tag or an absent optional field is encoded as `null`, so later fields never shift. Trailing `null`s MUST be omitted.
- **Sparse struct:** a struct declared `sparse` is encoded as a map from field tag (uint) to value, with absent fields left out. Use it for types with many optional fields that are usually empty.
- **Enum:** the sigil as a uint.
- **Union:** `[variant_tag: uint, value]`.
- **List:** a CBOR array. **Map:** a CBOR map with keys of the declared key type.
- **Bytes:** a byte string. Values larger than the session's `maxInlineBytes` (default 64 KiB) SHOULD use a byte stream instead (section 7.8).
- **Any:** `[type_id: uint, value]`, for a field whose type is only known at run time.

A decoder MUST skip array elements beyond the fields it knows and map entries whose tag it does not know. This rule lets a schema add fields without breaking older peers (section 6.7).

### 3.5 Tags used

| Tag | Meaning |
| --- | --- |
| 1 | Epoch time (timestamp type). |
| 37 | UUID, 16-byte byte string. |
| 55799 | Self-described CBOR. MAY prefix a stored schema file; MUST NOT appear on the wire. |

The core spec defines no other tags. Profiles MAY register more.

## 4. Streams and transport bindings

A session uses one **shared lane** for control messages and small, long-lived calls, plus a pool of **leased streams** that calls take one at a time and give back. The number of streams follows peak concurrency rather than the number of calls, and large transfers do not share a stream with other calls. Servers MUST support both bindings; clients MUST support WebTransport and SHOULD support WebSocket.

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
- After the header, each message is preceded by its length as a QUIC variable-length integer (RFC 9000, section 16). Receivers MUST reject a message longer than `maxMessageSize`.
- All messages of a call travel on the stream that carried its `Request`, in both directions. A call's messages are therefore ordered; separate calls have no ordering relation.
- Closing or resetting the shared lane ends the session.

### 4.2 Leasing

1. **Ownership.** A peer leases only streams it opened. The client's pool carries client-to-server calls and the server's pool, if it has one, carries server-to-client calls, so two peers can never claim the same idle stream.
2. **Start.** The caller leases an idle stream by sending a `Request` on it. If none is idle and fewer than the peer's `maxStreams` are open, it opens a new one. A peer that receives more leased streams than it allowed resets the extra ones with `resource_exhausted`. The opener counts a stream as open until both directions have finished or been reset, and the peer closes its direction only after it has seen the opener close, so both sides always count the same streams.
3. **Release.** The call ends as defined in section 7.1, after both peers have finished their halves, including any byte data. The stream is then idle and back in the pool. No message marks the release: each direction is ordered, so both peers see the same boundary.
4. **Shrink.** The opener SHOULD close streams that stay idle for about 30 s, by finishing its direction, and SHOULD keep one or two idle streams to avoid reopening. The peer then finishes its own direction.
5. **Abort.** Resetting a leased stream fails the call on it and removes the stream from the pool. Peers do this only when a `Cancel` goes unanswered (section 7.5) or the stream is broken.
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

### 4.7 Transport selection

Transport choice is the client's job. A client SHOULD try WebTransport first, fall back to WebSocket after a short timeout (a value around 3 s is RECOMMENDED), and MAY remember the result per origin. Endpoint URLs come from the profile (for the web profile, from `/connect`, section 9.1).

## 5. Session lifecycle

A session is three shared-lane messages (`Hello`, `Welcome`, `Ready`) followed by any number of calls. Authentication methods and endpoint discovery happen before the session, in a profile; the core only carries an opaque credential in `Hello`.

### 5.1 Before the session (profile)

The core spec does not define how a client gets its endpoint URLs or credential. The Sparrow Web Profile does this with an HTTP `POST /connect` that returns a short-lived ticket and the endpoints (section 9.1). Other profiles MAY use mTLS, a static token, or no authentication.

### 5.2 Handshake

1. The client opens the transport and the shared lane, and sends `Hello`.
2. The server checks the protocol version and credential, then sends `Welcome` with its schema offer.
3. The client loads the schema (from cache, delta, inline or out of band) and sends `Ready`.
4. The client MAY start calls immediately after sending `Ready`, without waiting for a reply.

> *Diagram (not included in this snapshot): session start with the web profile, 1 HTTP request, 3 handshake messages.*

The first two messages belong to the web profile; the core begins at the transport. With a cached schema, `Hello`, `Ready` and the first calls go out together.

Rules for the server:

- `Hello` MUST arrive within 10 s of the transport opening, or the server closes the connection.
- The client MUST NOT open leased streams before `Welcome` arrives. Until the credential is verified, the server buffers at most 64 KiB of shared-lane data after `Hello` and closes the session if the client sends more, so unauthenticated peers cannot make it hold much memory. On a failed check it closes the session with `unauthenticated`.
- The server MUST NOT dispatch a call before it has received `Ready`. Calls sent on the shared lane after `Ready` arrive in order. Calls on leased streams can arrive first; the server holds them until `Ready` arrives, up to `maxConcurrentCalls`.

If a session that did not start optimistically closes before `Welcome` arrives, no call was dispatched, and the client MAY retry all of them. In every other case, calls still open at the close fail with `unavailable`; the client retries only those whose method is flagged idempotent.

### 5.3 Optimistic start

A client with a cached schema can send `Hello`, `Ready` and its first calls in one flight, saving a round trip:

- It sets `Hello.optimistic = true`, puts the cached hash in both `Hello.known_schema` and `Ready`, and lists exactly one protocol version.
- Until `Welcome` arrives, it sends only on the shared lane, at most 64 KiB after `Hello`, and stays within the default `params`.
- It SHOULD send only calls to methods flagged idempotent this way: if the connection drops, the client cannot tell whether they ran.
- If the server's schema hash differs, the server MUST NOT dispatch any call from the session. It sends `Welcome`, so the client can update its cache, then `GoAway(schema_mismatch)` with `retry_after_ms` 0, and closes. The client reconnects and resends its calls; none of them ran.
- If the server's limits are below the defaults, it does the same with `GoAway(failed_precondition)`. The client caches `Welcome.params` next to the schema and does not start optimistically against a server whose cached limits are below the defaults.
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

Each peer's `params` are the limits it imposes on the other, like QUIC transport parameters: `Hello.params` bind the server and `Welcome.params` bind the client. A missing key means the default. `maxStreams` defaults to 16 in `Welcome` (streams the client may open) and 4 in `Hello` (streams the server may open). Both peers use the smaller `idleTimeoutMs`.

The client schema is always sent inline and is small for typical clients. The server parses it only after verifying the credential, and MAY reject one larger than 64 KiB or nested deeper than 32 levels with `GoAway(invalid_argument)`.

If no version matches, the server sends `GoAway(unsupported_version)` with its versions in the `versions` field. If the credential is rejected, it sends `GoAway(unauthenticated)`.

### 5.5 Control messages

| Kind | Message | Direction | Purpose |
| --- | --- | --- | --- |
| 3 | `SchemaUpdate [3, epoch, hash, delta]` | either | The sender's own schema changed (section 6.6). |
| 4 | `SchemaAck [4, epoch]` | either | The sender has applied the peer's schema up to this epoch. |
| 5 | `AuthRefresh [5, auth]` | C→S | Present a fresh credential for the same principal. |
| 6 | `AuthStatus [6, status, expires_at / null]` | S→C | Result of a refresh, or a warning that the session credential expires soon. |
| 7 | `Ping [7, nonce]` | either | Liveness check. |
| 8 | `Pong [8, nonce]` | either | Reply to `Ping`. |
| 9 | `GoAway [9, status, reason: tstr, retry_after_ms / null, versions: [* uint] / null]` | either | Graceful shutdown (section 5.6). This layout is fixed across all protocol versions. |

Authentication during a session:

- **Expiry** is defined by the profile, not by the credential's own lifetime. For the web profile it is the end of the login session (`sexp`, section 9.2); the ticket's short lifetime only limits when it can be presented.
- The server SHOULD send `AuthStatus` at least 60 s before expiry. At expiry it closes the session with `GoAway(unauthenticated)`.
- `AuthRefresh` MUST carry a credential for the same principal and login session as the original one. Otherwise the server closes the session with `GoAway(unauthenticated)`, so a session can never switch users.
- When the principal's permissions change, the server ends open calls that are no longer allowed with `Error(permission_denied)`, and sends a `SchemaUpdate` if the visible schema changes.

A peer SHOULD send `Ping` when the shared lane has been idle for half of `idleTimeoutMs`. A peer that receives nothing for `idleTimeoutMs` closes the session.

### 5.6 Shutdown

`GoAway` starts a graceful shutdown. Once it has been sent or received, neither peer opens new calls; a `Request` that crosses it is answered with `Error(going_away)`. Calls already running continue until they finish or a grace period (RECOMMENDED 30 s) ends, and then the transport is closed. `retry_after_ms` tells the client when to reconnect, which lets a server drain before a deploy.

The transport close carries the status too: WebTransport's session close code is the status code with the reason (at most 1024 bytes), and WebSocket's close code is 4000 plus the status code. An abrupt close with no `GoAway` is treated as `unavailable`. The client SHOULD reconnect with exponential backoff and jitter, starting around 500 ms and capped around 30 s.

## 6. Schema model

A schema is a CBOR document listing a peer's types, services, methods and sigils, each with a numeric ID assigned by that peer. IDs are part of the schema, so a schema hash fixes every ID: a client with a cached schema can encode calls before the session starts.

### 6.1 Ownership and ID scope

- Each peer publishes its own schema: the server in `Welcome`, the client (optionally) in `Hello`.
- **All IDs in a call belong to the callee's schema.** A call from client to server uses server IDs for the method, the request and the response; a call from server to client uses client IDs.
- There are four ID spaces: TypeIds, MethodIds, Sigils and ServiceIds. IDs 0–63 in each are reserved:

| Space | 0–31 | 32–63 |
| --- | --- | --- |
| TypeIds | Built-in types (section 6.3) | Meta-schema types |
| MethodIds | Core methods (none yet) | Profile methods (section 9.4) |
| Sigils | Status codes (section 8) | 32–47 core metadata keys (section 7.2), 48–63 reserved |
| ServiceIds | Reserved | Reserved |

- MethodIds are unique across all services, so a call names its method with one integer.
- Within a session an ID MUST NOT be reused for a different definition, even after it is retired.

### 6.2 Document layout

```
schema = [
  format:     1,
  name:       tstr,              ; e.g. "sparrow.host"
  version:    tstr,              ; informative, e.g. "2026.11.3"
  types:      [* type-def],
  services:   [* service-def],
  sigils:     [* sigil-def],
  annotations: annotations
]

annotations = { * tstr => any }  ; profile-defined metadata; unknown keys MUST be ignored
```

The meta-schema (the schema describing `schema` itself) is fixed by this specification and never transmitted. It occupies TypeIds 32–63, which lets a peer send schema fragments as ordinary typed values.

### 6.3 Types

Built-in types:

| TypeId | Name | CBOR encoding |
| --- | --- | --- |
| 0 | `unit` | `null` |
| 1 | `bool` | `true` / `false` |
| 2 | `int` | integer, signed 64-bit range |
| 3 | `uint` | unsigned integer, 64-bit range |
| 4 | `float32` | float32 |
| 5 | `float64` | float64 |
| 6 | `string` | text string |
| 7 | `bytes` | byte string |
| 8 | `timestamp` | tag 1 + integer or float seconds |
| 9 | `uuid` | tag 37 + 16-byte byte string |
| 10 | `any` | `[type_id, value]` |
| 11 | `symbol` | sigil (uint) or text string |

`symbol` is for strings that repeat often (event names, CSS classes, keys). The encoder sends the sigil when the string has one and the text otherwise.

Type references compose built-in and user types:

```
type-ref = uint                       ; a TypeId
         / [0, type-ref]              ; list
         / [1, key: type-ref, value: type-ref]  ; map
         / [2, type-ref]              ; optional (nullable)
         / [3, type-ref]              ; stream of values (method params/results only)
         / [4]                        ; byte stream (inline at top level, by token when nested; section 7.8)
```

User-defined types:

```
type-def =
    [0, id, name, fields: [* field], flags: uint, annotations]   ; struct (flag 0x1 = sparse)
  / [1, id, name, values: [* sigil-id], annotations]              ; enum
  / [2, id, name, variants: [* variant], annotations]             ; union
  / [3, id, name, target: type-ref, annotations]                  ; alias (named, same encoding)

field   = [tag: uint, name: tstr, type: type-ref, flags: uint, annotations]  ; flag 0x1 optional, 0x2 deprecated
variant = [tag: uint, name: tstr, type: type-ref, annotations]
id      = uint
name    = tstr   ; fully qualified, dot-separated, e.g. "sparrow.ui.PanelConfig"
```

### 6.4 Services and methods

```
service-def = [id: uint, name: tstr, methods: [* method-def], annotations]

method-def = [
  id:      uint,          ; MethodId, unique across services
  name:    tstr,          ; short name, e.g. "openPanel"
  input:   type-ref,      ; [3, T] = client stream, [4] = byte stream
  output:  type-ref,      ; [3, T] = server stream, [4] = byte stream
  errors:  [* sigil-id],  ; error codes this method may return, beyond the core set
  flags:   uint,          ; 0x1 idempotent, 0x2 notification, 0x4 shared, 0x8 input ends with End, 0x10 output ends with End
  annotations
]
```

The call shape follows from the types: plain input and output is unary, `[3, T]` on either side makes that side a stream. Both sides streaming is a bidi call.

Flags 0x8 and 0x10 say whether each half of a call is finished by `End` (section 7.1). The owner MUST set 0x8 when the input is a stream or contains `[4]` anywhere, and 0x10 likewise for the output; it MAY set them in other cases, which leaves room to add byte fields later. `[4]` MUST NOT appear inside an `any` value. A method's `input`, `output` and flags 0x2, 0x8 and 0x10 never change once defined; only `errors`, `annotations` and flags 0x1 and 0x4 may change in a compatible replace.

### 6.5 Sigils

```
sigil-def = [id: uint, name: tstr, kind: uint, annotations]  ; kind: 0 enum value, 1 error code, 2 symbol
```

Every enum value, error code and interned symbol is a sigil. An enum lists the sigils it allows. Sending a sigil is one small integer where JSON-RPC would send a string.

### 6.6 Hashing, epochs and deltas

- **Canonical form:** before hashing, `types`, `services` and `sigils` are each sorted by ID, methods within a service are sorted by ID, fields and variants by tag, enum values and method errors by sigil ID, retired definitions are removed, and the result is encoded with Core Deterministic Encoding (section 3.2). Every other array, including those inside annotations, keeps the order it was sent in, since deltas only ever replace such arrays whole.
- **Hash:** `0x01 || SHA-256(canonical schema)`, 33 bytes. The leading byte names the algorithm so it can change later.
- **Epoch:** each schema has its own epoch, starting at 0 when the session starts and going up by one with each `SchemaUpdate` from its owner. `SchemaAck(N)` acknowledges every epoch up to N. A peer only ever acknowledges the other peer's schema, so an ack is never ambiguous.
- **Delta:** a list of operations applied in order, after which the schema is put back into canonical form:

```
delta = [* delta-op]
delta-op =
    [0, type-def]                  ; add or compatibly replace a type
  / [1, service-def]               ; add or compatibly replace a service
  / [2, sigil-def]                 ; add a sigil
  / [3, space: uint, id: uint]     ; retire an ID (space: 0 type, 1 method, 2 sigil, 3 service)
  / [4, annotations]               ; replace top-level annotations
  / [5, version: tstr]             ; replace the version string
```

Rules for live updates:

1. The owner MUST NOT send any message that uses an ID added in epoch N, whether a request, response, item or error detail, until it has received `SchemaAck` for N. Such messages wait in a queue. If the ack has not arrived within 10 s, the owner closes the session with GoAway(schema_mismatch). The receiver MUST send SchemaAck as soon as its ID tables are updated and the hash checks out; downloading modules, writing snapshots and applying web.apply happen afterwards and never delay the ack.
2. The owner stops using a retired ID at once. A retired method rejects new calls with `unimplemented`; calls already running finish normally. A delta that leaves a reference to a retired or unknown ID is invalid and handled like a hash mismatch (rule 3). Receivers keep retired definitions locally, outside the hashed form, until the calls that use them have ended.
3. After applying a delta, the receiver MUST compute the new hash and compare it with the one in `SchemaUpdate`. On a mismatch it closes the session with `GoAway(schema_mismatch)`, and the next connection fetches the full schema.

Servers SHOULD keep IDs stable across restarts, rebuilds and every edge server of a deployment, for example by storing the name-to-ID table centrally. Edges that assign IDs differently produce different hashes for the same plugins, and clients would lose their cache each time they reach another edge. A server sends a delta only if it still has the schema the client named; otherwise it sends the full schema. Reference implementations MUST publish test vectors (schemas, deltas and their hashes) so Go and JavaScript can confirm they agree.

### 6.7 Evolution rules

| Change | Allowed in place? | Notes |
| --- | --- | --- |
| Add an optional struct field with a new tag | Yes | Older readers skip it. |
| Add an enum value or union variant | Yes | Readers MUST handle unknown values (map to an `unknown` case). |
| Add a method, service, type or sigil | Yes | New IDs. |
| Change annotations | Yes |  |
| Mark a field deprecated | Yes | It stays on the wire until removed. |
| Remove a field | Yes, if optional | Its slot is sent as null and the tag MUST NOT be reused. |
| Change a field's type, make optional required, reuse a tag | No | Define a new type or field with a new ID or tag. |
| Rename | No | Names are part of the hash; treat as remove + add. |
| Change a method's input, output, or flags 0x2, 0x8, 0x10 | No | Define a new method. |
| Make [4] reachable from a method half whose End flag is not set | No | Peers would disagree on how the call ends. Set the flag when defining the method if byte fields may come later. |

## 7. RPC messages

Every call has a call ID chosen by the caller, whether it runs on the shared lane or a leased stream. Each side of a call finishes its half with a defined message, and the call ends when both halves are finished. Cancellation is a message rather than a stream reset, so a leased stream survives it and returns to the pool.

### 7.1 Call IDs and call lifetime

- The caller assigns the ID. Client IDs are even and server IDs are odd, so they never collide. ID 0 is reserved for notifications, which get no reply.
- A sender's IDs, apart from 0, MUST strictly increase. Receivers track the IDs of open calls. A `Request` whose ID belongs to an open call, or that arrives on a leased stream whose call has not ended, is a `protocol_error`. Receivers need not detect reuse of ended IDs, which would take unbounded memory.
- The **caller's half** is finished by the `Request` itself, unless the method has flag 0x8 (*input ends with End*, section 6.4); then by `End` or `Cancel`.
- The **callee's half** is finished by `Response`, unless the method has flag 0x10 (*output ends with End*); then by `End`. `Error` finishes it at any time. These flags are fixed for the life of the method, so both peers always agree whether `End` is coming, even while the schema changes.
- `End`, `Error` and `Cancel` also close every byte token their sender opened in the call. Data not yet marked `fin` is cut off, and the receiver discards any later `Bytes` for the call. A referenced token that was cut off or never sent reaches the application as data_loss.
- The call **ends** when both halves are finished. Both peers then forget its ID, and a leased stream it ran on is idle again.
- If the callee finishes first while input is still arriving, it MUST keep reading and discarding that input until the caller's half is finished. When the callee's final message arrives, the caller MUST send `End` (or `Cancel`) next, with no further `Item` or `Bytes`.
- Messages for an unknown or ended call ID are ignored.

### 7.2 Call messages

| Kind | Message | Sent by | Layout |
| --- | --- | --- | --- |
| 16 | `Request` | caller | `[16, call_id, method_id, metadata, input]` |
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
| 33 | `trace` | bytes | W3C `traceparent` in binary form. |
| 34 | `(reserved)` | — | Reserved. (Rule 1 of section 6.6 already prevents a peer from using IDs its partner has not acknowledged.) |
| 35 | `credit` | uint | Initial credit in bytes the caller grants for the callee's half, replacing the default. |

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

- **Unit:** bytes. Each `Item` and `Progress` message counts the length of its CBOR data item, excluding the length prefix (so the count is the same over WebSocket), and each `Bytes` message counts the length of `data`. `Request`, `Response`, `Headers`, `End`, `Error`, `Cancel` and `Credit` do not count; each is bounded by `maxMessageSize` and occurs at most once per call or carries no data.
- **Initial credit:** each direction of a call starts with `sharedCredit` (default 64 KiB) on the shared lane or `leaseCredit` (default 1 MiB) on a leased stream. The caller MAY set the callee's initial credit with the `credit` metadata key.
- **Granting more:** the receiver sends `Credit [24, call_id, amount]`; grants add up. It SHOULD grant more once about half of its credit is used.
- **Sending:** a sender MAY send a message whenever its remaining credit is above zero, even if the message is larger; the credit then goes negative until more is granted. This guarantees progress for messages bigger than the window. A sender with zero or negative credit waits.
- **Violation:** a peer that sends with no credit left has broken the protocol for that call. The callee answers `Error(protocol_error)` and the caller sends `Cancel(protocol_error)`.
- **Memory bound:** a receiver buffers at most its granted credit plus one `maxMessageSize` per call direction, so a session needs at most about `maxConcurrentCalls` × (credit + `maxMessageSize`) for buffered data, plus one Request and one Headers per call, each up to maxMessageSize. Receivers SHOULD grow the credit they grant toward the bandwidth-delay product, so the 64 KiB shared-lane default does not cap throughput on fast links.

### 7.5 Cancellation and deadlines

- The caller cancels with `Cancel(status)`, normally `cancelled`. `Cancel` finishes the caller's half and closes its byte tokens.
- The callee SHOULD stop work and MUST answer with a final message, normally `Error(cancelled)`, unless it has already sent one. The call then ends as in section 7.1, so a leased stream returns to the pool in a clean state.
- If no final message arrives within about 5 s, the caller gives up. On a leased stream it resets the stream (section 4.2), which also tells the callee. On the shared lane it keeps counting the call toward `maxConcurrentCalls` until the final message arrives; if none arrives within 30 s, the peer is broken and the caller closes the session with `GoAway(protocol_error)`.
- When a `deadline` passes, the callee sends `Error(deadline_exceeded)`. The caller MAY also send `Cancel(deadline_exceeded)` when its own timer fires.

### 7.6 Concurrency

- A peer MUST NOT have more than `maxConcurrentCalls` calls open as caller, counting the shared lane and leased streams together. The callee answers excess requests with `Error(resource_exhausted)`. Notifications do not count.
- Messages of one call are ordered because they share a stream. Calls are independent of each other.

### 7.7 Example

A unary call with call ID 2 to method 1042 (`sparrow.ui.Panels.open`) with input struct `["settings", true]`, on an idle leased stream:

```
; caller -> callee
12                                  ; message length 18 (varint)
85                                  ; array(5)
   10                               ;   16  Request
   02                               ;   2  call_id
   19 04 12                         ;   1042  method_id
   a0                               ;   {}  metadata
   82 68 73 65 74 74 69 6e 67 73 f5 ;   ["settings", true]

; callee -> caller, same stream
04 83 11 02 f6                      ; length 4, [17, 2, null]
```

The `Request` finished the caller's half and the `Response` finished the callee's, so the call has ended and the stream is idle again. The same call in JSON-RPC carries the method name and field names as strings; here the whole request is 18 bytes.

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

Codes 23–31 are reserved for later core versions.

| Where | How the status is carried |
| --- | --- |
| `Error`, `Cancel`, `GoAway`, `AuthStatus` | The `status` field. |
| WebTransport stream reset | The WebTransport stream error code (0–255). |
| WebTransport session close | The session close code; the reason holds at most 1024 bytes of UTF-8. |
| WebSocket close | Close code 4000 + status for core codes 0–31; any other status uses 4002 (unknown) with the status in the reason. |

A peer that detects a `protocol_error` inside a call ends that call with `Error` (as callee) or `Cancel` (as caller). Outside any call, it sends `GoAway(protocol_error)` and closes the session.

`Error.details` is any value. It SHOULD be a typed value (`[type_id, value]`) from the callee's schema so clients can decode structured errors, such as a list of invalid fields.

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

Hashes in JSON are base64url without padding. `401` means log in again; `426` means the client's `hostApi` is too old for this host (section 9.4). The endpoint MUST require a CSRF-safe request: a JSON body with `Content-Type: application/json`, and an origin check when cookie-authenticated.

Because `/connect` returns the schema hash, the client can compare it with its snapshot and send an optimistic `Hello` (section 5.2) without waiting for `Welcome`.

### 9.2 Tickets

- The ticket goes in `Hello` as `["bearer", ticket]`. WebTransport sends no cookies and browsers cannot set headers on WebTransport or WebSocket, so it has to travel inside the protocol.
- A ticket is a signed token (PASETO `v4.public` or a JWT with EdDSA), so edge servers verify it without calling the host. Claims: `sub`, `sid` (the login session), `aud`, `exp`, `jti`, `sexp` (when the login session ends).
- `exp` MUST be within 60 s of issue. It only limits when the ticket may be presented in `Hello` or `AuthRefresh`; the session itself lasts until `sexp` (section 5.5).
- A ticket MUST be single-use: the edge records its `jti` until `exp`. Because one edge cannot see another's records, `aud` MUST name the specific edge instance whose endpoints `/connect` returned. Instances that share one hostname behind a load balancer MUST share a `jti` store.
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

Modules are declared in the server schema's top-level annotation `web.modules`:

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
- The client MUST skip any module whose `hostApi` range does not include its own host API version, and report it with MethodId 32, `web.moduleRejected`: a notification whose input is a list of strings (type [0, 6]) holding the module's `id`, `version` and a reason. Every server implementing the web profile MUST provide this method.
- The `hostApi` version is the client's real compatibility contract. It MUST follow semver: removing or changing anything in `HostApi` is a major version.
- Configuration for the client (layout, routes, feature flags) goes in `Welcome.props` or schema annotations under `web.*`. Its shape is defined by the host API, not by the core spec.

### 9.5 Module signing

Signing protects clients against a compromised plugin publisher, build pipeline, CDN or module store, and lets one frozen client trust modules from several publishers. It does not protect against a compromised origin that serves the client shell itself (`index.html` and the Service Worker), because whoever controls the shell controls the trusted keys. If that threat is in scope, serve the shell from a separate, locked-down origin.

- **Root keys:** the client build embeds one or more root public keys. Root keys are never added, replaced or removed at runtime.
- **Publisher certificates:** the schema annotation `web.keys` carries `[publisher_key, namespace, expires, root_key_id, root_sig]` entries. Each lets a publisher key sign modules whose `id` starts with `namespace`, which MUST end with a dot (for example `acme.`), until `expires`. Expiry is checked when a module is accepted into a snapshot, not each time a stored snapshot boots, so an offline client keeps working.
- **Per-module signatures:** each `web-module` carries `sig`, an Ed25519 signature over the canonical CBOR (section 3.2) of the entry without `sig`. The client MUST reject a module unless the key is a root key, or a certified publisher key whose namespace covers the module `id`, that has not expired and is not revoked. The file hashes in the entry then cover every byte.
- **Rollback protection:** after a snapshot has booted successfully, the client records the highest version of each module in it, and afterwards rejects lower versions, except in the one previous snapshot it keeps for rollback (section 9.6). A publisher or operator undoes a bad release by publishing a higher version.
- **Revocation:** the annotation `web.revoked` carries `[seq, [* key_id], root_key_id, root_sig]`. The client keeps the list with the highest `seq` and rejects modules signed by any key on it.
- **Stored state:** certificates are re-verified against the build-embedded root keys every time they are used, so a module that tampers with stored data cannot add trusted keys. At worst it can erase version and revocation records, which the next verified schema restores.
- **Scope:** namespaces limit what each publisher can sign. Once loaded, all modules share one JavaScript realm, so a module can still affect others unless modules are sandboxed (section 11.3).
- A development build MAY accept unsigned modules behind an explicit flag that a production build cannot enable.

Signed formats, which the test vectors of section 6.6 also cover:

- **Keys:** keys are raw 32-byte Ed25519 public keys. `key_id` is the first 16 bytes of SHA-256 of the key.
- **What each signature covers:** the canonical CBOR (section 3.2) of the signed array or map without its signature element, prefixed with a domain string so one kind of signature can never be replayed as another. The module `sig` uses `"sparrow-module-v1"`, certificates use `"sparrow-cert-v1"`, and revocation lists use `"sparrow-revoked-v1"`.
- **Times:** `expires` is tag 1 with integer seconds.
- **Versions:** module versions are semver 2.0 and compared by semver precedence, including pre-releases.

### 9.6 Offline snapshots

A snapshot is everything the client needs to boot without a network:

```
snapshot = { schemaHash, schema, props, modules: [web-module], files: {hash => bytes}, createdAt }
```

1. **Boot:** load the newest valid snapshot, verify file hashes, load modules, render.
2. **Connect** in the background (`/connect`, then the session). If the snapshot's schema hash is current, nothing more happens.
3. **Update:** if it differs, download the new schema and missing files, verify hashes and the signature, and write a new snapshot in one IndexedDB transaction. A half-written snapshot is never used.
4. **Apply** according to the annotation `web.apply`: `"hot"` (swap modules now), `"reload"` (on the next start) or `"prompt"` (ask the user).
5. **Keep** the previous snapshot until the new one has booted successfully once, so a bad update can roll back.

Before running any module, the loader MUST check its bytes against the signed hash, whether they come from the snapshot store or the network. Modules MUST be single-file ES module bundles: they import shared libraries from `host` and fetch assets through the host API, which checks asset hashes, so they need no relative imports. The RECOMMENDED loader fetches the bytes, verifies the hash and imports them from a `blob:` URL, which needs `blob:` in `script-src`. An import map with `integrity` metadata MAY be used instead, but only after a runtime self-test shows the browser enforces it: importing a module whose integrity entry deliberately does not match must fail. A Service Worker SHOULD serve `/sparrow/mods/*` from the snapshot store so modules load offline; it is a cache, not a security boundary, because a hard reload bypasses it.

## 10. Security considerations

The biggest risk is code push: a compromised server or plugin can run code in every client unless modules are signed (section 9.5). The rest of the risks are the usual ones for a binary protocol that parses untrusted input.

| Threat | Mitigation |
| --- | --- |
| Malicious or compromised module reaches clients | Per-module signatures chained to root keys in the client build, rollback protection, revocation, and a hash check before every load (section 9.5). A compromised origin serving the shell is out of scope. |
| One plugin abusing another | Out of scope for the protocol. Hosts SHOULD give each plugin its own service namespace and check permissions per method. Clients MAY load untrusted modules in a sandboxed iframe or worker instead of the main window. |
| Stolen ticket | 60 s presentation window, single use, bound to one edge instance; refresh only for the same user and login session. The RPC session ends at `sexp`. |
| Cross-site connection with the user's cookies | `/connect` requires a JSON body and checks `Origin`. WebSocket servers MUST check `Origin` too. WebTransport sends no cookies. |
| Memory exhaustion from large messages | `maxMessageSize` enforced before buffering; nesting depth limit of 64; collection lengths checked against remaining bytes before allocating; buffered data per call bounded by credit (section 7.4). |
| Too many calls or streams | `maxConcurrentCalls`; extra leased streams reset with resource_exhausted; notifications are best-effort and a flooding peer is disconnected. |
| Schema bomb (huge or deeply nested schema) | Clients SHOULD cap server schemas at 8 MiB and 32 levels of type nesting. Servers cap client schemas at 64 KiB and parse them only after authentication. |
| Peer sending IDs for methods it should not see | IDs are not secrets. Authorization MUST be checked on every call, never by hiding a method from the schema alone. |
| Downgrade to WebSocket | Both transports use TLS. The protocol is identical on both, so a downgrade costs performance but not security. |
| Tracking via schema hash | A per-user schema hash can identify a user across sessions on a shared device. Snapshots SHOULD be cleared on logout. |

Decoders MUST treat every field as untrusted, including values from a peer that passed authentication. Go and TypeScript reference implementations SHOULD be fuzzed (Go native fuzzing, and a property-based tester for TypeScript) against the decoder and the schema loader.

## 11. Implementation notes and open questions

The draft is implementable with existing libraries on both sides. The main unknown is whether a schema-driven CBOR decoder in JavaScript beats `JSON.parse` on real payloads, so benchmark that first.

### 11.1 Go reference server

- Transport: `quic-go` with `webtransport-go` for HTTP/3; `coder/websocket` (or `gorilla/websocket`) for the fallback. Both adapters implement one `Stream` interface.
- Encoding: `fxamacker/cbor` with preferred serialization for messages and Core Deterministic Encoding for schemas and signed data.
- Schema building: plugins register services into a registry, from Go types with struct tags (`sparrow:"1,optional"`) or hand-written definitions. The registry persists its name-to-ID table so IDs stay stable across restarts, and emits a `SchemaUpdate` delta when a plugin loads or unloads.
- Dispatch: one reader goroutine per stream routes messages by call ID to one goroutine per active call; `context.Context` carries deadline, cancellation and auth identity.

### 11.2 Browser client

- Encoding: `cbor-x` is a fast choice for messages, but only with record extensions and undefined disabled, and with 64-bit integers outside the safe range decoded as BigInt. It does not sort map keys, so schemas and signatures also need a canonical encoder. Measure it against `JSON.parse` on string-heavy payloads.
- Decoders: build lookup-table decoders from the schema when it loads. Generating code with `new Function` is faster but needs `unsafe-eval` in the CSP; keep it optional.
- Transport: try `WebTransport` first with a timeout of about 3 s, then `WebSocket`. Remember the winner per origin.
- Solid integration: expose server streams as signals or stores, and calls as async functions. Keep this binding outside the core library so the protocol stays framework-neutral.

### 11.3 Open questions

- [ ] Should IDs be assigned by the server registry (current draft) or derived from a hash of the name? Derived IDs need no stored table but are larger and can collide.
- [ ] Is a session-resumption token wanted, so a reconnect can keep its subscriptions open?
- [ ] Should the core define any datagram messages (presence, telemetry), or leave them entirely to profiles?
- [ ] Per-message compression: is a dictionary-based zstd option worth it on top of numeric IDs?
- [ ] Should untrusted third-party modules always run in a sandbox (iframe or worker), with only signed first-party modules in the main window?
- [ ] What is the exact `HostApi` surface for version 1, and who owns its versioning?
- [ ] Is a single schema per server enough, or do hosts need several named schemas (for example per workspace) in one session?
