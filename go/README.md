# Sparrow RPC: Go reference implementation

Module `github.com/aiviarium/sparrow-rpc/go`, Go 1.24, following core spec revision 377
(`../spec/core.md`) and hub-admin revision 38 (`../spec/hub-admin.md`). Phase 1 is the encoding,
wire format, schema model and web-profile signing (below); phase 2 the sessions, transports and the
node library (`session/README.md`); phase 3 the hub, `sparrow.hub.admin` and the `sparrow-hub`
program (section "Hub" below); phase 4 the Web Profile server (section "Web Profile" below).

| Package | Purpose |
| --- | --- |
| `cbor` | Minimal CBOR layer: preferred-serialization encoders, a zero-copy pull decoder, `Validate` for the Sparrow subset (3.1: definite lengths, UTF-8, unique keys, tags 1/37 only, no `undefined`, depth 64), `Canonical` (Core Deterministic Encoding), a generic value tree. |
| `wire` | QUIC varints, length-prefixed framing with `maxMessageSize`, stream header byte (4.1), kind ranges (3.3), typed messages for every kind of 5.4, 5.5 and 7.2 with payloads kept as raw CBOR, metadata (sigil keys 32-37), params with defaults, credit accounting (7.4), hub relay helpers (call-ID rewrite, request forwarding). |
| `status` | Status codes (8), WebTransport / WebSocket close-code mapping, reason truncation at a UTF-8 boundary. |
| `schema` | The facet model (6): types, CBOR codec, canonical form and hashes, validation, compatibility (6.7), interface conformance on wire shapes (6.5), deltas and per-session schema state (6.6), the built-in facet 1 `sparrow.web` (9.4). |
| `value` | Schema-driven payload encoder/decoder: positional structs with trailing-null omission, sparse structs, enums, unions, `dynamic`, `symbol`, byte-stream tokens. |
| `websign` | Module signing (9.5): key IDs, signature inputs, certificates, revocation lists, web-module entries, the acceptance verdict, semver precedence and rollback records. |
| `names` | Name grammars: facet names, node IDs, module ids, imported names, principals (6.1, 9.4, 10.2-10.8). |
| `adminiface` | The `sparrow.hub.admin` v1 interface (`../spec/hub-admin.md`): `Interface()`, `Facet(id)`, `InterfaceHash()`, type, method and sigil IDs. |
| `session`, `transport/...`, `node`, `examples/echo-node` | Phase 2: see `session/README.md`. `examples/echo-node` dials in to a hub (`-hub`) or waits to be dialed (`-listen`). |
| `admin` | `sparrow.hub.admin` v1: the document (CBOR and JSON forms), validation, revisions, confirmation and rollback, stored secrets, watch, persistence in a data directory, the facet handler and a client. |
| `hub` | The Hub Profile (core section 10): node links (nodes dial in, or the hub dials them; it never starts nodes), composition, authorization, forwarding, call contexts, offline nodes, federation. |
| `web` | The Web Profile (core section 9): `/sparrow/connect`, tickets, schema and module resources, the `web.*` annotations, and a client that follows the browser rules (signatures, rollback, revocation, snapshots). |
| `cmd/sparrow-hub` | The reference server program. |
| `cmd/sparrow-admin` | A command-line controller for `sparrow.hub.admin`. |
| `conformance` | Tests only: checks the library against every vector in `../test-vectors`, and the messages of every behaviour scenario in `../test-vectors/scenarios`. |

The vectors and this library use the same error vocabulary (`reserved_facet_id`, `invalid_notification`, ...).

## Testing

```sh
go vet ./...
go test -race ./...                 # unit tests and all test vectors
go test ./conformance -v            # prints "vector coverage: N/N vectors checked and passing"

# fuzzing (Go native), e.g. 20 s per target
go test ./cbor   -run '^$' -fuzz FuzzValidate -fuzztime 20s
go test ./wire   -run '^$' -fuzz FuzzDecode   -fuzztime 20s
go test ./schema -run '^$' -fuzz FuzzSchema   -fuzztime 20s
go test ./value  -run '^$' -fuzz FuzzDecode   -fuzztime 20s
go test ./admin  -run '^$' -fuzz FuzzDecode   -fuzztime 20s
```

The conformance suite fails if any vector is left unchecked. Set `SPARROW_VECTORS` to test against
another vector directory. `github.com/fxamacker/cbor/v2` is used only by tests, as a differential
reference for float widths and Core Deterministic Encoding.

## Choices worth knowing

- Receivers accept integers and lengths that are not in shortest form (3.1 binds senders);
  `cbor.Options.RequirePreferred` turns on strict checking. Senders always write preferred form,
  and map keys in deterministic order.
- The 64-level nesting limit applies to the whole message: arrays, maps and tags count, the outermost
  array is level 1, and scalars add no level (so 64 nested arrays holding a uint are accepted).
- Received `params` are checked with `wire.Params.Validate` (minimums of 5.4); unknown keys are kept
  in `Params.Extra` and otherwise ignored.
- Facet 1 must match `sparrow.web` by facet hash and be named `sparrow.web`.
- A notification must have output unit and no `[4]` in its input; TypeIds 12-31 are reserved
  (`reserved_type_id`); an interface's reachability ignores references inside tombstones.
- `Compatible` rejects making a required field optional and changing the type of a field or variant
  as (or after) it becomes a tombstone.
- `[4]` inside a `dynamic` value cannot be ruled out by schema validation (any named type may be
  sent as `dynamic`); `value` rejects it when encoding or decoding.
- A message that counts zero bytes of credit (an empty `Bytes` chunk, `End`) is never held back
  (`CreditWindow.CanSendCounted`) and never a credit violation.

## Hub (phase 3)

```sh
go build -o bin/ ./cmd/sparrow-hub ./cmd/sparrow-admin ./examples/echo-node
cat > hub.json <<'JSON'
{ "webtransport": "127.0.0.1:4433", "websocket": "127.0.0.1:4434", "selfSigned": true,
  "dataDir": "./data", "bootstrap": [{"principal": "user:admin", "credential": "change-me"}],
  "tokens": [{"token": "alice", "principal": "user:alice"}] }
JSON
bin/sparrow-hub -config hub.json -addr-file addrs.json     # logs the certificate hash and SPKI pin
A="bin/sparrow-admin -url https://127.0.0.1:4433/sparrow/wt -token change-me -cert-hash <hash>"
$A set-secret echo-link echo-credential                     # what the dial-in node presents
$A set-secret notes-link hub-credential                     # what the hub presents to a dialed node
bin/echo-node -id notes -listen 127.0.0.1:5533 -credential hub-credential -key-file notes.key &
#   prints {"webtransport":"https://127.0.0.1:5533/sparrow/node","pin":"<hex>"}
cat > doc.json <<'JSON'
{ "nodes": {"echo":  {"link": {"credential": "echo-link"}},
            "notes": {"link": {"dial": {"url": "https://127.0.0.1:5533/sparrow/node", "pin": "<hex>", "credential": "notes-link"}}}},
  "policy": [["user:alice", "echo", "use"], ["user:alice", "notes", "use"]] }
JSON
$A commit -confirm-within 10000 -confirm doc.json
bin/echo-node -id echo -hub https://127.0.0.1:4433/sparrow/wt -hub-pin <pin> -credential echo-credential &
```

The hub never starts, installs or supervises nodes: whatever runs them (here a shell, elsewhere an
orchestrator or a service manager) starts them and hands a dial-in node the hub's URL and its
credential, or registers a listening node's URL and SPKI pin in the document.

The static file (`cmd/sparrow-hub.Config`) holds listen addresses, TLS (or `selfSigned`), the data
directory, bootstrap administrators and optional static bearer tokens; everything else is committed
through `sparrow.hub.admin`. `spec/reference-server.md` describes the design and the hub-specific
choices (policy grants, extensions, crash policy, persistence files).

API: `hub.New(hub.Options{Store, Bootstrap, ...})` opens the state and applies the persisted document;
`Hub.ServeConn(ctx, conn)` runs any accepted connection (a client, a dial-in node or peer hub);
`WebTransportHandler` / `WebSocketHandler` mount it on listeners; `Close(grace)` sends `GoAway(going_away)`
to every session (also those still in the handshake), stops the nodes and returns once the connections
have finished closing. `hub.Policy` is pluggable (`Options.Policy`, then
`Hub.PolicyChanged`); the built-in one reads `ref.policy` grants from the document.

Choices worth knowing (details in `spec/reference-server.md`):

- Each session gets its own schema (`session.Config.SchemaFor`): the hub's facets and the node facets
  visible to its principal (`node:<id>` for nodes and peers), never the session's own facets, never
  imported facets towards a peer, plus `sparrow.defaults`. Facet IDs come from a persisted table keyed
  by (node ID, facet name, major); a counter that only grows means retired IDs are never handed out
  again. The last definition of every ID is persisted too: a node reconnecting (or updating) with a
  facet that is not a compatible successor is refused with `schema_mismatch`, also across restarts.
- A node's update, or the change any new session of a node brings (dialed or dial-in), is relayed to every session whose
  view changes; the node is acked only after each of them acked or was closed with
  `GoAway(schema_mismatch)` (5 s each, 2 s for an update from a peer hub; `Options.RelayAckTimeout`,
  `PeerRelayAckTimeout`). The node library gives its hub at least 10 s.
- Dial-in: only an enabled node configured to dial in has a dial-in credential; anything else is
  `GoAway(unauthenticated)`. A node that is removed or disabled, or whose link or `peer` setting
  changes, has its session ended at once: its running calls end with `unavailable`, then
  `GoAway(unauthenticated)`; it is dialed anew or waited for while still configured and enabled.
  A node that is not yet seen lists no facets. At a node's `maxConcurrentCalls` further calls get
  `resource_exhausted` at once. Calls from a peer hub never carry a `context` (one that does, or that names
  a `peer:` principal, gets `permission_denied`), the hub sends none to a peer, and a call acting for
  a `peer:` principal is never forwarded to another peer.
- Client sessions whose credential has a login session and an end (Web Profile tickets) get
  `AuthStatus` 60 s before the end and `GoAway(unauthenticated)` at the end; `AuthRefresh` for the same
  principal and login session extends them (`Actor.LoginSession`, `Actor.Expires`).
- Interfaces: the hub verifies `implements` against the interfaces it holds documents for (built in:
  `sparrow.hub.admin`; more in the document extension `ref.interfaces`). A claim to any other
  interface is refused with `schema_mismatch`, like an incompatible update.
- Contexts are 16 random bytes, bound to the node link they were issued on, valid while the call is
  open and 2 s after (never after its deadline); when the grace period ends the hub ends nested calls
  still carrying it with `permission_denied` (Error to the node, Cancel to the callee).
- Calls to a node that is not connected wait up to the connect timeout (`Options.ConnectTimeout`,
  static key `connectTimeoutMs`, default 10 s) for it to connect, then fail with `unavailable`
  (`unimplemented` at once if the node is removed or disabled meanwhile); notifications to it are
  dropped.
- Dialed nodes: the TLS chain is not verified, only the SHA-256 of the leaf's SubjectPublicKeyInfo
  (the pin); `https` dials WebTransport, `wss` WebSocket. The hub redials with backoff (about
  500 ms doubling to 30 s), at once and then every 250 ms or sooner while a call waits for the node.
- With `selfSigned`, the certificate's key is kept in the data directory, so the SPKI pin that
  dial-in nodes may check (`echo-node -hub-pin`) survives restarts.
- Calls (7.1, 7.6): as callee a session stops counting and forgets a call at its own final message,
  also while the caller's half is still open; the caller counts it until it has seen that message.

Limitations: the hub presents only `["link", credential]` when dialing (no mutual TLS); the hub never
calls a client's own facets (they are scoped to the client's session).

## Hub tests

```sh
go test -race ./admin ./hub ./cmd/...                  # unit and integration tests
go test -race -count=3 ./hub ./cmd/...                 # flakiness check
HUB_TEST_LOG=1 go test ./hub -run TestFederation -v     # with the hub's debug log
```

`hub` runs an in-process hub behind real WebTransport and WebSocket listeners, with the echo-node
binary run as separate processes (`internal/testutil.Proc`) that dial in over WebSocket or
WebTransport or wait to be dialed (SPKI pins), killed, stopped and restarted while calls wait for
them; in-process nodes that dial in or are dialed; three federated hubs; a fake clock for context
expiry and admin deadlines; restarts on the same data directory, which the node processes find again
by themselves; and every behaviour scenario of `../test-vectors/scenarios` through the hub to a node
(`TestScenariosThroughHub`). `cmd/sparrow-hub` builds the binaries and drives them as an operator
would: the hub, `sparrow-admin` and two echo-node processes (one dials in, one is dialed), SIGTERM,
restart on the same ports, cached schemas.

## Web Profile (phase 4)

```sh
cat > hub.json <<'JSON'
{ "webtransport": "127.0.0.1:4433", "websocket": "127.0.0.1:4434", "selfSigned": true, "dataDir": "./data",
  "bootstrap": [{"principal": "user:admin", "credential": "change-me"}],
  "tokens": [{"token": "alice", "principal": "user:alice"}],
  "web": {"modulesDir": "./mods", "rootKeys": ["<hex root key>"], "minHostApi": "3.0.0"} }
JSON
bin/sparrow-hub -config hub.json -addr-file addrs.json     # addrs.json gets "web": "https://127.0.0.1:4434"
curl -k -H 'Authorization: Bearer alice' -H 'Content-Type: application/json' \
     -d '{"client": {"name": "x", "hostApi": "3.2.0"}}' https://127.0.0.1:4434/sparrow/connect
```

`"web": true` turns the profile on with the defaults. Package `web` serves `POST /sparrow/connect`
(static bearer tokens, or any `web.Authenticator`), `GET /sparrow/schema/{hash}` and
`GET /sparrow/mods/{hash}.{ext}` on both listeners; tickets go in `Hello` and `AuthRefresh` as
`["bearer", ticket]`. Module files live in `modulesDir` under any name and are found by content hash;
the facets' `web.modules` entries sign them. The document extension `ref.web` (a CBOR map of `web.*`
annotations) puts `web.keys`, `web.revoked`, `web.apply` and client configuration at the top level of
every schema. `examples/echo-node -web-modules file.cbor` ships a list of signed entries. Details:
`spec/reference-server.md`, section 5.

```sh
go test -race ./web ./cmd/sparrow-hub        # unit tests, and the binary end to end (TestWebEndToEnd)
e2e/browser/run.sh                           # headless Chromium: WebTransport and WebSocket (TestBrowser)
```
