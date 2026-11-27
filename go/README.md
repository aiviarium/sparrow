# Sparrow RPC: Go reference implementation

Module `github.com/aiviarium/sparrow-rpc/go`, Go 1.24, following core spec revision 316
(`../spec/core.md`) and hub-admin revision 18 (`../spec/hub-admin.md`). Phase 1 is the encoding,
wire format, schema model and web-profile signing (below); phase 2 the sessions, transports and the
node library (`session/README.md`); phase 3 the hub, `sparrow.hub.admin` and the `sparrow-hub`
program (section "Hub" below). The Web Profile's HTTP endpoints come in phase 4.

| Package | Purpose |
| --- | --- |
| `cbor` | Minimal CBOR layer: preferred-serialization encoders, a zero-copy pull decoder, `Validate` for the Sparrow subset (3.1: definite lengths, UTF-8, unique keys, tags 1/37 only, no `undefined`, depth 64), `Canonical` (Core Deterministic Encoding), a generic value tree. |
| `wire` | QUIC varints, length-prefixed framing with `maxMessageSize`, stream header byte (4.1), kind ranges (3.3), typed messages for every kind of 5.4, 5.5 and 7.2 with payloads kept as raw CBOR, metadata (sigil keys 32-37), params with defaults, credit accounting (7.4), hub relay helpers (call-ID rewrite, request forwarding). |
| `status` | Status codes (8), WebTransport / WebSocket close-code mapping, reason truncation at a UTF-8 boundary. |
| `schema` | The facet model (6): types, CBOR codec, canonical form and hashes, validation, compatibility (6.7), interface conformance on wire shapes (6.5), deltas and per-session schema state (6.6), the built-in facet 1 `sparrow.web` (9.4). |
| `value` | Schema-driven payload encoder/decoder: positional structs with trailing-null omission, sparse structs, enums, unions, `dynamic`, `symbol`, byte-stream tokens. |
| `websign` | Module signing (9.5): key IDs, signature inputs, certificates, revocation lists, web-module entries, the acceptance verdict, semver precedence and rollback records. |
| `names` | Name grammars: facet names, node IDs, module ids, imported names, principals (6.1, 9.4, 10.2-10.8). |
| `adminiface` | The `sparrow.hub.admin` v1 interface (`../spec/hub-admin.md`): `Interface()`, `Facet(id)`, `InterfaceHash()`, type, method and sigil IDs, and `StoredFacetKey`. |
| `session`, `transport/...`, `node`, `examples/echo-node` | Phase 2: see `session/README.md`. |
| `admin` | `sparrow.hub.admin` v1: the document (CBOR and JSON forms), validation, revisions, confirmation and rollback, stored secrets and facets, watch, persistence in a data directory, the facet handler and a client. |
| `hub` | The Hub Profile (core section 10): node links, composition, authorization, forwarding, call contexts, offline nodes, federation. |
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
cat > doc.json <<'JSON'
{ "nodes": {"echo": {"spawn": {"command": ["bin/echo-node", "-id", "echo"]}}},
  "policy": [["user:alice", "echo", "use"]] }
JSON
bin/sparrow-admin -url https://127.0.0.1:4433/sparrow/wt -token change-me -cert-hash <hash> \
    commit -confirm-within 10000 -confirm doc.json
```

The static file (`cmd/sparrow-hub.Config`) holds listen addresses, TLS (or `selfSigned`), the data
directory, bootstrap administrators and optional static bearer tokens; everything else is committed
through `sparrow.hub.admin`. `spec/reference-server.md` describes the design and the hub-specific
choices (policy grants, extensions, crash policy, persistence files).

API: `hub.New(hub.Options{Store, Bootstrap, ...})` opens the state and applies the persisted document;
`Hub.ServeConn(ctx, conn)` runs any accepted connection (a client, a dial-in node or peer hub);
`WebTransportHandler` / `WebSocketHandler` mount it on listeners; `Close(grace)` sends `GoAway(going_away)`
to every session and stops the nodes. `hub.Policy` is pluggable (`Options.Policy`, then
`Hub.PolicyChanged`); the built-in one reads `ref.policy` grants from the document.

Choices worth knowing (details in `spec/reference-server.md`):

- Each session gets its own schema (`session.Config.SchemaFor`): the hub's facets and the node facets
  visible to its principal (`node:<id>` for nodes and peers), never the session's own facets, never
  imported facets towards a peer, plus `sparrow.defaults`. Facet IDs come from a persisted table keyed
  by (node ID, facet name, major); a counter that only grows means retired IDs are never handed out
  again. The last definition of every ID is persisted too: a node reconnecting (or updating) with a
  facet that is not a compatible successor is refused with `schema_mismatch`, also across restarts.
- A node's update is relayed to every session whose view changes; the node is acked only after each
  of them acked or was closed (5 s each, 2.5 s for an update from a peer hub).
- Interfaces: the hub verifies `implements` against the interfaces it knows (built in:
  `sparrow.hub.admin`; more in the document extension `ref.interfaces`). A claim it cannot verify is
  refused unless `AcceptUnknownInterfaces` is set; unverified claims never become defaults.
- Contexts are 16 random bytes, bound to the node link they were issued on, valid while the call is
  open and 2 s after (never after its deadline); when the grace period ends the hub ends nested calls
  still carrying it with `permission_denied` (Error to the node, Cancel to the callee).
- Calls to a node that is not connected wait up to the start timeout (default 10 s), starting a
  spawned node that is not running; notifications to it are dropped.
- Spawned processes run in their own process group, get `GoAway` when stopped and are killed after
  5 s; a process that exits cleanly after a `GoAway` of its own is started again on its next call;
  crashes restart with backoff, and 5 crashes within a minute mark the node failed until its
  configuration changes.
- Dialed nodes: the TLS chain is not verified, only the SHA-256 of the leaf's SubjectPublicKeyInfo
  (the pin); `https` dials WebTransport, `wss` WebSocket. A changed Dial keeps the old session until the
  new one supersedes it, or until the first new attempt fails.

## Hub tests

```sh
go test -race ./admin ./hub ./cmd/...                  # unit and integration tests
go test -race -count=3 ./hub ./cmd/...                 # flakiness check
HUB_TEST_LOG=1 go test ./hub -run TestFederation -v     # with the hub's debug log
```

`hub` runs an in-process hub behind real WebTransport and WebSocket listeners, with the echo-node
binary spawned over stdio, in-process nodes that dial in or are dialed (SPKI pins), three federated
hubs, a fake clock for context expiry and admin deadlines, restarts on the same data directory, and
every behaviour scenario of `../test-vectors/scenarios` through the hub to a node (`TestScenariosThroughHub`).
`cmd/sparrow-hub` builds the binaries and drives them as an operator would (`sparrow-admin`, SIGTERM,
restart, cached schemas).
