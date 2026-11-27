# Sparrow reference server (design note)

> Design note, not part of the specification. Snapshot of the live draft, revision 1, exported for this repository, with the details and deviations of the Go implementation (phase 3) added in this copy; they are marked *(implementation)* and go back to the live draft. The live document is the source of truth.

The reference server is a Go program, `sparrow-hub`, that implements the core protocol, the Hub Profile, the hub side of the Web Profile and `sparrow.hub.admin` v1. This note describes how it is built and configured. It is not part of the spec: another hub may make every choice here differently and still interoperate.

## 1. Layout

| Package | Purpose |
| --- | --- |
| `wire` | Varints, framing, every message kind, metadata, credit sizes |
| `status` | Status codes and transport close-code mapping |
| `schema` | Facets: model, canonical form, hashes, validation, compatibility, interface conformance, deltas |
| `value` | Schema-driven encoding of values |
| `websign` | Module signatures, certificates, revocation (Web Profile 9.5) |
| `session` | One Sparrow session over any binding: handshake, control messages, calls, credit, leases, schema updates |
| `transport` | Bindings: WebTransport (quic-go, webtransport-go), WebSocket, pipe |
| `node` | A small library for writing nodes and clients: publish facets, serve methods, call others |
| `hub` | Composition, forwarding, call contexts, authorization, node links, offline and starting nodes, federation |
| `admin` | The `sparrow.hub.admin` facet, persistence and reconciliation |
| `web` | `/connect`, tickets, schema and module HTTP resources *(implementation: phase 4; facet 1 `sparrow.web` is already published when the static file sets `web`, and `moduleRejected` is logged)* |
| `cmd/sparrow-hub` | The server program |
| `cmd/sparrow-admin` | *(implementation)* A command-line controller: get, validate, commit (and confirm over a new session), confirm, rollback, secrets, stored facets, watch |

*(implementation)* Reconciliation lives in `hub` (it implements `admin.Applier`); `admin` holds the document, the revision state machine and the stores. The facet-ID table and the last known facets are hub state, kept in the same data directory.

## 2. Configuration

The program reads a small static file at start: listen addresses, TLS certificate and key, the data directory, and the bootstrap administrator (a principal with a credential). Everything else arrives through `sparrow.hub.admin`.

The data directory holds the persisted state of admin section 2.4: the confirmed document and its revision, the revision high-water mark, stored secrets and facets, the facet-ID table and the last known facets of every node. Writes are atomic (write to a temporary file, then rename).

*(implementation)* The static file is JSON: `webtransport` (UDP address, served at `/sparrow/wt`), `websocket` (TCP address, `/sparrow/ws`, TLS unless `websocketPlain`), `tls.cert`/`tls.key` or `selfSigned` with `hosts` (a 10-day certificate whose hash and SPKI pin are logged and written to `-addr-file`), `dataDir`, `bootstrap` (`principal` with `credential` or `credentialFile`, presented as `["bearer", credential]`), optional static `tokens` (token, principal, groups), `web`, `startTimeoutMs`, `acceptUnknownInterfaces`, `allowedOrigins`, `shutdownGraceMs` and `log`. SIGINT or SIGTERM sends `GoAway(going_away)` to every session and node, waits for them up to the grace period and exits.

*(implementation)* Files of the data directory: `state.cbor` (`[revision, document]`, the last confirmed document), `highwater` (written before `commit` returns), `pending.cbor` (only a marker `[revision]` while a commit is pending, so a restart rolls it back as the next revision; the pending document itself is never written), `secrets/<name>` (mode 0600), `facets/<hex key>.cbor` (canonical, facet ID 0) and `hub.cbor` (the facet-ID counter, the table (node, name, major) → ID, the last definition of every ID and the IDs each node last published). Each file is written to a temporary file in the same directory, synced, renamed over the old one and the directory synced; temporary files a crash left behind are removed at start.

## 3. Nodes

- **Spawn:** `Start.spawn` runs the command with the given environment (secret values resolved at start) and speaks the pipe binding on its standard input and output. Exited nodes are restarted with backoff, and marked failed after 5 crashes within a minute.
  *(implementation)* The environment is the hub's plus the configured variables. The process runs in its own process group; standard error is logged line by line. To stop it the hub sends `GoAway(going_away)` and kills the group after 5 s. A process that exits with status 0 after sending `GoAway` itself is not restarted until a call needs it. Backoff starts around 125 ms and doubles up to 30 s, with jitter; a failed node stays failed until its configuration changes. The node extension `ref.lazy` (CBOR `true`) starts a node on its first call instead of at once.
- **Dial:** `Start.dial` connects over WebTransport, or WebSocket for `wss` URLs, verifies the pinned key hash and presents `["link", credential]`.
  *(implementation)* Only the pin is checked, not the certificate chain. The credential is sent as a text string when the secret is valid UTF-8, else as bytes. The hub always publishes a client schema in `Hello` (possibly empty), so it can update it later. When the Dial changes, the old session stays until the new one supersedes it, or until the first new attempt fails.
- **Dial-in:** nodes without `start` connect to the hub's listener and present `["link", credential]`.
  *(implementation)* The credential (text or bytes) is compared with the value of each dial-in node's secret. Credentials are re-validated every 30 s and on every commit; a changed or removed one closes the session with `GoAway(unauthenticated)` before anything else is reconciled. A credential that belonged to a dial-in node the hub now starts or dials is refused with `GoAway(failed_precondition)` (the hub remembers it for its lifetime); any other unknown credential with `unauthenticated`.
- *(implementation)* **Peers** (`peer: true`) use the same three link kinds; their facets are listed as `<peer-id>/<name>` and a peer exporting a name with `/` is refused (`invalid_argument`).
- **Other kinds:** none yet. Planned are `wasm` (a WebAssembly module run in-process with wazero, linked by an in-memory pipe and given no host functions beyond it) and `oci` (a node bundle pulled from an OCI registry: a small manifest, the facet documents and a binary or WebAssembly module, signed with the Web Profile's key chain).

## 4. Authorization

The built-in policy reads grants from the document's `extensions` under the key `ref.policy`: a CBOR list of `[principal, facet name, level]` with levels `view`, `use` and `manage`. `visible` needs `view`; `allowed` needs `use`, or `manage` for methods annotated `"sparrow.level": "manage"`. A principal's groups are taken from its credential. The bootstrap administrator is always allowed on `sparrow.hub.admin`.

*(implementation)* A grant's principal may also be `*` (everyone) or a group (`group:<id>`, matched against the groups of the credential; static tokens list them). Its facet name is the listed name (`<peer-id>/<name>` for imports), `*` for every facet, or `prefix.*` for every facet whose name starts with `prefix.`. The highest matching level counts. Facet 1 `sparrow.web` is visible to and callable by everyone. Each acting principal of a call is checked on its own: a node's grants, a peer's `node:<peer-id>` grants and `peer:<peer-id>/<principal>` grants are separate entries. The policy is pluggable (`hub.Options.Policy`); with a custom policy `ref.policy` is not accepted. Grants change with the document, and every session whose view changed gets a schema update, while calls no longer allowed end with `Error(permission_denied)` and `Cancel(permission_denied)`.

*(implementation)* Further hub-specific extensions: the document extension `ref.interfaces` (a CBOR list of encoded interface documents) adds interfaces the hub verifies `implements` claims against; `sparrow.hub.admin` is built in. A claim naming an interface the hub does not know is refused with `schema_mismatch` unless the static file sets `acceptUnknownInterfaces`; such claims are never chosen in `sparrow.defaults`. Every other extension key, and every `Other` start kind, is a validation problem.

## 4a. Hub behaviour *(implementation)*

- **Facet IDs:** `sparrow.hub.admin` takes the first free ID of a fresh hub (16), `sparrow.web` is facet 1; node facets get the next free IDs. A removed node's IDs are retired; a disabled node keeps them and is hidden.
- **Compatibility:** the hub keeps the last definition of every facet ID and checks every new version of a node's facet against it, at connection and in updates, also across sessions and restarts.
- **Relayed updates:** each downstream session gets 5 s to ack a node's update (2.5 s for an update from a peer hub); the hub acks the node when all have acked or been closed.
- **Forwarding:** the forwarded `credit` is the caller's (its key, or the default of its stream); `deadline` is lowered by the time spent, start-up included; `context` is 16 random bytes and `principal` the principal the call acts for. When a context's 2 s grace period ends, calls still carrying it are ended with `permission_denied`.
- **Watch:** after the `Snapshot`, the hub sends the current `NodeEvent` of every node, then events as they happen; on every commit each node's state is reported again with the new revision. A watcher more than 256 events behind is ended with `Error(resource_exhausted)`.
- **Problem paths** go down to the field at fault, through the variant name of a union (for example `["nodes", "acme.notes", "start", "dial", "pin"]`); keys of the `defaults` map (bytes) appear as lowercase hex.

## 5. Web Profile

The hub serves `POST /sparrow/connect` (tickets are EdDSA-signed JWTs bound to the hub instance), `GET /sparrow/schema/{hash}` and `GET /sparrow/mods/{hash}.{ext}`. How users log in before `/connect` is pluggable; the reference implementation ships a static-token authenticator for development and tests.

## 6. Testing

*(implementation)* Everything below exists for phase 3; the hub decodes only with `wire`, `schema` and `admin`, whose decoders are fuzzed (`admin.FuzzDecode` covers the document types). See `go/README.md`.

- Unit tests in every package, and conformance tests against the published test vectors.
- Behaviour scenarios: scripted message sequences with expected outcomes, run against the real server over each binding.
- Integration tests with real node processes, a dialed node, a dial-in node and two federated hubs.
- Fuzzing of every decoder.
