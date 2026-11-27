# Sparrow reference server (design note)

> Design note, not part of the specification. Snapshot of the live draft, revision 1, exported for this repository. The live document is the source of truth.

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
| `web` | `/connect`, tickets, schema and module HTTP resources |
| `cmd/sparrow-hub` | The server program |

## 2. Configuration

The program reads a small static file at start: listen addresses, TLS certificate and key, the data directory, and the bootstrap administrator (a principal with a credential). Everything else arrives through `sparrow.hub.admin`.

The data directory holds the persisted state of admin section 2.4: the confirmed document and its revision, the revision high-water mark, stored secrets and facets, the facet-ID table and the last known facets of every node. Writes are atomic (write to a temporary file, then rename).

## 3. Nodes

- **Spawn:** `Start.spawn` runs the command with the given environment (secret values resolved at start) and speaks the pipe binding on its standard input and output. Exited nodes are restarted with backoff, and marked failed after 5 crashes within a minute.
- **Dial:** `Start.dial` connects over WebTransport, or WebSocket for `wss` URLs, verifies the pinned key hash and presents `["link", credential]`.
- **Dial-in:** nodes without `start` connect to the hub's listener and present `["link", credential]`.
- **Other kinds:** none yet. Planned are `wasm` (a WebAssembly module run in-process with wazero, linked by an in-memory pipe and given no host functions beyond it) and `oci` (a node bundle pulled from an OCI registry: a small manifest, the facet documents and a binary or WebAssembly module, signed with the Web Profile's key chain).

## 4. Authorization

The built-in policy reads grants from the document's `extensions` under the key `ref.policy`: a CBOR list of `[principal, facet name, level]` with levels `view`, `use` and `manage`. `visible` needs `view`; `allowed` needs `use`, or `manage` for methods annotated `"sparrow.level": "manage"`. A principal's groups are taken from its credential. The bootstrap administrator is always allowed on `sparrow.hub.admin`.

## 5. Web Profile

The hub serves `POST /sparrow/connect` (tickets are EdDSA-signed JWTs bound to the hub instance), `GET /sparrow/schema/{hash}` and `GET /sparrow/mods/{hash}.{ext}`. How users log in before `/connect` is pluggable; the reference implementation ships a static-token authenticator for development and tests.

## 6. Testing

- Unit tests in every package, and conformance tests against the published test vectors.
- Behaviour scenarios: scripted message sequences with expected outcomes, run against the real server over each binding.
- Integration tests with real node processes, a dialed node, a dial-in node and two federated hubs.
- Fuzzing of every decoder.
