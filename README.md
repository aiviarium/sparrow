# Sparrow RPC

Sparrow RPC is a binary, bidirectional, streaming RPC protocol. At session start the server sends a
schema describing its services and types; after that, messages refer to methods, types and enum
values by compact numeric IDs, so a client can call services it was never compiled against.
Messages are CBOR, the primary transport is WebTransport (WebSocket as fallback), the reference
server is Go and the primary client is a browser.

**Status: draft.** The spec is a working draft and will change; so will the vectors.

Dual-licensed under MIT (`LICENSE-MIT`) or Apache-2.0 (`LICENSE-APACHE`), at your option.

## Repository layout

```
spec/core.md               Core protocol specification with the Web and Hub profiles (snapshot of draft revision 302)
spec/hub-admin.md          Sparrow Hub Administration: the sparrow.hub.admin v1 interface (companion, revision 16)
spec/reference-server.md   Design note for the Go reference server (not part of the spec)
SPEC-ISSUES.md             Resolution log of spec questions raised while writing the test vectors
test-vectors/              Test vectors, one JSON file per area, and their format (README.md)
test-vectors/scenarios/    Behaviour scenarios: scripted message sequences with expected outcomes
tools/vectorgen-go/        Go program that generates the vectors (canonical reference)
tools/verify-js/           Independent Node.js verifier (cbor2 + node:crypto)
go/                        Go reference implementation (see go/README.md)
.github/workflows/         CI: regenerate, check for drift, verify
```

The core specification defines the protocol. [`spec/hub-admin.md`](spec/hub-admin.md) is the companion
document that section 10.9 of the core refers to: the standard interface through which a controller
configures any hub. [`spec/reference-server.md`](spec/reference-server.md) describes how the Go
reference server is built and configured; another hub may make every choice there differently and
still interoperate.

## Test vectors

Section 6.6 of the spec requires reference implementations to publish test vectors for facets,
interfaces, schemas, deltas and their hashes, so Go and JavaScript can confirm they agree. The vectors
cover encoding (including the nesting limit), framing (including the pipe binding), the handshake and
`params`, call and control messages, credit accounting, facets, interfaces, schemas, their hashes and
deltas, module signing, status codes, Hub Profile forwarding and the `sparrow.hub.admin` interface.
Behaviour scenarios in `test-vectors/scenarios/` script whole message sequences for session tests. See [`test-vectors/README.md`](test-vectors/README.md) for the file format and the
assumptions behind them.

All keys in the vectors are **test-only** keys derived from trivial seeds. Never trust them in a
real client.

### Regenerate (Go 1.24+)

```sh
cd tools/vectorgen-go
go run . -out ../../test-vectors
git diff --exit-code ../../test-vectors   # no output means the committed vectors are current
```

The generator is deterministic. It fails if its own checks fail, for example if the section 7.7
example no longer encodes to the bytes printed in the spec.

### Verify independently (Node 20+)

```sh
cd tools/verify-js
npm ci
node verify.mjs ../../test-vectors
```

The verifier also checks every scenario message. It re-encodes and decodes every CBOR item with cbor2 (a different CBOR implementation
from the generator's fxamacker/cbor). It recomputes schema canonical forms, deltas and hashes from
the inputs, re-derives keys, key_ids and Ed25519 signatures with `node:crypto`, and re-runs the
module acceptance, interface conformance, compatibility and hub forwarding rules. It exits non-zero
on any disagreement.
