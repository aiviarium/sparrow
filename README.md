# Sparrow RPC

Sparrow RPC is a binary, bidirectional, streaming RPC protocol. At session start the server sends a
schema describing its services and types; after that, messages refer to methods, types and enum
values by compact numeric IDs, so a client can call services it was never compiled against.
Messages are CBOR, the primary transport is WebTransport (WebSocket as fallback), the reference
server is Go and the primary client is a browser.

**Status: draft.** The spec is a working draft and will change; so will the vectors.

**License: TBD.** No license has been chosen yet.

## Repository layout

```
spec/core.md             Core protocol specification with the Web and Hub profiles (snapshot of draft revision 183)
SPEC-ISSUES.md           Resolution log of spec questions raised while writing the test vectors
test-vectors/            Test vectors, one JSON file per area, and their format (README.md)
tools/vectorgen-go/      Go program that generates the vectors (canonical reference)
tools/verify-js/         Independent Node.js verifier (cbor2 + node:crypto)
.github/workflows/       CI: regenerate, check for drift, verify
```

## Test vectors

Section 6.6 of the spec requires reference implementations to publish test vectors for parts,
interfaces, schemas, deltas and their hashes, so Go and JavaScript can confirm they agree. The vectors cover encoding, framing (including the pipe binding),
the handshake, call and control messages, credit accounting, parts, interfaces, schemas, their
hashes and deltas, module signing, status codes and Hub Profile forwarding. See [`test-vectors/README.md`](test-vectors/README.md) for the file format and the
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

The verifier re-encodes and decodes every CBOR item with cbor2 (a different CBOR implementation
from the generator's fxamacker/cbor). It recomputes schema canonical forms, deltas and hashes from
the inputs, re-derives keys, key_ids and Ed25519 signatures with `node:crypto`, and re-runs the
module acceptance, interface conformance, compatibility and hub forwarding rules. It exits non-zero
on any disagreement.
