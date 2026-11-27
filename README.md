# Sparrow

Sparrow is a binary, bidirectional, streaming RPC protocol. At session start the server sends a
schema describing its services and types; after that, messages refer to methods, types and enum
values by compact numeric IDs, so a client can call services it was never compiled against.
Messages are CBOR, the primary transport is WebTransport (WebSocket as fallback, and a pipe binding
for peers on one machine, such as a process and the extensions it starts), the reference server is
Go and the primary client is a browser.

**Status: draft.** The spec is a working draft and will change; so will the vectors.

Dual-licensed under MIT (`LICENSE-MIT`) or Apache-2.0 (`LICENSE-APACHE`), at your option.

## Repository layout

```
spec/core.md               Core protocol specification with the Web and Hub profiles (snapshot of the draft)
spec/hub-admin.md          Sparrow Hub Administration: the sparrow.hub.admin v1 interface (companion, snapshot of the draft)
spec/reference-server.md   Design note for the Go reference server (not part of the spec)
test-vectors/              Test vectors, one JSON file per area, and their format (README.md)
test-vectors/scenarios/    Behaviour scenarios: scripted message sequences with expected outcomes
tools/vectorgen-go/        Go program that generates the vectors (canonical reference)
tools/verify-js/           Independent Node.js verifier (cbor2 + node:crypto)
go/                        Go reference implementation, module github.com/aiviarium/sparrow/go (see go/README.md)
ts/                        TypeScript implementation, npm package @aiviarium/sparrow (see ts/README.md)
e2e/browser/               Browser end-to-end test: a minimal page in headless Chromium (Playwright)
.github/workflows/ci.yml   CI: Go vet/gofmt/race tests, vectors (regenerate, drift, verify-js), fuzzing, browser test, TS
```

The core specification defines the protocol. Its bindings are WebTransport (4.5), WebSocket (4.6) and
the optional pipe binding (4.7): one ordered byte stream between peers on one machine, such as a
child process's standard input and output, where the started process is the client. Both
implementations have it (`go/transport/pipe`, `ts/src/transport/pipe.ts`); the hub does not use it,
since a hub never starts processes. The TypeScript package exists for tools that run extensions as
child processes and speak Sparrow to them, with JavaScript extensions on a TypeScript runtime; it
has the pipe, WebSocket and in-memory bindings, and is tested against the vectors and against Go. [`spec/hub-admin.md`](spec/hub-admin.md) is the companion
document that section 10.9 of the core refers to: the standard interface through which a controller
configures any hub. [`spec/reference-server.md`](spec/reference-server.md) describes how the Go
reference server is built and configured; another hub may make every choice there differently and
still interoperate.

## Test vectors

Section 6.6 of the spec requires reference implementations to publish test vectors for facets,
interfaces, schemas, deltas and their hashes, so Go and JavaScript can confirm they agree. The vectors
cover encoding (including the nesting limit), framing, the handshake and
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

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request, in five jobs: **go** (`go vet`,
`gofmt -l`, `go test -race ./...` in `go/`), **vectors** (regenerate with `tools/vectorgen-go`,
`git diff --exit-code test-vectors`, then `tools/verify-js`), **fuzz** (every Go fuzz target for
15 s, one job per package; failing inputs are kept as an artifact), **browser** (`TestBrowser`
in headless Chromium, installed with Playwright in that job; `SPARROW_CHROMIUM` picks another
binary) and **ts** (Node 20 and 22: `npm ci`, type check, `npm test` with the Go interop and
differential tests; on Node 22 also a longer fuzz and differential run). See `go/README.md` for
running the fuzzers and the network-fault tests locally, and `ts/README.md` for the TypeScript tests.
