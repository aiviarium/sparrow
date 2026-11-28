# Sparrow Web Client & Empty Hull (`@aiviarium/sparrow-client`)

Minimal, design-agnostic Web Profile client (spec section 9) built on top of `@aiviarium/sparrow`:

- **Signing & Acceptance (`signing.ts`)**: Ed25519 verification (`crypto.subtle` or injectable), publisher certificates (`web.keys`), revocation lists (`web.revoked`), semver 2.0 & `hostApi` range checks, rollback protection, and `web.*` facet key filtering.
- **Web Profile HTTP Client (`web.ts`)**: `/sparrow/connect`, ticket refresh, hash-verified schema & module/asset fetching, and `ModuleLoader`.
- **Offline Snapshots (`snapshot.ts`)**: Canonical CBOR snapshot encoding/verification, rollback state machine (`Snapshots`), `MemorySnapshotStore`, and `IndexedDBSnapshotStore`.
- **Transport Selection (`transport.ts`)**: WebTransport by default with WebSocket fallback and per-origin preference caching (spec 4.8).
- **Empty Hull & Glue (`hull.ts`)**: `createHull` / `Hull` and `ModuleHost` — connects to a Sparrow hub, verifies and topologically loads signed ESM modules (including a primary shell module and dynamically dialed-in feature modules), handles `SchemaUpdate` reconciliation (`web.apply`), `AuthStatus` / `AuthRefresh`, and exposes a framework-agnostic `shared` runtime bag and `CapabilityRegistry` without baking in UI components or CSS.

```sh
npm install
npm run typecheck
npm test

# Include the real Chromium browser E2E test (WebTransport, WebSocket fallback,
# WebCrypto Ed25519, blob ESM, CSS assets, IndexedDB snapshots, live SchemaUpdate):
SPARROW_BROWSER=1 npm test

# Opt-in stress suites (skipped in default CI):
SPARROW_STRESS=1 npx vitest run test/stress.test.ts
(cd ../go && SPARROW_STRESS=1 go test -v -run TestStress ./hub)
```
