# Sparrow for TypeScript

`@aiviarium/sparrow` is the TypeScript implementation of Sparrow (`../spec/core.md`,
sections 3-8): an own CBOR codec, the wire format, the schema model, the schema-driven value codec
and sessions in either role, over the **pipe** binding (4.7), the **WebSocket** binding (4.6) and an
**in-memory** pair. It mirrors the semantics of the Go reference implementation (`../go`) and is
tested against the shared test vectors and against Go itself.

ESM, TypeScript 5.9, Node 20+ (and browsers for everything except the pipe binding). No runtime
dependencies.

```sh
npm ci
npm test          # builds dist/, then vitest (about 3 s): vectors, scenarios, sessions, bindings,
                  # faults, fuzzing, Go interop and differential checks
npm run typecheck # sources and tests
SPARROW_FUZZ_ITERS=50000 npx vitest run test/fuzz.test.ts test/interop.test.ts   # a longer fuzz run
```

`npm test` builds `../go/cmd/sparrow-interop` with `go build` (Go 1.24); set `SPARROW_SKIP_GO=1` to
skip the Go interop and differential tests when Go is not installed. `SPARROW_VECTORS` points the
conformance tests at another vector directory; `SPARROW_FUZZ_SEED` changes the fuzzing seed.

## Modules

| Import | Contents |
| --- | --- |
| `@aiviarium/sparrow` | Everything below except the pipe binding. Browser-safe (no Node built-ins). Namespaces `cbor`, `wire`, `schema`; the main classes are also exported directly. |
| `@aiviarium/sparrow/pipe` | `pipeConn`, `stdio`, `spawn` (Node only). |
| `@aiviarium/sparrow/websocket` | `connectWebSocket`, `webSocketConn`, `SUBPROTOCOL`. |
| `@aiviarium/sparrow/mem` | `memPair`. |

Source files: `src/cbor.ts`, `wire.ts`, `status.ts`, `sha256.ts`, `schema.ts`, `value.ts`,
`session.ts`, `transport.ts`, `transport/{pipe,websocket,mem}.ts`.

## A node over stdio (the started process is the client)

```ts
import { FacetBuilder, Session, SparrowError, T, field, makeSchema, stream } from '@aiviarium/sparrow';
import { stdio } from '@aiviarium/sparrow/pipe';

// The facet this process publishes in Hello.client_schema.
const b = new FacetBuilder('acme.ext', '1.0.0', { id: 16 });
const notFound = b.errorCode('not_found_here');
const Point = b.struct('Point', [field('x', T.int), field('y', T.int)]);
const svc = b.service('Ext');
svc.method('norm', Point, T.float64, { idempotent: true });
svc.method('ticks', T.uint, stream(T.uint));
svc.notification('log', T.string);
const schema = makeSchema('acme.ext', '1.0.0', [b.build()]);

const session = await Session.connect(stdio(), {
  schema,
  auth: { scheme: 'bearer', credentials: process.env.TOKEN },
  handlers: {
    'acme.ext': {
      norm: (p: { x: number; y: number }) => Math.hypot(p.x, p.y),
      ticks: async function* (n: number, ctx) {
        for (let i = 1; i <= n && !ctx.signal.aborted; i++) yield i;
      },
      log: (s: string) => console.error(s), // never write to stdout: it is the pipe
    },
  },
});

// Calls to the server's facets, by name through the server's schema.
const text = await session.call('host.files', 'read', { path: '/etc/hosts' }, { timeoutMs: 5000 });
for await (const ev of session.stream('host.events', 'watch', null)) console.error(ev);
session.notify('host.log', 'info', 'started');
await session.closed; // the parent ends the session (GoAway, or closing the pipe)
```

The starter (the Sparrow server) uses `spawn(cmd, args)` and `Session.accept(conn, { schema, handlers,
authenticate })`; it can call the child's facets the same way (`session.call('acme.ext', 'norm', ...)`).
`spawn` returns `{ conn, child, exited }`: when the connection ends the child gets `killAfterMs`
(default 5 s) to exit before it is killed, and `exited` resolves with its code or signal.

## API

### Session

```ts
Session.connect(conn: Conn, opts?: SessionOptions): Promise<Session>   // client: Hello -> Welcome -> Ready
Session.accept(conn: Conn, opts?: SessionOptions): Promise<Session>    // server: resolves once Ready arrived

session.call(facet: string | number, method: string | number, input?: unknown, opts?: CallOptions): Promise<unknown>
session.stream(facet, method, input?, opts?): ClientCall      // AsyncIterable of the output items
session.open(facet, method, input?, opts?): ClientCall        // low level: send()/end() by hand
session.notify(facet, method, input?, { metadata }?): void    // call ID 0, best-effort
session.updateSchema(schema: Schema, { ackTimeoutMs }?): Promise<void>  // SchemaUpdate; resolves at SchemaAck
session.goAway(status = going_away, reason = '', retryAfterMs = null): void  // drain
session.close(status = going_away, reason = ''): Promise<CloseInfo>          // GoAway + close now
session.ping(): void
session.refreshAuth(auth) / session.sendAuthStatus(status, expiresAt)       // 5.5
session.closed: Promise<CloseInfo>          // { code, reason, remote }; never rejects
session.role, principal, sessionId, hello, welcome, peerSchema, peerEpoch, localSchema,
       limits ({ local, peer }), isOpen, isDraining, goAwayReceived, openCalls
session.peerFacet(name | id), session.peerCodec(name | id)
```

Facets and methods are named by name (`'acme.ext'`, `'norm'` or `'Ext.norm'`) or by ID, resolved
through the **peer's** schema (6.1: all IDs in a call belong to the callee's schema).

`call` covers unary methods, client streams (input is an `Iterable` or `AsyncIterable` of items,
sent with credit, then `End`), uploads (`[4]` input: a `Uint8Array` or an iterable of chunks) and
downloads (`[4]` output: resolves with the token-0 bytes). For a stream output it drains the items
and resolves with `undefined`; use `stream` instead. `stream` covers server streams and bidi streams
(input as for `call`). Calls wait for a free `maxConcurrentCalls` slot of the peer.

`SessionOptions` (all optional):

| Option | Side | Meaning |
| --- | --- | --- |
| `schema` | both | This peer's schema: `Welcome` (server) or `Hello.client_schema` (client). A client without one cannot be called and cannot publish one later. |
| `handlers` | both | A `Router` or `{ [facetName]: { [methodName or 'Service.method']: Handler } }`. |
| `params` | both | The limits this peer imposes on the other (5.4), e.g. `{ maxMessageSize: 4 << 20, idleTimeoutMs: 60000 }`. |
| `caps`, `props` | both / server | `Hello`/`Welcome` caps, `Welcome.props`. |
| `auth`, `versions` | client | `Hello.auth` (`{ scheme, credentials }`), offered versions (default `[1]`). |
| `knownSchema`, `knownParams`, `optimistic` | client | A cached server schema (offered as `known_schema`) and optimistic start (5.3). |
| `fetchSchema(location, hash)`, `onServerSchema(hash, schema, params)`, `onAuthStatus` | client | Out-of-band offers, cache updates, `AuthStatus`. |
| `authenticate(hello) => principal` | server | A throw closes with `GoAway(unauthenticated)` (or the core status of a thrown `SparrowError`). |
| `acceptClientSchema(principal, schema)`, `schemaByHash(hash)`, `offerLocation(hash)`, `maxClientSchemaSize`, `onAuthRefresh` | server | Client-schema policy (64 KiB and depth 32 by default), `Delta` and out-of-band offers, `AuthRefresh`. |
| `onPeerSchemaUpdate(s, {epoch, hash, delta, schema})`, `onGoAway(s, goaway)`, `log(msg)` | both | Hooks (the update hook runs before `SchemaAck`). |
| `helloTimeoutMs` (10 s), `schemaAckTimeoutMs` (10 s), `cancelGiveUpMs` (5 s), `cancelBrokenMs` (30 s), `gracePeriodMs` (30 s), `lingerMs` (1 s) | both | Timers. |
| `clock` | both | `{ now(), setTimeout(f, ms), clearTimeout(t) }` for every protocol timer (default `realClock`); tests pass a fake one. |

`CallOptions`: `signal` (sends `Cancel(cancelled)`), `timeoutMs` (sends the `deadline` key and
`Cancel(deadline_exceeded)` when it passes), `metadata` (a `Map<number | string, unknown>` or an
object of text keys), `credit` (the `credit` key: initial credit for the callee's half; with 0 the
callee waits until the application first waits for output, when the default window is granted),
`onProgress({ done, total, note })`, `onHeaders(metadata)`.

### ClientCall

```ts
for await (const item of call) ...      // output items; throws the callee's SparrowError
await call.result()                     // Response value (or token-0 bytes, or undefined for a stream)
await call.send(item); await call.end(trailers?)   // stream input by hand (with open())
await call.sendBytes(token, data, fin = true); await call.bytes(token)
for await (const chunk of call.byteChunks(token)) ...   // a token chunk by chunk
call.cancel(status = cancelled)
call.headers: Promise<Metadata>         // Headers, or an empty map if the callee sent data first
call.trailers: Promise<Metadata>        // the callee's End trailers
call.id
```

Breaking out of a `for await` loop cancels the call. A cancelled call rejects at once; the session
keeps counting it until the callee's final message arrives (7.5).

### Handlers

```ts
type Handler = (input: any, ctx: CallContext) => unknown;
```

- `input` is the decoded `Request` input; for a stream input (`[3, T]`) an `AsyncIterable` of the
  decoded items (pulled with credit; it throws `SparrowError(cancelled)` on `Cancel`); `null` for a
  `[4]` input (read it with `ctx.bytes(0)` or `ctx.byteChunks(0)`).
- The result finishes the call: the output value for a unary method (`undefined` is `null` for
  `unit`); for a stream output an `Iterable`/`AsyncIterable` of items (an async generator is the
  natural form), or nothing after sending items with `ctx.send`; for a `[4]` output a `Uint8Array`, or
  nothing after `ctx.sendBytes(0, ...)`.
- Throw `new SparrowError(status, message?, details?)` to answer `Error`. `status` is a core code
  (`Status.not_found`), a core name (`'not_found'`) or the name of an error code of the method's facet
  (`'not_found_here'`, defined with `FacetBuilder.errorCode`). `details` of the form `{ type, value }`
  (type: TypeId or type name of the facet) is sent as a `dynamic` value (8: SHOULD); anything else as a
  generic CBOR value. Any other exception answers `unknown` with its message; an output that does not
  encode answers `internal`.
- A `Cancel` or a passed deadline is answered by the session at once (`Error(cancelled)` /
  `Error(deadline_exceeded)`) and aborts `ctx.signal`; the handler's later result is ignored.

`CallContext`: `signal`, `metadata` (the Request metadata), `deadline` (epoch ms), `principal`
(the server session's principal, else the `principal` metadata key), `session`, `callId`, `facet`,
`method`, `notification`, `progress(done, total?, note?)`, `sendHeaders(md?)`, `send(item)`,
`setTrailers(md)`, `sendBytes(token, data, fin?)`, `bytes(token)`, `byteChunks(token)`.

Byte data is granted back as credit when the application takes it: `bytes(token)` collects a token
(any size) in memory, `byteChunks(token)` hands it over chunk by chunk. Data for a token nobody
reads stays buffered and holds the sender back, so read referenced tokens in the order they are
sent, or concurrently.

A `Router` can be used instead of a map: `new Router().handle('acme.ext', 'norm', h).fallback(h2)`;
facets and methods match by name, `Service.method` or ID.

### Errors

`SparrowError extends Error`: `status: number` (core code 0-31 or a facet error sigil; -1 for an
unresolved name before sending), `code: string` (core name or the facet's sigil name), `rawMessage`,
`details` (received: `{ type, typeName, value }` when the details decode as a `dynamic` value of the
callee's facet, otherwise the generic CBOR value), `detailsRaw: Uint8Array`, `remote` (the status came
from the peer), `notDispatched` (the callee certainly did not run the call: it may be retried as is).
Local failures: `invalid_argument` (input does not encode), `unimplemented` (no such facet or method
in the peer's schema), `message_too_large`, `going_away` (draining), `unavailable` (session closed),
`cancelled` / `deadline_exceeded`. `Status` holds the codes by name; `statusName(code)`,
`statusByName(name)`, `webSocketCloseCode(code)`, `truncateReason(reason, max)` are in `status.ts`.

### Schemas

`schema.ts` models section 6 in its wire shape:

```ts
type TypeRef = number | [0, T] | [1, K, V] | [2, T] | [3, T] | [4];   // list, map, optional, stream, byte stream
interface Facet { id; name; version; types: TypeDef[]; services: Service[]; sigils: Sigil[];
                  implements: Uint8Array | null; retired: [space, id][]; annotations: Record<string, unknown> }
type TypeDef = { kind: 'struct', id, name, fields: Field[], flags, annotations }   // flags 0x1 sparse
             | { kind: 'enum', id, name, values: number[], annotations }
             | { kind: 'union', id, name, variants: Field[], annotations }
             | { kind: 'alias', id, name, target: TypeRef, annotations };
interface Field { tag; name; type: TypeRef; flags; annotations }      // 0x1 optional, 0x2 deprecated, 0x4 removed
interface Method { id; name; input; output; errors: number[]; flags; annotations }
interface Schema { format: 2; name; version; facets: Facet[]; annotations }
```

`T` holds the built-in TypeIds (`T.string`, ...); `list`, `mapOf`, `optional`, `stream`, `byteStream`
build references. `FacetBuilder(name, version, { id })` mirrors `go/node.FacetBuilder`: `struct`,
`sparseStruct`, `union` (with `variant(name, type)`), `alias`, `enum(name, values)` (returns `{ type,
values: { name: sigil } }`; each value becomes a kind-0 sigil named `<enum>.<value>`, 6.5), `errorCode`, `symbol`,
`service(name).method(name, in, out, { id, idempotent, shared, errors, annotations })` and
`.notification(name, in)`; flags 0x8/0x10 follow from the types; `build()` validates. IDs are assigned
in order (types and sigils from 64, services and methods from 0) unless fixed. `makeSchema(name,
version, facets)` wraps facets in a document.

Also: `encodeSchema`/`decodeSchema` (and for facets, interfaces, deltas), `canonicalSchema`,
`facetHash`, `interfaceHash`, `schemaHash` (`0x01 || SHA-256`, synchronous), `validateSchema`,
`validateFacet`, `validateInterface`, `checkCompatible` (6.7), `conforms` / `verifyImplements` (6.5),
`SchemaState` (`create`, `apply(delta)`, `applyUpdate(epoch, hash, delta)`, `hash`, `epoch`,
`removedFacetIds()`), `diff(old, new)`, `webFacet()`. Errors are `SchemaError` with the vectors'
vocabulary in `code` (`incompatible_change`, `facets_not_sorted`, `duplicate_sigil_name`, ...).

### Values (schema-driven, 3.4)

| Schema type | JS value (decoded) | Also accepted when encoding |
| --- | --- | --- |
| `unit` | `null` | `undefined` |
| `bool` | `boolean` | |
| `int`, `uint` | `number` if it is a safe integer, else `bigint` | either |
| `float32`, `float64` | `number` (always encoded as a float, shortest exact width; float32 rounded) | `bigint` |
| `string` | `string` | |
| `bytes` | `Uint8Array` | |
| `timestamp` | `Date` (tag 1; sent as integer seconds when there is no fraction, else float seconds; received float seconds are rounded to the nearest millisecond, halves up, as Go's `cbor.Time.UnixMilli`; NaN, infinities and times beyond `Date`'s ±8.64e12 s are refused) | epoch seconds as a `number` or `bigint` |
| `uuid` | `string`, lowercase `8-4-4-4-12` | `Uint8Array` of 16 bytes |
| `dynamic` | `{ type: TypeId, value }` | `type` as a type name or built-in name |
| `symbol` | `string` (a kind-2 sigil decodes to its name; another sigil to its number) | a sigil `number` |
| enum | the value name: the sigil name without its `<enum>.` prefix (`'green'` for `Color.green`); an unknown value decodes as its sigil `number` | the full sigil name (`'Color.green'`), the sigil `number` |
| struct, sparse struct | object keyed by field name; absent optional fields are left out | `undefined`/`null` for absent |
| union | `{ variant: name, value }`; an unknown variant is `{ variant: tag, value: <generic CBOR> }` | `variant` as a tag |
| alias | the target's representation | |
| `[0, T]` list | `Array` | |
| `[1, K, V]` map | object when `K` is `string` (or an alias of it), otherwise `Map` | `Map` or object |
| `[2, T]` optional | `null` or `T`'s value | `undefined` |
| `[4]` inside a value | the byte token (`number`) | |

Encoding omits trailing nulls of positional structs, writes `null` for removed fields and absent
optional fields, sorts map keys canonically and rejects unknown fields and missing required fields.
Decoding skips elements and sparse tags it does not know. `new Codec(facet)` gives
`encode(type, value)` / `decode(type, bytes)` by hand.

### CBOR and wire

`cbor.encode(value)` / `cbor.decode(bytes, { maxDepth, extraTags, noFloats, requirePreferred })`
use a generic representation: integers as `number` or `bigint`; floats as `number`, except a float
with an integral value, which decodes as a `Float` (so it re-encodes as a float); `Uint8Array`;
`string`; `Array`; `Map` (encoders also take plain objects); `Tag`; `true`/`false`/`null`. `Raw`
wraps encoded bytes. Every encoding is Core Deterministic (preferred serialization, sorted keys).
`cbor.Reader` is a pull reader; `validate`, `isCanonical`, `canonical` help with untrusted and
canonical data.

`wire.encodeMessage(m)` / `wire.decodeMessage(bytes)` handle every message of 5.4, 5.5 and 7.2 as
plain objects tagged with `kind` (`{ kind: 16, callId, facetId, methodId, metadata, input }`, ...);
payloads (`input`, `output`, `value`, `details`, schemas, deltas) stay encoded `Uint8Array` views.
Also: `encodeVarint`, `decodeVarint`, `frame`, `FrameDecoder` (rejects a frame above
`maxMessageSize` from its prefix), `kindRange`, `classifyStreamHeader`, `limitsOf`, `checkParams`,
`DEFAULTS`, `MetaKeys`, `countedBytes`, `CreditWindow`. Numbers that the protocol puts in a JS
`number` (IDs, counts, lengths, timestamps in messages) must stay within 2^53 - 1: a larger one is
refused as malformed, and a larger credit amount or `retry_after_ms` saturates there.

### Transports

A `Conn` moves whole messages on the shared lane: `start(handlers)`, `send(msg)`,
`setReadLimit(n)`, `close(code, reason)`, `closed`, `binding`. Implement it to add a binding.

- **Pipe** (`/pipe`): `pipeConn(readable, writable, { lingerMs })`, `stdio()` (this process's stdin
  and stdout; the started process is the client), `spawn(cmd, args, { killAfterMs, ...spawnOptions })
  => { conn, child, exited }` (the starter's end; stderr inherited). Varint length prefixes, no stream
  header; a frame above `maxMessageSize` is refused from its prefix (the messages before it in the
  same read are still delivered). `close` finishes the write side and waits up to `lingerMs` (2 s)
  for the peer's end, not at all when the peer has already gone. Status and reason travel only in
  `GoAway`.
- **WebSocket** (`/websocket`): `connectWebSocket(url, { WebSocket?, timeoutMs, signal })` opens with
  subprotocol `sparrow.v1` (browsers, Node 22's global `WebSocket`, or pass the `ws` package's
  class); `webSocketConn(ws)` wraps an open socket on either side (for example one accepted by a `ws`
  server, which must select `sparrow.v1` and check `Origin`). One binary message per Sparrow
  message; close codes 1000 / 4000 + status with the reason cut to 123 bytes.
- **In-memory** (`/mem`): `memPair()` returns two connected `Conn`s for tests.

## What is implemented, and what is not

Implemented: everything of sections 3-8 that applies to a session on a shared lane: the handshake
(version check, params and their minimums, credential hook, client schema limits, offers
`Unchanged` / `Delta` / `Full` / out-of-band, optimistic start with its mismatch rules, the 64 KiB
pre-authentication buffer), control messages (`SchemaUpdate`/`SchemaAck` with the rule-1 gate and the
10 s ack timer, `AuthRefresh`/`AuthStatus`, `Ping`/`Pong` and the idle timeout, `GoAway` drain and
grace period), every call shape, `Headers`, `Progress`, `End` trailers, `Error` with details,
`Cancel` on both sides (with the 5 s / 30 s give-up rules), deadlines, credit (grants at half the
window, violations answered with `Error(protocol_error)` / `Cancel(protocol_error)`), call-ID parity,
`maxConcurrentCalls` (callers wait, callees refuse excess), `maxMessageSize` on both sides, unknown
kinds by range, notifications (dropped when unknown, best-effort with a cap of 64 in flight).

Not implemented:

- **WebTransport and leased streams** (4.2, 4.5): every binding here has only the shared lane, so
  `maxStreams` and `leaseCredit` never apply and every call runs with `sharedCredit`.
- Credit windows stay at the initial credit (no growth toward the bandwidth-delay product);
  `maxInlineBytes` is not enforced on values.
- No client bookkeeping across sessions (the two-rejected-optimistic-starts rule of 5.3, the
  transport per origin of 4.8); no reconnect loop. `spawn` does not restart a child.
- The Web Profile (section 9: `/connect`, tickets, module signing, snapshots) and the Hub Profile
  (section 10) are out of scope; the `context`/`principal` metadata keys are only passed through.

Choices: byte chunks are at most 16 KiB (the shared-lane recommendation of 7.8); `GoAway` reasons
are cut to 1024 bytes.

## Tests

| File | What |
| --- | --- |
| `test/vectors.test.ts` | Every vector of `encoding`, `framing`, `handshake`, `calls`, `credit`, `schema`, `status` and `admin` (238 of 303, printed as "vector coverage"); `signing.json` (55, Web Profile) and `hub.json` (10, Hub Profile) are skipped as out of scope. Also every message of every scenario. |
| `test/scenarios.test.ts` | All 14 behaviour scenarios of `test-vectors/scenarios`, run against a real server session by a scripted raw client (shared lane only, so `stream_idle` / `streams_open` do not apply). |
| `test/session.test.ts`, `test/rawpeer.test.ts` | Sessions over the in-memory binding: the interop suite TS to TS, handshake failures, optimistic start, GoAway, limits, schema updates and rule 1 of 6.6, byte streams beyond the credit window, credit 0, protocol violations by raw peers; timeouts (idle and Ping, unanswered Cancel, schema ack, deadlines, linger) on a fake clock (`test/helpers/clock.ts`). |
| `test/value.test.ts` | Enum value names and duplicate sigil names (6.5), timestamps (the rounding table shared with `go/cbor`). |
| `test/pipe.test.ts`, `test/websocket.test.ts` | The bindings: in-process streams, a child process on its stdio, a `ws` server. |
| `test/pipefaults.test.ts` | The pipe binding with writes cut into 1-7 bytes, stalls, the stream ending mid-message and at every point of the handshake, a child process killed in the middle of a call and of a download: calls end with `unavailable`, no session counts a call. |
| `test/fuzz.test.ts` | Property tests of every decoder (CBOR, messages, framing, schemas, facets, interfaces, deltas, values, the handshake of both roles) on the vectors' bytes and seeded mutations: only the library's error types, round trips, nothing held beyond the input. `SPARROW_FUZZ_ITERS` (default 2000), `SPARROW_FUZZ_SEED`; crashers stay in `test/helpers/fuzz.ts`. |
| `test/interop.test.ts` | Against Go (`go/cmd/sparrow-interop`): a TS client started by a Go `session.NewServer`, and a Go client started by a TS server, each running the interop suite of `test/fixture/interop.mjs` (unary, server/client/bidi streams, notification, error with details, cancel, deadline, progress, a byte-identical round trip of every value type, byte streams, headers and trailers, calls to the client's facet). A differential check sends the fuzzing inputs to `sparrow-interop decode`: Go and TS must accept and reject the same CBOR, messages, schemas and timestamps and re-encode them to the same bytes (known differences: integers beyond 2^53 - 1, times beyond `Date`). |
| `test/cbor.test.ts` | The codec against `cbor2` on random values, random and truncated input, SHA-256. |
