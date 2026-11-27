# Sparrow RPC: Go reference implementation (phase 1)

Module `github.com/aiviarium/sparrow-rpc/go`, Go 1.24. This phase covers the encoding, wire format,
schema model and web-profile signing of the core spec (`../spec/core.md`). Sessions, transports and
the hub come later and build on these packages.

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
