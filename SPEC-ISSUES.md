# Spec issues: resolution log

Questions raised while writing the test vectors, and how the spec author resolved them. The current
spec is `spec/core.md`, revision 180. Every item below is **resolved**, and the vectors follow
each decision.

## Raised against revision 164 (resolved in revision 180)

| # | Question | Decision (rev180) | Vectors |
| --- | --- | --- | --- |
| 1 | "`implements` sorted bytewise" in the canonical form | Removed from the sort list (6.6) | — |
| 2 | Order of `parts` in a sent schema | A schema lists its parts sorted by ID (6.1); canonical form sorts them (6.6). A received schema with parts out of order breaks a rule of 6.1 and is invalid (6.6 rule 3) | `schema/sent-parts-out-of-order` |
| 3 | Version of part 1 `sparrow.web` | Fully defined: version `1.0.0`, no types, sigils, interface, retired IDs or annotations; MUST match by part hash (6.1, 9.4) | `part/sparrow-web`, `schema/delta-invalid-part1-mismatch` |
| 4 | Reserved part IDs | 0 and 2–15 MUST NOT appear (6.1) | `schema/delta-invalid-reserved-part-id` |
| 5 | Compatibility rules | 6.7 table now explicit: a new field only if optional; enum values and required fields can't be removed; tombstones are permanent; kind, sparse flag, alias target, field and variant types and sigil kind are fixed; `retired` only grows; methods may move between services | `schema/delta-*` |
| 6 | Major version in an in-place replace | Major = first number of `version`, 0 included; changing it in place is invalid (6.7) | `schema/delta-invalid-major-in-place` |
| 7 | Re-adding a removed part ID | Only for the same name and major, as a compatible successor (6.1) | `schema/delta-3-readd-part`, `schema/delta-invalid-readd-renamed` |
| 8 | References inside tombstones | Not checked (6.6 rule 3) | `part/acme-notes` (tombstone at Note tag 5) |
| 9 | Implementing a service with extra methods | A service's wire shape leaves out its method list; each interface method is compared on its own, so parts may add methods (6.5) | `conformance/extra-method-in-service` (passes), `conformance/method-in-other-service` (fails) |
| 10 | Hint flags in wire shapes | Cleared: method 0x1 and 0x4, field 0x2 (6.5) | `conformance/hint-flags-differ` (passes) |
| 11 | A float in a schema | Makes it invalid (6.6 rule 3) | `schema/delta-invalid-float` |
| 12 | Module id equal to the part name | Allowed: equal, or starts with the name and a dot (9.4) | `module-scope/acme.charts/acme.charts` |
| 13 | `<hub-id>/` vs `<peer-id>/` | `<peer-id>/` everywhere (9.4, 10.8) | `module-scope/hub-b_acme.charts/*` |
| 14 | Unicode in names | Part names, node IDs and module ids follow `[a-z0-9-]+(\.[a-z0-9-]+)*` (ASCII); names of types, services, methods, fields and sigils are ASCII (6.1, 9.4) | `schema/delta-invalid-part-name-*`, `schema/delta-invalid-type-name-non-ascii`, `module-scope/acme.charts/acme.charts.Ui`, `…/acme.charts.café` |
| 15 | A revocation entry naming a root key | Ignored; the rest of the list applies (9.5) | `verify/root-not-revocable`, `verify/publisher-revoked-by-list-naming-root` |
| 16 | Where `web.keys`, `web.revoked` and client configuration live | Top-level schema annotations only (9.4) | `module-scope/part-web-keys` |
| 17 | Context for forwarded notifications | None: call ID 0 on both hops, no `context`; the node acts as itself (10.5) | `forward/notification` |
| 18 | What "payload" means | Everything except the call ID, the part ID and a Request's metadata (10.5) | `forward/unary`, `forward/error-relay` |
| 19 | `credit` when forwarding | The hub may set it no higher than the caller's value, or than the default for the caller's stream (10.5) | `forward/unary` |
| 20 | Principal grammar | ASCII; `<hub-id>` follows the node-ID grammar (10.4) | `hub/principals` |
| 21 | Unknown part or method | `Error(unimplemented)` (7.1) | `unimplemented/unknown-part`, `unimplemented/unknown-method` |
| 22 | Truncating close reasons | Senders shorten at a character boundary (8) | `status/close-reason-truncation` |
| 23 | Reserved codes 23–31 in WebSocket closes | The mapping covers all core codes 0–31 (8) | `status/reserved-23-31` |
| C1 | Module `sig` key_id | That of the key that signed it, root or publisher (9.5, normative) | `module/*` |
| C2 | Check order for module acceptance | Doesn't change the verdict (9.5, normative) | `verify/*` |
| C3 | Hub call IDs on a pipe link | Odd: the hub is the Sparrow server there (4.7, 7.1) | `forward/*` |
| C4 | Deadline lowering in the forwarding vector | Whole milliseconds; the vector assumes 50 ms elapsed (test data, not a protocol rule) | `forward/unary` |

## Raised against revision 108 (resolved in revision 164)

| # | Question | Decision |
| --- | --- | --- |
| A1 | Integral floats in canonical data | Canonical data MUST NOT contain floats (3.2) |
| A2 | Schema hash definition, 1.4 vs 6.6 | `0x01 ‖ SHA-256` everywhere |
| A3 | Meta-schema numbering | Meta-schema removed; TypeIds 32–63 reserved |
| A4 | Domain prefix byte format | Canonical CBOR of `[domain, value]` (9.5) |
| A5–A7 | Status mapping for transports | Core codes only; WebSocket `ok` = 1000, otherwise 4000 + code (8) |
| A8, A9 | `any` naming; composite types in it | CDDL `any`; Sparrow type `dynamic`, composites via alias (6.2, 6.3) |
| A10, A11 | Retired IDs; sigil annotation changes | Per-part `retired`; whole-part replace (6.2, 6.6) |
| A12 | Service for `moduleRejected` | Part 1, service 0, method 0 (9.4) |
| A13, A14 | `trace` format; Ping and AuthStatus field types | 26 bytes; uint and timestamp (5.5, 7.2) |
| A15 | Status for a drain | `going_away` (5.6) |
| B16–B27 | Signed bytes, certificate rules, URL hashes, credit counting, trailing nulls, varints, deltas, ID ranges, End flags, annotations, `params` keys | Settled in 3.4, 4.1, 6.1, 6.3, 6.4, 6.6, 7.4, 9.1 and 9.5 |
