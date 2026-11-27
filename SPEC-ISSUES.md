# Spec issues: resolution log

Questions raised while writing the test vectors, and how the spec author resolved them. The current
spec is `spec/core.md`, revision 305, with the companion `spec/hub-admin.md`, revision 18. Items
26–36 are decisions taken since revision 183, and items O1–O5, raised while applying them, were
decided in core revision 305 and hub-admin revision 18. Every item is **resolved**; the vectors, the
JavaScript verifier and the Go library follow each decision.

The concept called "part" up to revision 183 is called "facet" since then. The vectors, the
generator, the verifier and the Go conformance tests now use "facet" for it everywhere: vector names
(`facet/acme-notes`, `schema/delta-1-replace-facet`, …), JSON keys (`facet_hash`, `facet_hashes`,
`removed_facet_ids_after`, `facet_map`, …), vector types (`facet`, `facet_hash_invariance`,
`facet_owner_table`, `facet_web_keys`) and error codes (`facets_not_sorted`, `facet1_mismatch`,
`reserved_facet_id`, …). No CBOR byte changed: the error texts inside `unimplemented/*` messages keep
the word "part". The table rows below for older revisions keep the names of their time.

## Raised against revision 302 (resolved in core revision 305, hub-admin revision 18)

| # | Question | Decision | Vectors |
| --- | --- | --- | --- |
| O1 | The admin interface hash depended on details hub-admin section 5 did not state (annotations, `errors`, version, how `optional` is typed) | "The interface document is named `sparrow.hub.admin` with version `1.0.0` and carries no annotations, and its methods list no errors, since every error they use is a core code. An `optional` field has flag 0x1 and its plain type; `list<T>` is `[0, T]` and `map<K, V>` is `[1, K, V]`" (hub-admin 5). This changed the interface hash from the first published one: optional fields are no longer typed `[2, T]` | `admin/interface`, `admin/facet` (regenerated) |
| O2 | Is a scalar inside a level-64 container at level 65? | No: "a scalar adds no level" (3.1) | `depth/*` |
| O3 | Does a notification naming an unknown facet or method get an `Error`? | No: "a notification naming one is dropped" (7.1) | scenario `notification-unknown-dropped` |
| O4 | May a tombstone change later? | "A tombstone keeps its last definition and never changes again, apart from its name and annotations" (6.7): its type and flags are frozen | `schema/delta-invalid-existing-tombstone-changes-type`, `schema/delta-invalid-tombstone-flags-changed` |
| O5 | Does `putFacet` canonicalise its input? | Yes: it "stores a facet document, which the hub puts into canonical form and which must be valid as in core spec section 6.6 rule 3" (hub-admin 2.1) | `admin/stored-facet-key` (input unsorted, facet ID 17) |

## Decided since revision 183 (applied for revision 302)

| # | Decision (rev302) | Vectors |
| --- | --- | --- |
| 26 | Facet 1 must match `sparrow.web` by **name** and facet hash (6.1) | `schema/invalid-facet1-renamed` |
| 27 | Interface reachability ("exactly the types and sigils those services reach") does not count references inside tombstones (6.5). No existing interface vector changed: `interface/acme-charts-renderer` has no tombstone | `interface/tombstone-reference-not-counted`, `interface/invalid-reached-only-through-tombstone` |
| 28 | A method with flag 0x2 MUST have output `unit` and no `[4]` in its input (6.4); otherwise the schema is invalid (`invalid_notification`) | `schema/delta-invalid-notification-output`, `schema/delta-invalid-notification-byte-stream` |
| 29 | TypeIds 12–31 are reserved for built-ins of later core versions; a schema that uses one is invalid (6.4, `reserved_type_id`) | `schema/delta-invalid-reserved-type-id` |
| 30 | Making a required field optional is incompatible (6.7) | `schema/delta-invalid-required-made-optional` |
| 31 | Changing a field's or variant's type when it becomes a tombstone is incompatible (6.7) | `schema/delta-invalid-tombstone-changes-type`, `schema/delta-invalid-existing-tombstone-changes-type` |
| 32 | The nesting limit: a message nested deeper than 64 levels is rejected, arrays, maps and tags all count, the message array is level 1 (3.1) | `depth/64-arrays`, `depth/65-arrays`, `depth/64-mixed`, `depth/65-mixed` |
| 33 | Receivers accept any other valid encoding of an ordinary message, shortest or not (3.1) | `non-shortest/credit`, `non-shortest/float-width`, `non-shortest/text-length`, `non-shortest/unsorted-metadata` |
| 34 | `params`: unknown keys are ignored; `maxMessageSize`, `maxInlineBytes`, `sharedCredit` and `leaseCredit` MUST be ≥ 16384 and `maxConcurrentCalls` ≥ 1; a smaller value gets `GoAway(invalid_argument)` (5.4). Go: `wire.Params.Validate`, `wire.ParamMinimum` | `params/validation`, `hello/unknown-params-key`, `goaway/params-too-small`, scenario `credit-violation` |
| 35 | Messages that count zero bytes of credit, such as an empty final `Bytes` chunk, are never held back and never a violation (7.4). Go: `wire.CreditWindow.CanSendCounted` | `credit/sequence-zero-byte-messages`, `credit/sequence-violation`, scenario `server-stream-credit` |
| 36 | The administration interface `sparrow.hub.admin` v1 (hub-admin, core 10.9), with the stored-facet key of hub-admin 2.1. Go: package `adminiface` | `admin.json` |
| — | Vector fix: the description of `map/mixed-keys` called its keys metadata symbols, which -1 and -25 cannot be; it is now a generic `any` map (bytes unchanged) | `map/mixed-keys` |
| — | Behaviour scenarios (scripted message sequences, `test-vectors/scenarios/`) for the reference server's session tests (reference-server design note, section 6) | 13 scenarios |

## Raised against revision 180 (resolved in revision 183)

| # | Question | Decision (rev183) | Vectors |
| --- | --- | --- | --- |
| 24 | Variant names were missing from the 6.1 ASCII rule | Names of types, services, methods, fields, variants and sigils are ASCII (6.1) | `schema/delta-invalid-variant-name-non-ascii` |
| 25 | Is `principal` set on a forwarded notification? | Yes: no `context`, but the hub still sets `principal`; the node calls the hub as itself (10.5) | `forward/notification` |

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
