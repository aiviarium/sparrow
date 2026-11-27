# Spec issues: resolution log

Questions raised while writing the test vectors and the Go reference implementation, and how the
spec author resolved them. The current spec is `spec/core.md`, revision 377, with the companion
`spec/hub-admin.md`, revision 38; the scope change S1–S7 below came with core 347 and hub-admin 35,
and its follow-ups S8–S16 with core 360–377 and hub-admin 36–38. Items P1–P16, raised by the Go hub (phase 3), were decided in core
revision 324 and hub-admin revision 25; items 26–36 are decisions taken since revision 183, and
items O1–O5, raised while applying them, were decided in core revision 305 and hub-admin revision 18.
Every item is **resolved**; the vectors, the JavaScript verifier and the Go library follow each
decision.

The concept called "part" up to revision 183 is called "facet" since then. The vectors, the
generator, the verifier and the Go conformance tests now use "facet" for it everywhere: vector names
(`facet/acme-notes`, `schema/delta-1-replace-facet`, …), JSON keys (`facet_hash`, `facet_hashes`,
`removed_facet_ids_after`, `facet_map`, …), vector types (`facet`, `facet_hash_invariance`,
`facet_owner_table`, `facet_web_keys`) and error codes (`facets_not_sorted`, `facet1_mismatch`,
`reserved_facet_id`, …). No CBOR byte changed: the error texts inside `unimplemented/*` messages keep
the word "part". The table rows below for older revisions keep the names of their time.

## Scope change in core revision 347 and hub-admin revision 35

The owner reduced the scope: **the hub never starts, installs or supervises nodes.** Nodes dial in,
or the hub dials a configured node (URL and SPKI pin). An outside system (an orchestrator, a service
manager, a person) provisions nodes and hands them the hub's URL and a credential, or registers them
through `sparrow.hub.admin`. This was a decision, not a question raised here; P12 below (lazy start
of a spawned node, `ref.lazy`) is superseded by it.

| # | Change | Spec | Go / vectors |
| --- | --- | --- | --- |
| S1 | Two link kinds only, "The node dials in" and "The hub dials a configured node at its URL"; identity no longer mentions processes; "A hub never installs, starts or supervises nodes" | core 10.2, 10.10, hub-admin 2.2 | spawning removed from `hub` (supervision, process groups, crash backoff and the `failed` state, `ref.lazy`, environment from secrets, restart on change) and from `admin`, `sparrow-hub` and `sparrow-admin` |
| S2 | 10.7 "Offline nodes": a call waits "for at most a connect timeout (RECOMMENDED 10 s), and then fails with `Error(unavailable)`"; the rule for restarting spawned nodes is gone | core 10.7 | `hub.Options.ConnectTimeout`, static key `connectTimeoutMs` (was `startTimeoutMs`); dialed nodes are redialed with backoff, sooner while calls wait; `TestOfflineEchoProcesses`, `TestDialedNodeRedials` |
| S3 | The pipe binding stays as a generic binding: "a hub itself never starts processes" | core 4.7 | `transport/pipe` and `node.RunStdio` kept as library features, unused by the hub; pipe vectors described accordingly (bytes unchanged) |
| S4 | `NodeConfig` field 0 is `dial optional Dial`; `Start`, `Spawn`, `EnvValue` and `Other` are removed and the types renumbered (64 `Config` … 79 `NodeState`); `NodeState` is `connected`, `offline`, `disabled`, `removed` (sigils 67–70); commit problems are `[71, problems]` | hub-admin 3, 5.1, 5.2 | `adminiface`, `admin`, `admin.json` regenerated: new interface hash; `admin/value/event-node-failed` became `admin/value/event-node-offline` |
| S5 | Validation: exactly one of `dial` or `credential`; no `Dial.credential` with the same value as a `NodeConfig.credential`; the `Spawn` and `Other.kind` rules are gone | hub-admin 3 | `TestValidate` (`replayable credential value`) |
| S6 | Problem paths use the field names of section 3 (`["nodes", "acme.notes", "dial", "pin"]`) | hub-admin 5.1 | `admin/value/problems`; the JSON form writes `{"dial": ...}` and refuses `start` |
| S7 | Call counting: "The caller counts a call until it has both sent its own last message and seen the callee's; the callee counts it only until it has sent its own final message"; a callee "MAY close a session that keeps more than twice `maxConcurrentCalls` calls with the caller's half still open with `GoAway(resource_exhausted)`" | core 7.6 | `session`: the callee uncounts at its final message also while the caller's half is open; the 2× bound; `TestCalleeUncountsAtItsFinalMessage`, `TestCallerCountsUntilCalleesFinal`, `TestCallerHalfOpenBound` |

Follow-ups in core revisions 360–377 and hub-admin revisions 36–38 (S7's 2× bound is withdrawn by S9):

| # | Change | Spec | Go / vectors |
| --- | --- | --- | --- |
| S8 | The pipe binding is deleted; transport selection is now 4.7 | core 4 | `transport/pipe`, `node.RunStdio` and echo-node's stdio mode removed; the vector `pipe/node-hello` removed, `hello/node-pipe` and `welcome/node-pipe` became `hello/node-dial-in` (presenting `["link", credential]`) and `welcome/node-dial-in` |
| S9 | "The callee counts a call from its `Request` until it has sent its own final message or ended its direction of the call's stream, and then forgets it"; a callee that finished first "forgets the call ID, ignores that input and grants no more credit for it; on a leased stream it still notes when the caller's half finishes … one flag per stream"; the 2× close rule is gone | core 7.1, 7.6 | `session`: forgetting at the final message, the per-stream flag; `TestCalleeForgetsAtItsFinalMessage`, `TestForgottenCallKeepsStreamUntilCallerEnd`; scenario `callee-error-while-streaming` reworded |
| S10 | After resetting a leased stream on an unanswered Cancel, the caller "counts the call as long as it counts the stream" | core 7.5 | `TestCallerKeepsResetCallCounted` |
| S11 | Identity: every link opener presents `["link", credential]`; a credential that is not a dial-in node's, "or one of a disabled node", gets `GoAway(unauthenticated)`; the pin "replaces certificate-chain validation"; no mutual-TLS option; the 60 s re-validation is gone | core 10.2 | the hub's credential loop removed; `TestDisableDialInNode` |
| S12 | New sessions, dialed or dial-in, are relayed and acknowledged before they take calls; refused facets keep any old session. A configuration change (remove, disable, credential, link, `peer`) ends the session at once "without the grace period of section 5.6": running calls end with `Error(unavailable)`, then `GoAway(unauthenticated)`; dialed nodes are no longer superseded. At the node's `maxConcurrentCalls` the hub refuses with `resource_exhausted` | core 10.2, hub-admin 2.2 | `TestReconfigurationEndsSessionAtOnce`, `TestRefusedFacetsKeepOldSession`, `TestNodeAtConcurrencyLimit`; `session.CallOptions.NoWait` |
| S13 | "When the node's final message arrives, the hub forwards it and, if the caller's half is still open, sends `End` to the node itself" | core 10.5 | done by the session on the hub's caller side |
| S14 | Last known facets only for enabled nodes, none for a node never seen, discarded on removal; a call to a removed or disabled node's facet ID gets `unimplemented`, as do calls waiting for it; dial when configured or enabled, redial "with exponential backoff and jitter, as a client reconnects" | core 10.7 | `TestNeverSeenNodeHasNoFacets`, `TestRemovedNodeDiscardsFacets`, `TestWaitingCallsForRemovedNode` |
| S15 | Stored facets removed (putFacet, deleteFacet, listFacets, `NodeConfig.facets`, `Hashes`, the stored-facet key); `NodeConfig.link` is the union `Link` = `[0, Dial] / [1, secret-name]`; types 64–79 renumbered, methods 0–8, details `[72, problems]`; every secret a link names is named once and all their values are pairwise distinct | hub-admin 2, 3, 5 | `adminiface`, `admin`; `admin.json` regenerated (new interface hash), `admin/stored-facet-key` removed |
| S16 | Watch: a NodeEvent's revision "is the revision applied when it was sent"; every configured node is reported after each revision; a disabled node is reported `disabled` until enabled; a removed node once; an offline message is the last connection failure | hub-admin 4 | `admin.Manager.NodeEvent`, `hub` |

## Raised against core revision 316 and hub-admin revision 18 (resolved in core revision 324, hub-admin revision 25)

| # | Question | Decision | Go / vectors |
| --- | --- | --- | --- |
| P1 | Does a reset abort both directions of a leased stream, and when does the acceptor stop counting a stream it reset? | "A reset aborts only the resetting side's sending direction (QUIC `RESET_STREAM`, never `STOP_SENDING`)"; "an acceptor that starts a reset stops counting it as soon as it has sent its end" (4.2 rule 5) | `session` resets only the sending direction and drains the peer's; `TestAcceptorResetSendingOnly`, `TestAcceptorResetUncountsAtOnce` |
| P2 | What does a server do with a `SchemaUpdate` from a client that sent no client schema? | "a `SchemaUpdate` from it closes the session with `GoAway(schema_mismatch)`" (5.4) | `TestNoLateClientSchema` |
| P3 | Which code refuses a dial-in with a credential of a node the hub starts or dials? | "only a node configured to dial in has a dial-in credential; any other credential is refused with `GoAway(unauthenticated)`" (10.2) | the hub no longer remembers old credentials; `TestOneLinkDirection` |
| P4 | May a hub accept an `implements` claim to an interface it does not know? | No: a claim "to an interface it holds no document for" is treated "like an incompatible update"; "How a hub obtains interface documents is its configuration" (10.3) | `AcceptUnknownInterfaces` removed; `ref.interfaces` stays; `TestUnknownInterfaceRefused` |
| P5 | How long does each downstream session get to ack a relayed update? | "5 s to ack an update from a node, and 2 s to ack one the hub relays from a peer hub"; "A node gives its hub at least 10 s" (10.3) | `Options.RelayAckTimeout`, `PeerRelayAckTimeout`; `node.MinHubAckTimeout`; `TestRelayAckLimits` |
| P6 | Do those limits apply to the change a superseding session brings? | "The same limits apply to the change a superseding session brings" (10.3) | `TestRelayAckLimits` |
| P7 | What exactly happens at the end of a context's grace period? | The hub "answers the node with `Error(permission_denied)` and sends `Cancel` for the forwarded call" (10.6) | `TestContextGraceCancelsNested` |
| P8 | Which code refuses peer principals, and may a peer send a context? | `Error(permission_denied)` for a named principal starting with `peer:` and for "a call from a peer that carries a `context`"; "A hub never forwards a call acting for a `peer:` principal to another peer" (10.8) | the hub sends no context to a peer; `TestPeerPrincipalRules` |
| P9 | Are configured facets still used after a node has published? | "Once a node has published a schema, configured facets are no longer used for it" (10.7) | `TestConfiguredFacetsIgnoredAfterPublish` |
| P10 | Notifications to a node that is offline or starting? | "are dropped" (10.7) | `TestNotificationToOfflineNodeDropped` |
| P11 | What "equal" means for the no-op commit | "byte-for-byte equal to the applied one in canonical encoding" (hub-admin 2) | `TestNoOpCommitIsCanonicalByteEquality` |
| P12 | May a hub start a spawned node lazily? | "A hub MAY instead start a spawned node on its first call" (hub-admin 2.2) | node extension `ref.lazy`; superseded by S1 (removed) |
| P13 | When does the old session of a re-dialed node end? | "when the new one is ready or the first new attempt fails, whichever comes first" (hub-admin 2.2) | unchanged |
| P14 | What follows the watch `Snapshot`, and which nodes are reported after a commit? | "followed by one `NodeEvent` for each configured node"; "After each applied revision the hub sends a `NodeEvent` for every configured node, changed or not" (hub-admin 4) | `TestWatchReportsEveryNode` |
| P15 | How deep does `Problem.path` go? | "following the JSON form, so a union variant's name is a key, with list positions as decimal strings and byte-string map keys as lowercase hex" (hub-admin 5.1) | `admin/value/problems` now ends in `["start", "dial", "pin"]`; the JSON form writes `{"start": {"spawn": ...}}` and `{"literal": ...}` |
| P16 | Further validation rules | "no two dial-in nodes name secrets with the same value"; "every `Spawn` program is non-empty and every environment variable name is non-empty and contains no `=` or NUL" (hub-admin 3) | `TestValidate`; the `Spawn` rules went with S5 |

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
