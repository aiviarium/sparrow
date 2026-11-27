# Spec issues found while writing the test vectors

Against `spec/core.md`, revision 164. Section A lists open questions found while implementing
rev164. Each one says what the vectors do today, so changing the decision means changing the
generator and regenerating. Section B lists rev108 issues that rev164 resolved. Section C lists
choices that remain assumptions. All of them are also under "Assumptions" in
[`test-vectors/README.md`](test-vectors/README.md).

## A. Open (new in rev164)

### Schema model (section 6)

1. **"`implements` bytewise" in the canonical form (6.6).** `implements` is a single `bstr / null`,
   so there is nothing to sort. This looks like a leftover. Vectors: no-op.
2. **Order of `parts` in a transmitted schema (6.2, 6.6).** The canonical form sorts the contents of
   each part, and the schema-hash entries are sorted by part ID. Nothing says the `parts` array of a
   schema document (as sent in `Welcome [2, hash, schema]`) is sorted. Vectors: the canonical schema
   sorts `parts` by ID. The hash doesn't depend on it.
3. **Version of part 1 `sparrow.web` (9.4).** The spec defines its contents but no `version` string,
   so its part hash isn't fixed and no two implementations will agree on it. Vectors use `"1.0.0"`
   (`part/sparrow-web`). Suggest fixing the version in the spec and publishing the part hash.
4. **Reserved part IDs (6.1).** Are IDs 0 and 2–15 invalid in any schema today, and must part 1 match
   the spec's definition exactly (by part hash) or only by name? Vectors reject 0 and 2–15
   (`reserved_part_id`) and check part 1 by name only.
5. **Compatibility rules are incomplete (6.6 rule 2, 6.7).** The vectors decide these cases (code
   `incompatible_change` unless noted):
   - A new struct field must be optional (the table only says "add an *optional* field").
   - Removing an enum value is incompatible (the table doesn't list it).
   - A struct member's tag must stay in the list. A removed member stays as a tombstone, and a
     tombstone can't be revived (tag reuse).
   - Removing a *required* field is incompatible.
   - Changing a type's kind, the sparse flag, an alias target, a union variant's type, or a sigil's
     kind is incompatible.
   - The replacing part must keep every entry of the old `retired` (`retired_not_carried_over`).
     6.1 only says so for a re-added part.
   - Methods are identified by MethodId within the part, so moving a method to another service is
     allowed.
6. **Major version in an in-place replace (6.6 vs 10.3).** 10.3 says a new major version is a new
   part, but 6.6's `[0, part]` replace only requires compatibility. Vectors reject an in-place
   replace that changes the major version (`major_version_changed`), even if it is otherwise
   compatible. Semver 0.x is treated like any other major (first component compared).
7. **Re-adding a removed part ID (6.1).** Vectors: within a session, a removed ID may come back only
   with the same name and major version, as a compatible successor of the last version seen
   (`removed_part_mismatch` otherwise, including for an unrelated part reusing the ID). Please
   confirm an unrelated part may never take a removed ID within the session.
8. **References inside tombstones (6.3).** If type references in removed fields or variants must
   still resolve, a type can never be retired while a tombstone mentions it. Vectors skip
   tombstones when resolving references and when deciding whether a method needs End flags.
   Tombstones still count for hashes and wire shapes.
9. **Implementing a service means its exact method list (6.5).** Conformance compares each service's
   wire shape, which includes its methods. So a part can't add a method to a service it implements;
   it must add a separate service. Intended? Vector: `conformance/extra-method-in-service` fails.
10. **The deprecated flag and other `flags` are part of the wire shape (6.5).** Marking a field
    deprecated (0x2), or changing a method's idempotent (0x1) or shared (0x4) flag, breaks
    conformance, although these are compatible changes elsewhere. Intended? Vector:
    `conformance/method-flags-differ`.
11. **What a receiver does with a float in a schema (3.2, 6.6 rule 3).** Canonical data MUST NOT
    contain floats, but the rule-3 checks don't list it. Vectors treat it as an invalid part or schema
    (`float_in_canonical_data`, handled like any rule-3 failure). Scope: does this apply only to
    schemas and signed data, or also to other hashed values?

### Web profile (section 9)

12. **A module id equal to the part name (9.4).** "Every module `id` MUST start with the part's name
    … followed by a dot": read literally, a part `acme.charts` can't ship a module with id
    `acme.charts`, which is exactly the example in the 9.4 CDDL. Vectors reject it
    (`module-scope/acme.charts/acme.charts`). Suggest allowing `id == name`, or changing the example.
13. **`<hub-id>/` (9.4) vs `<peer-id>/` (10.8).** Two names for the same prefix. Vectors strip
    everything up to the first `/` from the part name, and module ids never carry the prefix.
14. **No Unicode normalization for namespaces and ids (9.5).** Coverage is a UTF-8 byte-prefix match,
    so `café.menu` in NFD is not covered by namespace `café.` in NFC, though they look identical
    (`verify/utf8-nfd`). Suggest restricting namespaces, module ids and part names to ASCII (like
    node IDs), or requiring NFC.
15. **A revocation list that names a root key (9.5).** Roots "cannot be revoked this way". Vectors
    ignore that entry, while the rest of the list still counts (`verify/root-not-revocable`).
    The alternative would be to reject the whole list; please say which.
16. **Where `web.keys` and `web.revoked` live (9.4, 9.5).** A part's annotations may carry only
    `web.modules`, so these must be top-level schema annotations. The vectors put them there.
    Worth stating.

### Hub profile (section 10)

17. **Context for notifications (10.6).** The hub "issues a context for every call it forwards", but
    a context is valid "while its call is open". A notification (call ID 0) is never open. Is a
    context sent with notifications, and for how long is it valid?
18. **What "payload" means for byte-exact copying (10.5).** Vectors take it to be the `input`,
    `output`, `value` and `details` elements. The envelope, including metadata, is re-encoded.
    Please list the elements explicitly; `Error.details` and `Headers` metadata especially.
19. **The `credit` metadata key when forwarding (10.5).** "May lower but never raise". If the caller
    didn't send `credit`, may the hub add one? Vectors: the caller sent none and the hub adds none.
20. **Principal grammar (10.4).** Are "letters" ASCII only? Must the `<hub-id>` in `peer:<hub-id>/…`
    follow the node-ID grammar? Vectors: ASCII letters, and yes.
21. **The status for an unknown part or method ID.** A Request naming a part that isn't in the
    callee's schema, or a method missing from the part. Presumably `unimplemented` (12), but the
    spec doesn't say so.

### Transport (sections 4, 8)

22. **Truncating the close reason (8).** WebSocket allows 123 bytes and WebTransport 1024. Must a
    longer reason be truncated on a UTF-8 character boundary? Not covered by the vectors.
23. **Reserved codes 23–31 in closes (8).** "4000 + the core status code": the vectors map them to
    4023–4031 for forward compatibility; a peer of this revision never sends them.

## B. Resolved by rev164 (previously reported against rev108)

| rev108 # | Topic | Resolved by |
| --- | --- | --- |
| A1 | Integral floats in canonical data | 3.2: canonical data MUST NOT contain floats |
| A2 | Schema hash definition, 1.4 vs 6.6 | 1.4 now says `0x01 ‖ SHA-256` |
| A3 | Meta-schema numbering | Meta-schema removed; TypeIds 32–63 are plain reserved |
| A4 | Domain prefix byte format | 9.5: canonical CBOR of `[domain, value]` |
| A5 | Stream reset for statuses > 255 | 8: resets and closes carry core codes only |
| A6 | WebSocket 4002 reason format | 8: no non-core mapping any more |
| A7 | `ok` → 4000 | 8: `ok` → 1000 |
| A8 | Two meanings of `any` | 6.2: the CDDL `any`; the Sparrow type is `dynamic` |
| A9 | Composite types in `dynamic` | 6.3: use an alias |
| A10 | Retired IDs absent from the hashed form | Each part's `retired` list |
| A11 | Sigil annotations could never change | Whole-part replace |
| A12 | Service for `moduleRejected` | 9.4: part 1, service 0, method 0 |
| A13 | `trace` format | 7.2: 26 bytes |
| A14 | Ping nonce, AuthStatus expiry types | 5.5: uint, timestamp |
| A15 | Status for a drain | 5.6: `going_away` |
| B16 | What is signed | 9.5 |
| B18 | Expiry, multiple certificates, revocation signer, prefix match | 9.5 (check *order* still an assumption, C2) |
| B19 | Hash encoding in URLs | 9.1 |
| B20 | Credit counting | 7.4: the whole message |
| B21 | Trailing nulls in envelopes | 3.4 |
| B22 | Varint form | 4.1 |
| B23 | Delta semantics | Replaced by whole-part ops (see A5–A7 above) |
| B24 | ID ranges | 6.1 table |
| B25 | End flags through referenced types; `[3, T]` placement | 6.3, 6.4 |
| B26 | Required annotations | CDDL has no `/ null` |
| B27 | Text keys in `params` | 3.4 |

## C. Remaining assumptions

1. **Module `sig` key_id** is the key_id of the key that signed it, root or publisher (implied, not
   stated).
2. **Check order for module acceptance:**
   1. a revocation list counts only if a root key signed it;
   2. a root key is accepted;
   3. a revoked key is rejected;
   4. certificate checks follow: root known, signature, trailing dot, expiry, namespace;
   5. the module signature is checked last.

   The reason names are a vocabulary for the vectors only.
3. **Hub call IDs on a pipe link** are odd, because the hub is the Sparrow server there (4.7, 7.1).
4. **Deadline lowering** uses whole milliseconds; the vector assumes 50 ms elapsed.
