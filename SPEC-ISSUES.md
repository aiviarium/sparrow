# Spec issues found while writing the test vectors

Against `spec/core.md`, revision 108 (2026-11-26 draft). Part A lists problems that likely need a
spec change. Part B lists choices the vectors had to make where the spec is silent; they are also
under "Assumptions" in [`test-vectors/README.md`](test-vectors/README.md). Each entry names what
the vectors do today, so changing a decision means changing the generator and regenerating.

## A. Problems that likely need a spec change

1. **Integral floats in canonical data break Go/JS agreement (3.1, 3.2, 11.2).** Canonical data
   must use the shortest exact float width, so Go encodes `1.0` as `f9 3c00`. JavaScript has no
   separate float type, and a JS encoder that does not know the declared type writes `01`. cbor2's
   own CDE preset (`cdeEncodeOptions`) does this too. `100000.0` and `65504.0` give the same
   mismatch. Any annotation or signed value that holds an integral float therefore hashes or signs
   differently in the two languages. Options: (a) require integral floats to be encoded as integers
   in canonical data (dCBOR-style numeric reduction; decoders already accept ints for floats), (b)
   ban floats in hashed or signed data, or (c) require schema-aware canonical encoders. The vectors
   follow RFC 8949 as written today (Go behaviour). The JS verifier matches only because it is told
   which values are floats. Vectors: `float/float64/1`, `/100000`, `/65504`.
2. **The schema hash definition differs between 1.4 and 6.6.** The terminology table says "SHA-256
   of a schema's canonical encoding"; 6.6 says `0x01 ‖ SHA-256(...)`, 33 bytes. The vectors use
   6.6.
3. **The meta-schema is not defined (6.1, 6.2).** TypeIds 32–63 are "fixed by this specification",
   but no type numbering is given, so schema fragments cannot be sent as typed values yet. There
   are no vectors for it, and references to 32–63 count as dangling.
4. **Domain separation needs an exact byte format (9.5).** "Prefixed with a domain string" does not
   say whether there is a separator or length. The vectors use raw UTF-8 directly followed by the
   CBOR. This is only unambiguous because no domain string is a prefix of another and CBOR never
   starts with an ASCII letter. Suggest stating the format; length-prefixing the domain or signing
   `[domain, value]` would be more robust.
5. **There is no WebTransport stream-reset code for statuses above 255 (4.5, 8).** Reset codes are
   limited to 0–255, but method error sigils can be any uint. The vectors show `null` (not
   representable). The spec should give a fallback, for example `unknown` (2).
6. **The WebSocket 4002 reason format is unspecified (8).** "With the status in the reason" does
   not say how. The vectors use the decimal status (`"64"`). Note also that WebSocket close reasons
   are limited to 123 bytes (RFC 6455), while 5.6 allows 1024 bytes for WebTransport.
7. **`ok` maps to WebSocket close code 4000 (8).** A normal close would usually be 1000. Is 4000
   intended? (Codes 23–31 are reserved, but they map to 4023–4031 under the "core 0–31" rule. The
   vectors do that.)
8. **`any` means two different things.** The message CDDL (`caps`, `props`, `auth`, metadata,
   `Error.details`) uses CDDL `any` (any CBOR value). 3.4 and 6.3 define a Sparrow `any` type
   encoded as `[type_id, value]`. `Error.details` mixes the two: "any / null" that "SHOULD be a
   typed value". Suggest renaming one, or a note in 1.3.
9. **Typed `any` values can only carry named types.** `type_id` is a TypeId (uint), so a composite
   type like `[0, 6]` cannot be sent in `any` or `Error.details` without an alias.
10. **Retired IDs and the hashed form (6.1, 6.6).** The canonical form drops retired definitions
    and the schema CDDL has no "retired" marker. A peer that loads a full schema (not a delta chain)
    therefore cannot know which IDs are retired, so it cannot enforce "an ID MUST NOT be reused
    within a session". Also, "retired definitions are removed" before hashing suggests a transmitted
    schema can contain them, but there is no way to mark one. Clarify.
11. **Sigils cannot change, though annotations may (6.6 vs 6.7).** Delta op 2 is "add a sigil" with
    no replace, but 6.7 allows "Change annotations" in place. As written, a sigil's annotations (such
    as an `http.status`) can never change. The vectors treat op 2 on an existing ID as invalid.
12. **The service for `web.moduleRejected` is undefined (6.1, 9.4).** MethodId 32 must be in the
    server schema (IDs belong to the callee), but every method sits in a service, and ServiceIds 0–63
    are all "Reserved". Which service ID and name hold profile methods? The example schema leaves
    it out.
13. **The `trace` metadata format (7.2, key 33) is ambiguous.** "W3C `traceparent` in binary form":
    the W3C binary trace-context draft uses field IDs (29 bytes), while the simple packing is 26
    bytes. The vectors use 26 bytes: version ‖ trace-id ‖ parent-id ‖ flags. Please name the exact
    format.
14. **Field types missing in control messages (5.5).** `Ping`/`Pong` nonce and
    `AuthStatus.expires_at` have no types. The vectors use uint and a timestamp (tag 1, integer
    seconds).
15. **The status for a graceful shutdown is not named (5.6).** The vectors use `going_away` (21)
    for a drain before a deploy. `unavailable` would also fit.

## B. Assumptions to confirm

16. **What is signed (9.5).** The signed array or map with its signature element removed (not
    replaced by null). A certificate signs `[publisher_key, namespace, expires, root_key_id]`, a
    revocation list signs `[seq, [* key_id], root_key_id]`, and a module signs its map without
    `"sig"`.
17. **Module `sig` key_id** names the key that signed it, either a root key or a certified publisher
    key.
18. **Module acceptance rules (9.5).** Expiry is exclusive (`now < expires`). If several
    certificates name the key, any one that passes is enough. A revocation list counts only if
    signed by a root key, and it can revoke root keys too. Namespace coverage is a byte-prefix match.
    `web.keys` is an array of certificates and `web.revoked` is one list.
19. **Hashes in URLs (9.3).** `{hash}` is base64url without padding of the 33-byte hash, as for JSON
    in 9.1.
20. **Credit counting (7.4).** "The length of its CBOR data item" counts the whole `Item`/`Progress`
    message, not just its value.
21. **Message envelopes keep trailing nulls.** The 3.4 rule applies only to schema-described
    structs. 7.7's `[17, 2, null]` supports this; worth stating.
22. **QUIC varint form.** Senders use the shortest form. Receivers accept non-minimal forms
    (RFC 9000 allows them).
23. **Delta semantics (6.6).** (a) Op 1 replaces the whole service including its method list;
    dropping a live method without op 3 is invalid. (b) Retiring a service retires its methods.
    (c) Retiring an unknown ID is invalid. (d) References are validated once, after the whole delta.
    (e) The compatibility rule for methods (input, output, flags 0x2/0x8/0x10 unchanged) is enforced
    on replace.
24. **ID ranges.** User TypeIds, ServiceIds and Sigils start at 64. MethodIds ≥ 32 are accepted
    (profile methods 32–63). Method `errors` may omit core statuses 0–31 and list only `kind 1`
    sigils otherwise. Enum values must name `kind 0` sigils.
25. **End flags (6.4).** "Contains `[4]` anywhere" is followed through user types, aliases,
    optional, list and map. `[3, T]` is accepted only as a method's top-level input or output.
26. **Annotations** are required in every definition (`{}` when empty), with text keys.
27. **`params` keys** are text strings (`"maxStreams"`), per CDDL bareword keys. This is standard
    CDDL, but worth confirming given the compactness goal.
