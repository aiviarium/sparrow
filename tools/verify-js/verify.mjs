#!/usr/bin/env node
// Independent verifier for the Sparrow RPC test vectors.
//
//   node verify.mjs [path/to/test-vectors]
//
// Re-checks every vector with cbor2 and Node's crypto, without using any
// output of the Go generator other than the vector files themselves.

import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decode } from 'cbor2';
import {
  concat, decodeCDE, decodeTJ, encTJ, eqTJ, fmtFloat, hex, unhex, varintDecode, varintEncode,
} from './lib/cbor.mjs';
import {
  P, SchemaState, DeltaError, canonicalFacet, canonicalIface, canonicalSchema, facetHash, facetHashInput, ifaceHash,
  schemaHash, schemaHashInput, conforms, validateFacet, validateIface, validateSchema, validateSentSchema,
  storedFacetKey, storedFacetKeyInput,
} from './lib/schema.mjs';
import { checkValue } from './lib/value.mjs';
import {
  DOMAIN, ed25519Sign, ed25519Verify, fileHash, keyId, moduleInFacet, privateKeyFromSeed, publicKeyRaw, sha256, signedBytes, verifyModule,
} from './lib/signing.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const dir = process.argv[2] ?? join(here, '..', '..', 'test-vectors');
const files = Object.fromEntries(
  readdirSync(dir).filter((f) => f.endsWith('.json')).sort().map((f) => [f, JSON.parse(readFileSync(join(dir, f), 'utf8'))]),
);
const scenarioDir = join(dir, 'scenarios');
const scenarioFiles = readdirSync(scenarioDir).filter((f) => f.endsWith('.json')).sort()
  .map((f) => [f, JSON.parse(readFileSync(join(scenarioDir, f), 'utf8'))]);
const byName = new Map();
for (const doc of Object.values(files)) for (const v of doc.vectors) {
  if (byName.has(v.name)) throw new Error(`duplicate vector name ${v.name}`);
  byName.set(v.name, v);
}

const failures = [];
let checks = 0;

function check(cond, vec, what) {
  checks++;
  if (!cond) failures.push(`${vec.name}: ${what}`);
  return cond;
}
function checkEq(got, want, vec, what) {
  return check(got === want, vec, `${what}: got ${got}, want ${want}`);
}
function expectError(fn, code, vec, what) {
  try {
    fn();
    check(false, vec, `${what}: accepted, expected ${code}`);
  } catch (e) {
    if (!(e instanceof DeltaError)) throw e;
    checkEq(e.code, code, vec, `${what} error code`);
  }
}
function expectOk(fn, vec, what) {
  try { fn(); check(true, vec, ''); } catch (e) { check(false, vec, `${what}: ${e.message}`); }
}

/** encode(value) == cbor and decode(cbor) == value */
function roundTrip(vec, tj, cborHex, label = '') {
  const p = label ? `${label} ` : '';
  checkEq(hex(encTJ(tj)), cborHex, vec, `${p}cbor2 encoding`);
  let decoded;
  try { decoded = decodeTJ(unhex(cborHex)); } catch (e) { return check(false, vec, `${p}decode failed: ${e.message}`); }
  check(eqTJ(decoded, tj), vec, `${p}decoded value differs: ${JSON.stringify(decoded)}`);
}

function checkCanonical(vec, cborHex, label) {
  expectOk(() => decodeCDE(unhex(cborHex)), vec, `${label} not accepted by cbor2 CDE decoder`);
}

const knownHash = (h) => [...byName.values()].some((s) => s.hash === h);

// ---------------------------------------------------------------------------
// encoding.json

function structFromFields(fields) {
  const present = (fields ?? []).filter((f) => f.value !== null);
  const max = Math.max(-1, ...present.map((f) => f.tag));
  const arr = Array(max + 1).fill(null);
  for (const f of present) arr[f.tag] = f.value;
  return arr;
}

/** Nesting level as section 3.1 counts it: arrays, maps and tags; scalars add none. */
function tjDepth(t) {
  if (t === null || typeof t !== 'object') return 0;
  if (Array.isArray(t)) return 1 + Math.max(0, ...t.map(tjDepth));
  if ('$bytes' in t || '$int' in t || '$float' in t) return 0;
  if ('$tag' in t) return 1 + tjDepth(t.value);
  if ('$map' in t) return 1 + Math.max(0, ...t.$map.flatMap(([k, x]) => [tjDepth(k), tjDepth(x)]));
  return 1 + Math.max(0, ...Object.values(t).map(tjDepth));
}

/** Nesting level computed from the bytes, independently of the tree. */
function byteDepth(u8) {
  let off = 0;
  let maxSeen = 0;
  const arg = (info) => {
    if (info < 24) return info;
    const n = 1 << (info - 24);
    let x = 0;
    for (let i = 0; i < n; i++) x = x * 256 + u8[off++];
    return x;
  };
  const item = (level) => {
    const ib = u8[off++];
    const major = ib >> 5;
    const a = arg(ib & 0x1f);
    if (major === 2 || major === 3) { off += a; return; }
    if (major === 4 || major === 5 || major === 6) {
      maxSeen = Math.max(maxSeen, level);
      const n = major === 4 ? a : major === 5 ? 2 * a : 1;
      for (let i = 0; i < n; i++) item(level + 1);
    }
  };
  item(1);
  if (off !== u8.length) throw new Error('trailing bytes');
  return maxSeen;
}

function checkEncoding(v) {
  if (v.type === 'depth') {
    roundTrip(v, v.message, v.cbor);
    checkMessageFields(v, v.message);
    checkEq(tjDepth(v.message), v.depth, v, 'depth from the value tree');
    checkEq(byteDepth(unhex(v.cbor)), v.depth, v, 'depth from the bytes');
    checkEq(v.max_depth, 64, v, 'limit');
    checkEq(v.expected_valid, v.depth <= 64, v, 'verdict');
    return;
  }
  if (v.type === 'non_shortest') {
    let d;
    try { d = decodeTJ(unhex(v.cbor)); } catch (e) { check(false, v, `decode: ${e.message}`); return; }
    check(eqTJ(d, v.message), v, 'non-shortest bytes decode to the message');
    checkEq(hex(encTJ(v.message)), v.shortest_cbor, v, 'shortest encoding');
    check(v.cbor !== v.shortest_cbor, v, 'bytes differ from the shortest encoding');
    checkMessageFields(v, v.message);
    return;
  }
  if (v.type === 'decode_only') {
    const d = decode(unhex(v.cbor));
    checkEq(Number(d), Number(v.decoded_float), v, 'integer-on-wire decodes to the float value');
    checkEq(hex(encTJ({ $float: v.decoded_float })), v.canonical_cbor, v, 'shortest float encoding');
    return;
  }
  roundTrip(v, v.value, v.cbor);
  const L = v.logical;
  switch (v.rule) {
    case 'int':
    case 'literal':
      check(eqTJ(L.value, v.value), v, 'logical value != value');
      break;
    case 'float': {
      let x = Number(L.value);
      if (L.declared === 'float32') x = Math.fround(x);
      check(eqTJ({ $float: fmtFloat(x) }, v.value) && Object.is(Number(v.value.$float), x), v, `float value ${fmtFloat(x)}`);
      break;
    }
    case 'struct':
      check(eqTJ(structFromFields(L.fields), v.value), v, 'struct positional encoding');
      break;
    case 'sparse_struct': {
      const m = { $map: (L.fields ?? []).filter((f) => f.value !== null).map((f) => [f.tag, f.value]) };
      checkEq(hex(encTJ(m)), v.cbor, v, 'sparse struct map encoding');
      break;
    }
    case 'enum': check(eqTJ(L.sigil, v.value), v, 'enum sigil'); break;
    case 'union': check(eqTJ([L.variant_tag, L.value], v.value), v, 'union [tag, value]'); break;
    case 'dynamic': check(eqTJ([L.type_id, L.value], v.value), v, 'dynamic [type_id, value]'); break;
    case 'symbol': check(eqTJ(L.sigil ?? L.text, v.value), v, 'symbol'); break;
    case 'map':
      checkEq(hex(encTJ({ $map: L.entries })), v.cbor, v, 'map key order');
      checkCanonical(v, v.cbor, 'map');
      break;
    default:
      check(false, v, `unknown rule ${v.rule}`);
  }
}

// ---------------------------------------------------------------------------
// messages

const LAYOUT = { // kind -> [name, array length]
  0: ['Hello', 8], 1: ['Welcome', 7], 2: ['Ready', 2], 3: ['SchemaUpdate', 4], 4: ['SchemaAck', 2],
  5: ['AuthRefresh', 2], 6: ['AuthStatus', 3], 7: ['Ping', 2], 8: ['Pong', 2], 9: ['GoAway', 5],
  16: ['Request', 6], 17: ['Response', 3], 18: ['Item', 3], 19: ['End', 3], 20: ['Error', 5],
  21: ['Progress', 5], 22: ['Headers', 3], 23: ['Cancel', 3], 24: ['Credit', 3], 25: ['Bytes', 5],
};

const stateCache = new Map();
/** Schema state after the named schema vector (base or delta chain), recomputed in JS. */
function stateOf(name) {
  if (stateCache.has(name)) return stateCache.get(name);
  const v = byName.get(name);
  const st = v.type === 'schema' ? new SchemaState(v.input) : stateOf(v.from).apply(v.delta);
  stateCache.set(name, st);
  return st;
}

function checkOffer(v, offer) {
  const h = offer[1].$bytes;
  switch (offer[0]) {
    case 0: check(knownHash(h), v, 'offer [0] names a known hash'); break;
    case 1: {
      const from = [...byName.values()].find((s) => s.type === 'schema' && s.hash === offer[2].$bytes)
        ?? [...byName.values()].find((s) => s.type === 'delta' && s.expected_valid && s.hash === offer[2].$bytes);
      if (!check(from, v, 'delta offer: unknown from hash')) return;
      checkEq(hex(schemaHash(stateOf(from.name).apply(offer[3]).doc)), h, v, 'delta offer: hash after applying delta');
      break;
    }
    case 2:
      checkEq(hex(schemaHash(offer[2])), h, v, 'inline schema hash');
      expectOk(() => validateSentSchema(offer[2]), v, 'inline schema invalid');
      break;
    case 3:
      checkEq(offer[2], `/sparrow/schema/${Buffer.from(unhex(h)).toString('base64url')}`, v, 'out-of-band location');
      break;
    default: check(false, v, 'bad schema-offer');
  }
}

function checkMessageFields(v, m) {
  const lay = LAYOUT[m[0]];
  if (!check(lay, v, `unknown kind ${m[0]}`)) return;
  checkEq(m.length, lay[1], v, `${lay[0]} array length`);
  const core = (s) => Number.isInteger(s) && s >= 0 && s <= 22;
  if (m[0] === 23 || m[0] === 9 || m[0] === 6) check(core(m[m[0] === 23 ? 2 : 1]), v, 'Cancel/GoAway/AuthStatus carry core codes only');
}

function checkMessage(v) {
  roundTrip(v, v.message, v.cbor);
  const b = unhex(v.cbor);
  checkEq(v.length, b.length, v, 'length');
  checkEq(v.framed, hex(concat(varintEncode(b.length), b)), v, 'framed = varint(length) || cbor');
  const m = v.message;
  checkMessageFields(v, m);
  checkEq(v.kind_name, LAYOUT[m[0]]?.[0], v, 'kind name');
  if (v.matches_spec) checkEq(v.framed, v.spec_framed, v, 'bytes from the spec text');
  if (m[0] === 0) {
    if (m[4] !== null) check(knownHash(m[4].$bytes), v, 'known_schema is a known schema hash');
    if (m[5] !== null) {
      checkEq(m[5][0], 2, v, 'client_schema tag');
      checkEq(hex(schemaHash(m[5][2])), m[5][1].$bytes, v, 'client_schema hash');
      expectOk(() => validateSentSchema(m[5][2]), v, 'client schema invalid');
    }
    if (m[7] === true) checkEq(m[1].length, 1, v, 'optimistic Hello lists exactly one version');
  }
  if (m[0] === 1) { checkEq(m[3].$bytes.length, 32, v, 'session_id is 16 bytes'); checkOffer(v, m[5]); }
  if (m[0] === 2) check(knownHash(m[1].$bytes), v, 'Ready names a known hash');
  if (m[0] === 3) {
    const want = byName.get(v.refs.hash).hash;
    checkEq(m[2].$bytes, want, v, 'SchemaUpdate hash');
    checkEq(hex(schemaHash(stateOf('schema/server-base').apply(m[3]).doc)), want, v, 'SchemaUpdate delta applied in JS');
  }
  if (m[0] === 16 && m[1] === 0) check(true, v, '');
}

const HEADER = (byte, opener, sharedOpen) => {
  if (byte === 0x00) return opener === 'client' && !sharedOpen ? 'shared_lane' : 'protocol_error';
  if (byte === 0x01) return 'leased_stream';
  if (byte >= 0x40 && byte <= 0x7f) return 'profile_reserved';
  return 'protocol_error';
};
const KIND = (k) => (k <= 47 ? ['core', 'close_protocol_error'] : k <= 63 ? ['core', 'ignore']
  : k <= 111 ? ['profile', 'close_protocol_error'] : k <= 127 ? ['profile', 'ignore'] : ['invalid', 'close_protocol_error']);

function checkFraming(v) {
  switch (v.type) {
    case 'quic_varint': {
      const d = varintDecode(unhex(v.encoded));
      checkEq(d.value.toString(), String(v.value.$int ?? v.value), v, 'varint decode');
      checkEq(d.length, v.encoded.length / 2, v, 'varint length');
      const shortest = hex(varintEncode(BigInt(v.value.$int ?? v.value)));
      if (v.decode_only) check(shortest !== v.encoded, v, 'non-minimal form differs from the shortest form');
      else checkEq(shortest, v.encoded, v, 'varint encode');
      break;
    }
    case 'stream_header_table':
      for (const e of v.entries) checkEq(HEADER(parseInt(e.byte, 16), e.opener, e.shared_lane_open), e.result, v, `header ${e.byte} from ${e.opener}`);
      break;
    case 'kind_range_table':
      for (const e of v.entries) {
        const [owner, action] = KIND(e.kind);
        checkEq(e.owner, owner, v, `kind ${e.kind} owner`);
        checkEq(e.if_unknown, action, v, `kind ${e.kind} action`);
      }
      break;
    case 'message': checkMessage(v); break;
    case 'stream': {
      const all = unhex(v.bytes);
      checkEq(hex(concat(...v.parts.map((p) => unhex(p.hex)))), v.bytes, v, 'stream bytes = parts');
      for (const p of v.parts) {
        if (!p.ref) continue;
        const r = byName.get(p.ref);
        checkEq(p.hex, p.what.startsWith('framed') ? r.framed : r.cbor, v, `facet ${p.what}`);
      }
      const off = v.parts[0].what.startsWith('stream header') ? 1 : 0;
      const len = varintDecode(all.subarray(off));
      checkEq(Number(len.value), all.length - off - len.length, v, 'length prefix covers the rest');
      const msg = all.subarray(off + len.length);
      expectOk(() => checkMessageFields(v, decodeTJ(msg)), v, 'framed message decodes');
      if (v.reverse_bytes) {
        const ref = byName.get(v.reverse_ref ?? 'example-7.7/response');
        checkEq(v.reverse_bytes, ref.framed, v, 'reverse direction');
      }
      break;
    }
    case 'websocket':
      checkEq(v.ws_messages[0], byName.get('example-7.7/request').cbor, v, 'ws message 1');
      checkEq(v.ws_messages[1], byName.get('example-7.7/response').cbor, v, 'ws message 2');
      break;
    default: check(false, v, `unknown type ${v.type}`);
  }
}

function checkUnimplemented(v) {
  for (const [k, m] of [['request', v.request], ['error', v.error]]) { roundTrip(v, m.message, m.cbor, k); checkMessageFields(v, m.message); }
  const req = v.request.message;
  const err = v.error.message;
  const schema = canonicalSchema(byName.get(v.schema).input);
  const facet = schema[3].find((p) => p[P.id] === req[2]);
  const has = facet && facet[P.services].some((s) => s[2].some((m) => m[0] === req[3]));
  check(!has, v, 'request names a facet or method the callee does not have');
  checkEq(err[0], 20, v, 'answer is Error');
  checkEq(err[1], req[1], v, 'same call ID');
  checkEq(err[2], 12, v, 'status unimplemented');
}

// ---------------------------------------------------------------------------
// credit.json

function counted(msg) {
  if (msg[0] === 18 || msg[0] === 21) return encTJ(msg).length;
  if (msg[0] === 25) return unhex(msg[3].$bytes).length;
  return 0;
}

function checkCredit(v) {
  if (v.type === 'credit_count') {
    roundTrip(v, v.message, v.cbor);
    checkMessageFields(v, v.message);
    checkEq(counted(v.message), v.counted_bytes, v, 'counted bytes');
    const len = unhex(v.cbor).length;
    checkEq(v.framed_length, varintEncode(len).length + len, v, 'framed length');
    return;
  }
  let remaining = v.initial_credit;
  for (const [i, s] of v.steps.entries()) {
    if (s.action === 'send') {
      check(remaining > 0 || counted(s.message) === 0, v, `step ${i}: send allowed only with credit > 0, or when it counts zero bytes`);
      roundTrip(v, s.message, s.cbor, `step ${i}`);
      remaining -= counted(s.message);
      checkEq(s.counted_bytes, counted(s.message), v, `step ${i} counted`);
      checkEq(s.remaining_after, remaining, v, `step ${i} remaining`);
    } else if (s.action === 'violation') {
      roundTrip(v, s.message, s.cbor, `step ${i}`);
      checkEq(s.counted_bytes, counted(s.message), v, `step ${i} counted`);
      check(remaining <= 0 && counted(s.message) > 0, v, `step ${i}: a violation sends counted data with no credit left`);
      checkEq(s.remaining, remaining, v, `step ${i} remaining`);
      roundTrip(v, s.answer.message, s.answer.cbor, `step ${i} answer`);
      check(eqTJ(s.answer.message, [23, s.message[1], 17]), v, `step ${i}: caller answers Cancel(protocol_error)`);
    } else if (s.action === 'receive_credit') {
      remaining += s.message[2];
      checkEq(s.remaining_after, remaining, v, `step ${i} remaining`);
    } else {
      checkEq(s.may_send, remaining > 0, v, `step ${i} may_send`);
      checkEq(s.remaining, remaining, v, `step ${i} remaining`);
    }
  }
}

// ---------------------------------------------------------------------------
// schema.json

function facetHashesOf(doc) {
  return canonicalSchema(doc)[3].map((p) => ({ facet_id: p[P.id], facet_name: p[P.name], facet_hash: hex(facetHash(p)) }));
}

function checkSchema(v) {
  switch (v.type) {
    case 'facet': {
      expectOk(() => validateFacet(v.input), v, 'JS facet validation');
      check(eqTJ(canonicalFacet(v.input), v.canonical), v, 'canonical facet');
      checkEq(hex(encTJ(canonicalFacet(v.input))), v.canonical_cbor, v, 'canonical facet bytes');
      checkEq(hex(encTJ(facetHashInput(v.input))), v.hash_input_cbor, v, 'facet hash input (id 0, name "")');
      checkEq(hex(facetHash(v.input)), v.facet_hash, v, 'facet hash');
      checkCanonical(v, v.canonical_cbor, 'canonical facet');
      break;
    }
    case 'interface':
      if (v.expected_valid) {
        expectOk(() => validateIface(v.input), v, 'JS interface validation');
        check(eqTJ(canonicalIface(v.input), v.canonical), v, 'canonical interface');
        checkEq(hex(encTJ(canonicalIface(v.input))), v.canonical_cbor, v, 'canonical interface bytes');
        checkEq(hex(ifaceHash(v.input)), v.hash, v, 'interface hash');
      } else expectError(() => validateIface(v.input), v.expected_error, v, 'interface');
      break;
    case 'conformance': {
      expectOk(() => validateFacet(v.facet), v, 'facet validation');
      const iface = byName.get(v.interface).input;
      const got = conforms(v.facet, iface);
      checkEq(got === null, v.expected_conforms, v, 'conforms');
      check(eqTJ(got, v.first_mismatch), v, `first mismatch ${JSON.stringify(got)}`);
      if (v.facet[P.implements]) checkEq(v.facet[P.implements].$bytes, hex(ifaceHash(iface)), v, 'implements = interface hash');
      break;
    }
    case 'schema': {
      expectOk(() => validateSentSchema(v.input), v, 'JS schema validation (as sent)');
      check(eqTJ(canonicalSchema(v.input), v.canonical), v, 'canonical schema');
      checkEq(hex(encTJ(canonicalSchema(v.input))), v.canonical_cbor, v, 'canonical schema bytes (JS canonicalised from unsorted input)');
      checkEq(unhex(v.canonical_cbor).length, v.canonical_length, v, 'canonical length');
      check(eqTJ(facetHashesOf(v.input), v.facet_hashes), v, 'facet hashes');
      check(eqTJ(schemaHashInput(v.input), v.hash_input), v, 'schema hash input');
      checkEq(hex(encTJ(schemaHashInput(v.input))), v.hash_input_cbor, v, 'schema hash input bytes');
      checkEq(hex(schemaHash(v.input)), v.hash, v, 'schema hash');
      checkCanonical(v, v.canonical_cbor, 'canonical schema');
      roundTrip(v, v.canonical, v.canonical_cbor, 'canonical');
      break;
    }
    case 'schema_sent':
      expectOk(() => validateSchema(v.input), v, 'contents valid');
      expectError(() => validateSentSchema(v.input), v.expected_error, v, 'sent schema');
      checkEq(hex(schemaHash(v.input)), byName.get('schema/server-base').hash, v, 'canonicalised hash equals server-base');
      break;
    case 'schema_invalid':
      expectError(() => validateSentSchema(v.input), v.expected_error, v, 'schema');
      checkEq(hex(facetHash(v.input[3][0])), v.facet_hash, v, 'facet 1 hash still equals sparrow.web');
      checkEq(v.facet_hash, byName.get('facet/sparrow-web').facet_hash, v, 'sparrow.web facet hash');
      break;
    case 'facet_hash_invariance': {
      const [pa] = v.schema_a[3];
      const [pb] = v.schema_b[3];
      check(pa[P.id] !== pb[P.id] && pa[P.name] !== pb[P.name], v, 'facets differ in id and name');
      checkEq(hex(facetHash(pa)), v.facet_hash, v, 'facet hash a');
      checkEq(hex(facetHash(pb)), v.facet_hash, v, 'facet hash b');
      checkEq(hex(schemaHash(v.schema_a)), v.schema_hash_a, v, 'schema hash a');
      checkEq(hex(schemaHash(v.schema_b)), v.schema_hash_b, v, 'schema hash b');
      check(v.schema_hash_a !== v.schema_hash_b, v, 'schema hashes differ');
      break;
    }
    case 'delta': {
      checkEq(hex(schemaHash(stateOf(v.from).doc)), v.from_hash, v, 'from_hash');
      if (v.expected_valid) {
        const st = stateOf(v.name);
        checkEq(hex(encTJ(st.doc)), v.canonical_cbor, v, 'canonical bytes after delta');
        check(eqTJ(facetHashesOf(st.doc), v.facet_hashes), v, 'facet hashes after delta');
        checkEq(hex(schemaHash(st.doc)), v.hash, v, 'hash after delta');
        check(eqTJ(st.removedIds(), v.removed_facet_ids_after), v, `removed facet ids ${JSON.stringify(st.removedIds())}`);
        const u = v.schema_update;
        roundTrip(v, u.message, u.cbor, 'SchemaUpdate');
        check(u.message[0] === 3 && u.message[1] === v.epoch && u.message[2].$bytes === v.hash && eqTJ(u.message[3], v.delta), v, 'SchemaUpdate fields');
      } else {
        expectError(() => stateOf(v.from).apply(v.delta), v.expected_error, v, 'delta');
      }
      break;
    }
    default: check(false, v, `unknown type ${v.type}`);
  }
}

// ---------------------------------------------------------------------------
// signing.json

function checkSigning(v, doc) {
  switch (v.type) {
    case 'key': {
      const pub = publicKeyRaw(privateKeyFromSeed(unhex(v.seed)));
      checkEq(hex(pub), v.public_key, v, 'public key from seed');
      checkEq(hex(sha256(pub)), v.sha256_public_key, v, 'sha256(public key)');
      checkEq(hex(keyId(pub)), v.key_id, v, 'key_id');
      break;
    }
    case 'certificate':
    case 'revocation':
    case 'module': {
      const wrong = v.name === 'module/wrong-domain' || v.name === 'cert/omega-wrong-domain';
      const expectDomain = v.type === 'revocation' ? DOMAIN.revoked
        : v.type === 'module' ? (wrong ? DOMAIN.cert : DOMAIN.module) : (wrong ? DOMAIN.module : DOMAIN.cert);
      checkEq(v.domain, expectDomain, v, 'domain string');
      check(eqTJ(v.signed_value, [v.domain, v.unsigned]), v, 'signed value = [domain, value]');
      const sb = signedBytes(v.domain, v.unsigned);
      checkEq(hex(sb), v.signed_bytes, v, 'signed bytes = canonical CBOR of [domain, value]');
      checkCanonical(v, v.signed_bytes, 'signed bytes');
      roundTrip(v, v.signed_value, v.signed_bytes, 'signed value');
      checkEq(hex(ed25519Sign(unhex(v.signer_seed), sb)), v.signature, v, 'Ed25519 signature (deterministic)');
      const signerPub = publicKeyRaw(privateKeyFromSeed(unhex(v.signer_seed)));
      check(ed25519Verify(signerPub, sb, unhex(v.signature)), v, 'signature verifies');
      if (v.type === 'certificate') {
        check(eqTJ(v.certificate, [...v.unsigned, { $bytes: v.signature }]), v, 'certificate = unsigned + sig');
        checkEq(hex(encTJ(v.certificate)), v.certificate_cbor, v, 'certificate cbor');
      } else if (v.type === 'revocation') {
        check(eqTJ(v.revocation, [...v.unsigned, { $bytes: v.signature }]), v, 'revocation = unsigned + sig');
        checkEq(hex(encTJ(v.revocation)), v.revocation_cbor, v, 'revocation cbor');
      } else {
        const fh = hex(fileHash(Buffer.from(v.file_utf8, 'utf8')));
        checkEq(fh, v.file_hash, v, 'file hash');
        checkEq(v.unsigned.hash.$bytes, fh, v, 'entry hash = file hash');
        checkEq(v.unsigned.url, `/sparrow/mods/${Buffer.from(unhex(fh)).toString('base64url')}.js`, v, 'module url');
        const { sig, ...rest } = v.entry;
        checkEq(sig[0].$bytes, hex(keyId(signerPub)), v, 'sig key_id');
        checkEq(sig[1].$bytes, v.signature, v, 'sig signature');
        if (!v.name.includes('tampered')) check(eqTJ(rest, v.unsigned), v, 'entry without sig = unsigned');
        else check(!eqTJ(rest, v.unsigned), v, 'tampered entry differs from what was signed');
        roundTrip(v, v.entry, v.entry_cbor, 'entry');
      }
      break;
    }
    case 'file_hash':
      checkEq(hex(fileHash(Buffer.from(v.file_utf8, 'utf8'))), v.hash, v, 'file hash');
      break;
    case 'verify': {
      const ctxDef = doc[v.context];
      const ctx = {
        roots: ctxDef.root_public_keys.map(unhex),
        webKeys: doc.vectors.filter((x) => x.type === 'certificate').map((x) => x.certificate),
        revoked: byName.get(v.revocation).revocation,
        now: ctxDef.now,
      };
      checkEq(ctxDef.now, Date.parse(ctxDef.now_iso) / 1000, v, 'now_iso');
      const reason = verifyModule(byName.get(v.module).entry, ctx);
      checkEq(reason, v.expected_reason, v, 'acceptance result');
      checkEq(v.expected_valid, reason === 'ok', v, 'expected_valid');
      break;
    }
    case 'module_scope':
      checkEq(moduleInFacet(v.facet_name, v.module_id), v.expected_valid, v, 'module id within facet name');
      break;
    case 'facet_web_keys': {
      const keys = Object.keys(v.facet_annotations).filter((k) => k.startsWith('web.'));
      check(eqTJ(keys.filter((k) => k === 'web.modules'), v.honoured_web_keys), v, 'honoured keys');
      check(eqTJ(keys.filter((k) => k !== 'web.modules').sort(), [...v.ignored_web_keys].sort()), v, 'ignored keys');
      break;
    }
    default: check(false, v, `unknown type ${v.type}`);
  }
}

function checkSchemaModules() {
  // Every module a facet of the server schema ships must be named after the facet.
  const base = byName.get('schema/server-base');
  const fake = { name: 'schema/server-base (web.modules)' };
  for (const p of base.input[3]) {
    for (const m of p[P.ann]['web.modules'] ?? []) {
      check(moduleInFacet(p[P.name], m.id), fake, `module ${m.id} in facet ${p[P.name]}`);
      check([...byName.values()].some((x) => x.type === 'module' && eqTJ(x.entry, m)), fake, `module ${m.id} is a signing vector`);
    }
  }
}

// ---------------------------------------------------------------------------
// status.json

const CORE_NAMES = ['ok', 'cancelled', 'unknown', 'invalid_argument', 'deadline_exceeded', 'not_found', 'already_exists',
  'permission_denied', 'resource_exhausted', 'failed_precondition', 'aborted', 'out_of_range', 'unimplemented', 'internal',
  'unavailable', 'data_loss', 'unauthenticated', 'protocol_error', 'schema_mismatch', 'unsupported_version', 'not_ready',
  'going_away', 'message_too_large'];
const ws = (s) => (s === 0 ? 1000 : 4000 + s);

function checkStatus(v) {
  if (v.type === 'status_table') {
    checkEq(v.entries.length, 23, v, 'all 23 core statuses present');
    checkEq(v.websocket_reason_max_bytes, 123, v, 'ws reason limit');
    checkEq(v.webtransport_reason_max_bytes, 1024, v, 'wt reason limit');
    for (const e of v.entries) {
      checkEq(e.name, CORE_NAMES[e.status], v, `name of ${e.status}`);
      checkEq(e.websocket_close_code, ws(e.status), v, `ws close for ${e.status}`);
      checkEq(e.webtransport_session_close_code, e.status, v, `wt session close for ${e.status}`);
      checkEq(e.webtransport_stream_reset_code, e.status, v, `wt reset for ${e.status}`);
    }
  } else if (v.type === 'status_reserved') {
    for (const e of v.entries) {
      check(e.status >= 23 && e.status <= 31, v, 'reserved range');
      checkEq(e.websocket_close_code, ws(e.status), v, `ws close for ${e.status}`);
    }
  } else if (v.type === 'reason_truncation') {
    const trunc = (str, n) => {
      const b = Buffer.from(str, 'utf8');
      if (b.length <= n) return str;
      let k = n;
      while (k > 0 && (b[k] & 0xc0) === 0x80) k--;
      return b.subarray(0, k).toString('utf8');
    };
    checkEq(v.cases.map((c) => c.max_bytes).join(','), '123,1024', v, 'WebSocket and WebTransport limits');
    for (const t of v.cases) {
      checkEq(Buffer.byteLength(t.reason_utf8), t.reason_length, v, 'reason length');
      const got = trunc(t.reason_utf8, t.max_bytes);
      checkEq(got, t.truncated_utf8, v, `truncated to ${t.max_bytes}`);
      checkEq(Buffer.byteLength(got), t.truncated_length, v, 'truncated length');
      check(Buffer.byteLength(got) <= t.max_bytes && !got.includes('\ufffd') && t.reason_utf8.startsWith(got), v, 'fits and ends on a character boundary');
    }
  } else if (v.type === 'status_scope') {
    check(v.status > 31, v, 'non-core status');
    check(eqTJ(v.allowed_in, ['Error']), v, 'only Error carries non-core statuses');
  } else check(false, v, `unknown type ${v.type}`);
}

// ---------------------------------------------------------------------------
// hub.json

const NODE_ID = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;
const PRINCIPAL = /^(user|group|node):[A-Za-z0-9._@-]+$/;
function validPrincipal(p) {
  if (!p.startsWith('peer:')) return PRINCIPAL.test(p);
  const rest = p.slice(5);
  const i = rest.indexOf('/');
  return i >= 0 && NODE_ID.test(rest.slice(0, i)) && PRINCIPAL.test(rest.slice(i + 1));
}
function actingPrincipals(e) {
  if (e.from === 'client_session') return [e.session_principal];
  if (e.from === 'node') return e.context ? [e.context.split(' ').pop(), `node:${e.node_id}`] : [`node:${e.node_id}`];
  if (e.from === 'peer_hub') {
    if (!e.principal) return [`node:${e.node_id}`];
    if (e.principal.startsWith('peer:')) return null;
    return [`node:${e.node_id}`, `peer:${e.node_id}/${e.principal}`];
  }
  throw new Error(e.from);
}
const msgTail = (msgHex, payloadHex) => msgHex.endsWith(payloadHex);
const mdGet = (md, k) => md.$map?.find(([kk]) => kk === k)?.[1];

function checkHub(v) {
  const msgOk = (m, label) => { roundTrip(v, m.message, m.cbor, label); checkMessageFields(v, m.message); };
  switch (v.type) {
    case 'forward': {
      const cr = v.client_request.message;
      const fr = v.forwarded_request.message;
      msgOk(v.client_request, 'client request');
      msgOk(v.forwarded_request, 'forwarded request');
      msgOk(v.node_response, 'node response');
      msgOk(v.relayed_response, 'relayed response');
      check(cr[1] !== fr[1], v, 'call_id differs between hops');
      checkEq(fr[1] % 2, 1, v, 'hub is the Sparrow server on the pipe link, so its call ID is odd');
      checkEq(cr[2], v.facet_map.hub_facet_id, v, 'client uses the hub facet ID');
      checkEq(fr[2], v.facet_map.node_facet_id, v, 'forwarded call uses the node facet ID');
      checkEq(cr[3], fr[3], v, 'same method ID');
      check(eqTJ(cr[5], fr[5]), v, 'same input value');
      const pl = v.payload_cbor;
      checkEq(hex(encTJ(cr[5])), pl, v, 'payload bytes');
      check(msgTail(v.client_request.cbor, pl) && msgTail(v.forwarded_request.cbor, pl), v, 'payload bytes identical in both messages');
      // Metadata rules.
      checkEq(mdGet(fr[4], 32), mdGet(cr[4], 32) - v.elapsed_ms, v, 'deadline lowered by elapsed time');
      checkEq(mdGet(fr[4], 37), v.session_principal, v, 'principal set by the hub');
      const cc = mdGet(cr[4], 35) ?? v.caller_default_credit;
      checkEq(v.caller_default_credit, v.caller_stream === 'leased' ? 1048576 : 65536, v, 'default credit of the caller stream');
      check(mdGet(fr[4], 35) === undefined || mdGet(fr[4], 35) <= cc, v, 'forwarded credit no higher than the caller\'s');
      check(mdGet(cr[4], 37) !== v.session_principal, v, 'caller-sent principal replaced');
      const ctx = mdGet(fr[4], 36);
      check(ctx && ctx.$bytes.length >= 32 && ctx.$bytes !== mdGet(cr[4], 36)?.$bytes, v, 'context: >= 128 bits, issued by the hub');
      check(eqTJ(mdGet(fr[4], 'x-tenant'), mdGet(cr[4], 'x-tenant')), v, 'other metadata copied');
      // Response relay.
      const nr = v.node_response.message;
      const rr = v.relayed_response.message;
      checkEq(nr[1], fr[1], v, 'node answers the forwarded call');
      checkEq(rr[1], cr[1], v, 'relayed response uses the client call ID');
      check(msgTail(v.node_response.cbor, v.response_payload_cbor) && msgTail(v.relayed_response.cbor, v.response_payload_cbor), v, 'response payload identical');
      // Facet identity across hops.
      const hubFacet = byName.get('schema/server-base').input[3].find((p) => p[P.id] === v.facet_map.hub_facet_id);
      const nodeFacet = byName.get('schema/node-acme-charts').input[3].find((p) => p[P.id] === v.facet_map.node_facet_id);
      checkEq(hex(facetHash(hubFacet)), v.facet_map.facet_hash, v, 'hub facet hash');
      checkEq(hex(facetHash(nodeFacet)), v.facet_map.facet_hash, v, 'node facet hash (same facet)');
      break;
    }
    case 'forward_notification': {
      msgOk(v.client_request, 'client notification');
      msgOk(v.forwarded_request, 'forwarded notification');
      const cr = v.client_request.message;
      const fr = v.forwarded_request.message;
      check(cr[1] === 0 && fr[1] === 0, v, 'call ID 0 on both hops');
      checkEq(cr[2], v.facet_map.hub_facet_id, v, 'hub facet id');
      checkEq(fr[2], v.facet_map.node_facet_id, v, 'node facet id');
      checkEq(mdGet(fr[4], 36), undefined, v, 'no context on a forwarded notification');
      checkEq(mdGet(fr[4], 37), v.session_principal, v, 'principal replaced');
      checkEq(hex(encTJ(cr[5])), v.payload_cbor, v, 'payload');
      check(msgTail(v.client_request.cbor, v.payload_cbor) && msgTail(v.forwarded_request.cbor, v.payload_cbor), v, 'payload identical');
      const facet = byName.get('schema/server-base').input[3].find((p) => p[P.id] === cr[2]);
      const m = facet[P.services].flatMap((s) => s[2]).find((x) => x[0] === cr[3]);
      check(m && (m[5] & 0x2), v, 'method is a notification');
      break;
    }
    case 'relay': {
      msgOk(v.from_node, 'from node');
      msgOk(v.to_client, 'to client');
      const a = v.from_node.message;
      const b = v.to_client.message;
      checkEq(a[1], v.call_id_map.node, v, 'node call id');
      checkEq(b[1], v.call_id_map.client, v, 'client call id');
      check(eqTJ(a.slice(2), b.slice(2)) && eqTJ(a[0], b[0]), v, 'only the call ID changes');
      break;
    }
    case 'message_with_principals': {
      msgOk(v.request, 'request');
      const m = v.request.message;
      checkEq(m[1] % 2, 0, v, 'node is the Sparrow client: even call ID');
      const fwd = byName.get('forward/unary').forwarded_request.message;
      checkEq(mdGet(m[4], 36).$bytes, mdGet(fwd[4], 36).$bytes, v, 'node passes the context it received');
      check(eqTJ(v.acting_principals, [mdGet(fwd[4], 37), 'node:acme.charts']), v, 'acting principals');
      const welcome = byName.get(v.refs.schema).message;
      const facet = welcome[5][2][3].find((p) => p[P.id] === m[2]);
      check(facet && facet[P.services].some((s) => s[2].some((mm) => mm[0] === m[3])), v, 'method exists in the hub schema the node sees');
      break;
    }
    case 'schema_view': {
      const base = byName.get(v.from);
      const view = canonicalSchema(base.input);
      view[3] = view[3].filter((p) => !v.omitted_facet_ids.includes(p[P.id]));
      checkEq(hex(schemaHash(view)), v.hash, v, 'view hash');
      const w = byName.get('welcome/node-pipe').message;
      checkEq(w[5][1].$bytes, v.hash, v, 'welcome/node-pipe offers this view');
      break;
    }
    case 'node_id_table':
      for (const e of v.entries) checkEq(NODE_ID.test(e.node_id), e.valid, v, `node id ${JSON.stringify(e.node_id)}`);
      break;
    case 'facet_owner_table':
      for (const e of v.entries) checkEq(e.facet_name === e.node_id || e.facet_name.startsWith(`${e.node_id}.`), e.allowed, v, `${e.node_id} / ${e.facet_name}`);
      break;
    case 'imported_name': {
      checkEq(`${v.peer_id}/${v.facet_name}`, v.imported_name, v, 'imported name');
      const inv = byName.get('schema/facet-hash-invariance');
      checkEq(inv.schema_b[3][0][P.name], v.imported_name, v, 'matches the invariance vector');
      break;
    }
    case 'principal_table':
      for (const e of v.entries) checkEq(validPrincipal(e.principal), e.valid, v, `principal ${e.principal}`);
      break;
    case 'acting_principals_table':
      for (const e of v.entries) check(eqTJ(actingPrincipals(e), e.acting), v, `acting principals for ${JSON.stringify(e)}`);
      break;
    default: check(false, v, `unknown type ${v.type}`);
  }
}

// ---------------------------------------------------------------------------

const dispatch = {
  'encoding.json': checkEncoding,
  'framing.json': checkFraming,
  'handshake.json': (v) => (v.type === 'params_table' ? checkParams(v) : checkMessage(v)),
  'calls.json': (v) => (v.type === 'unimplemented' ? checkUnimplemented(v) : checkMessage(v)),
  'credit.json': checkCredit,
  'schema.json': checkSchema,
  'signing.json': checkSigning,
  'status.json': checkStatus,
  'hub.json': checkHub,
  'admin.json': checkAdmin,
};

// ---------------------------------------------------------------------------
// params (5.4)

const PARAM_DEFAULTS = { maxMessageSize: 1048576, maxInlineBytes: 65536, maxConcurrentCalls: 100, maxStreams: null, sharedCredit: 65536, leaseCredit: 1048576, idleTimeoutMs: 30000 };
const PARAM_MIN = { maxMessageSize: 16384, maxInlineBytes: 16384, sharedCredit: 16384, leaseCredit: 16384, maxConcurrentCalls: 1 };

function checkParams(v) {
  check(eqTJ(v.minimums, PARAM_MIN), v, 'minimums');
  for (const e of v.entries) {
    checkEq(hex(encTJ(e.params)), e.params_cbor, v, `params cbor ${e.note}`);
    const p = e.params.$map ? Object.fromEntries(e.params.$map) : e.params;
    const bad = Object.keys(PARAM_DEFAULTS).find((k) => k in p && k in PARAM_MIN && p[k] < PARAM_MIN[k]);
    if (bad) {
      checkEq(e.expected, 'goaway', v, `${e.note}: verdict`);
      checkEq(e.key, bad, v, `${e.note}: key`);
      checkEq(e.status, 3, v, `${e.note}: invalid_argument`);
      continue;
    }
    checkEq(e.expected, 'ok', v, `${e.note}: verdict`);
    const eff = {};
    for (const [k, d] of Object.entries(PARAM_DEFAULTS)) eff[k] = k in p ? p[k] : (d ?? (e.sent_in === 'Hello' ? 4 : 16));
    check(eqTJ(eff, e.effective), v, `${e.note}: effective limits ${JSON.stringify(eff)}`);
  }
}

// ---------------------------------------------------------------------------
// admin.json (spec/hub-admin.md)

// Section 5 of the admin tab, transcribed independently of the generator.
const ADMIN_TYPES = [
  [64, 'Config', 'struct'], [65, 'NodeConfig', 'struct'], [66, 'Start', 'union'], [67, 'Spawn', 'struct'], [68, 'EnvValue', 'union'],
  [69, 'Dial', 'struct'], [70, 'Other', 'struct'], [71, 'Snapshot', 'struct'], [72, 'CommitRequest', 'struct'], [73, 'ValidateRequest', 'struct'],
  [74, 'Problem', 'struct'], [75, 'Problems', 'alias'], [76, 'Secret', 'struct'], [77, 'Names', 'alias'], [78, 'Hashes', 'alias'],
  [79, 'Event', 'union'], [80, 'RevisionEvent', 'struct'], [81, 'RevisionState', 'enum'], [82, 'NodeEvent', 'struct'], [83, 'NodeState', 'enum'],
];
const ADMIN_FIELDS = { // type -> [tag, name, type, optional]
  64: [[0, 'nodes', [1, 6, 65]], [1, 'defaults', [1, 7, 6], 1], [2, 'extensions', [1, 6, 7], 1]],
  65: [[0, 'start', 66, 1], [1, 'credential', 6, 1], [2, 'facets', [0, 7], 1], [3, 'peer', 1, 1], [4, 'enabled', 1, 1], [5, 'extensions', [1, 6, 7], 1]],
  66: [[0, 'spawn', 67], [1, 'dial', 69], [2, 'other', 70]],
  67: [[0, 'command', [0, 6]], [1, 'env', [1, 6, 68], 1], [2, 'dir', 6, 1]],
  68: [[0, 'literal', 6], [1, 'secret', 6]],
  69: [[0, 'url', 6], [1, 'pin', 7], [2, 'credential', 6]],
  70: [[0, 'kind', 6], [1, 'params', 7]],
  71: [[0, 'revision', 3], [1, 'config', 64], [2, 'state', 81], [3, 'confirmInMs', 3, 1]],
  72: [[0, 'base', 3], [1, 'config', 64], [2, 'confirmWithinMs', 3]],
  73: [[0, 'base', 3], [1, 'config', 64]],
  74: [[0, 'path', [0, 6]], [1, 'message', 6]],
  76: [[0, 'name', 6], [1, 'value', 7]],
  79: [[0, 'snapshot', 71], [1, 'revision', 80], [2, 'node', 82]],
  80: [[0, 'revision', 3], [1, 'state', 81], [2, 'confirmInMs', 3, 1]],
  82: [[0, 'node', 6], [1, 'revision', 3], [2, 'state', 83], [3, 'message', 6, 1]],
};
const ADMIN_ALIASES = { 75: [0, 74], 77: [0, 6], 78: [0, 7] };
const ADMIN_ENUMS = { 81: [64, 65, 66], 83: [67, 68, 69, 70, 71, 72] };
const ADMIN_SIGILS = ['pending', 'confirmed', 'rolledBack', 'starting', 'connected', 'offline', 'failed', 'disabled', 'removed'];
const IDEM = 0x1;
const ADMIN_METHODS = [ // id, name, input, output, flags
  [0, 'get', 0, 71, IDEM], [1, 'validate', 73, 75, IDEM], [2, 'commit', 72, 3, 0], [3, 'confirm', 3, 0, IDEM],
  [4, 'rollback', 3, 3, 0], [5, 'setSecret', 76, 0, 0], [6, 'deleteSecret', 6, 0, IDEM], [7, 'listSecrets', 0, 77, IDEM],
  [8, 'putFacet', 7, 7, IDEM], [9, 'deleteFacet', 7, 0, IDEM], [10, 'listFacets', 0, 78, IDEM], [11, 'watch', 0, [3, 79], 0x10],
];
const KIND_NAMES = ['struct', 'enum', 'union', 'alias'];

function checkAdminInterface(v, iface) {
  checkEq(iface[0], 'sparrow.hub.admin', v, 'interface name');
  checkEq(iface[1], '1.0.0', v, 'interface version');
  const types = canonicalIface(iface)[2];
  check(eqTJ(types.map((t) => [t[1], t[2], KIND_NAMES[t[0]]]), ADMIN_TYPES), v, 'types 64-83 with names and kinds');
  for (const t of types) {
    if (ADMIN_FIELDS[t[1]]) {
      const want = ADMIN_FIELDS[t[1]].map(([tag, name, ty, optional]) => [tag, name, ty, optional ? 1 : 0, {}]); // optional: flag 0x1, plain type
      check(eqTJ(t[3], want), v, `fields of type ${t[1]} ${t[2]}`);
    }
    if (t[0] === 0) checkEq(t[4], 0, v, `type ${t[1]} is not sparse`);
    if (ADMIN_ALIASES[t[1]]) check(eqTJ(t[3], ADMIN_ALIASES[t[1]]), v, `alias ${t[1]}`);
    if (ADMIN_ENUMS[t[1]]) check(eqTJ(t[3], ADMIN_ENUMS[t[1]]), v, `enum ${t[1]}`);
  }
  const sig = canonicalIface(iface)[4];
  check(eqTJ(sig, ADMIN_SIGILS.map((n, i) => [64 + i, n, 0, {}])), v, 'sigils 64-72, kind 0');
  const svcs = canonicalIface(iface)[3];
  checkEq(svcs.length, 1, v, 'one service');
  checkEq(svcs[0][0], 0, v, 'service 0');
  checkEq(svcs[0][1], 'Admin', v, 'service name');
  check(eqTJ(svcs[0][2], ADMIN_METHODS.map(([id, n, i, o, f]) => [id, n, i, o, [], f, {}])), v, 'methods 0-11 with inputs, outputs and flags');
}

function checkAdmin(v) {
  const iface = () => byName.get('admin/interface').input;
  const typeMap = () => new Map(canonicalIface(iface())[2].map((t) => [t[1], t]));
  switch (v.type) {
    case 'interface':
      checkSchema(v);
      checkAdminInterface(v, v.input);
      break;
    case 'facet': {
      checkSchema(v);
      check(conforms(v.input, byName.get(v.interface).input) === null, v, 'admin facet conforms to the interface');
      checkEq(v.input[P.implements].$bytes, byName.get(v.interface).hash, v, 'implements = interface hash');
      checkEq(v.input[P.name], 'sparrow.hub.admin', v, 'facet name');
      for (const m of v.input[P.services][0][2]) check(eqTJ(m[6], { 'sparrow.level': 'manage' }), v, `method ${m[1]} carries sparrow.level manage`);
      break;
    }
    case 'stored_facet_key': {
      const src = byName.get(v.facet);
      check(eqTJ(v.input, src.input), v, 'input is the named facet');
      check(eqTJ(storedFacetKeyInput(v.input), v.key_input), v, 'key input: canonical facet, id 0, name kept');
      checkEq(v.key_input[P.name], v.input[P.name], v, 'name kept');
      checkEq(v.key_input[P.id], 0, v, 'id 0');
      checkEq(hex(encTJ(v.key_input)), v.key_input_cbor, v, 'key input bytes');
      checkEq(hex(storedFacetKey(v.input)), v.stored_facet_key, v, 'stored-facet key');
      checkEq(hex(encTJ(facetHashInput(v.input))), v.facet_hash_input_cbor, v, 'facet hash input');
      checkEq(hex(facetHash(v.input)), v.facet_hash, v, 'facet hash');
      checkEq(v.facet_hash, src.facet_hash, v, 'facet hash of the named facet vector');
      check(v.differs && v.facet_hash !== v.stored_facet_key, v, 'key and facet hash differ');
      break;
    }
    case 'admin_value':
      roundTrip(v, v.value, v.cbor);
      checkEq(v.type_name, typeMap().get(v.type_id)?.[2], v, 'type name');
      expectOk(() => checkValue(typeMap(), v.type_id, v.value), v, 'value conforms to its type');
      if (v.name === 'admin/value/config') {
        const key = byName.get('admin/stored-facet-key').stored_facet_key;
        check(v.value[0]['acme.charts'][2][0].$bytes === key, v, 'acme.charts lists its stored-facet key');
        checkEq(v.value[1].$map[0][0].$bytes, byName.get('interface/acme-charts-renderer').hash, v, 'defaults key is the Renderer interface hash');
        check(Object.values(v.value[0]).every((n) => (n[0] != null) !== (n[1] != null)), v, 'every node has exactly one link direction');
      }
      break;
    case 'message': {
      checkMessage(v);
      const m = v.message;
      checkEq(m[2], 9, v, 'failed_precondition');
      checkEq(m[4][0], 75, v, 'details are dynamic Problems');
      expectOk(() => checkValue(typeMap(), 10, m[4]), v, 'details conform');
      break;
    }
    default: check(false, v, `unknown type ${v.type}`);
  }
}

// ---------------------------------------------------------------------------
// scenarios/ (behaviour scenarios: messages are checked here, behaviour by session tests)

const OUTCOMES = new Set(['session_ready', 'dispatched', 'not_dispatched', 'call_ended', 'stream_idle', 'streams_open', 'half_finished',
  'held_back', 'no_reply', 'discarded', 'violation', 'session_closed', 'transport_closed', 'client_retries']);

function checkScenario(fname, sc) {
  const v = { name: `scenarios/${fname}` };
  checkEq(sc.format, 1, v, 'format');
  checkEq(`${sc.name}.json`, fname, v, 'file name');
  const schemaVec = byName.get(sc.given.schema);
  if (!check(schemaVec && schemaVec.type === 'schema', v, 'given.schema names a schema vector')) return;
  let state = stateOf(sc.given.schema);
  let pending = null;
  const opened = new Set(sc.given.session?.startsWith('established') ? ['shared'] : []);
  const credit = new Map(Object.entries(sc.given.initial_credit ?? {}));
  const errorFor = new Map();
  for (const st of sc.steps) if (st.message && st.message[0] === 20) errorFor.set(st.message[1], st.message[2]);
  sc.steps.forEach((st, i) => {
    const at = `step ${st.step}`;
    checkEq(st.step, i + 1, v, `${at} numbering`);
    if ('expect' in st) {
      check(OUTCOMES.has(st.expect), v, `${at}: unknown outcome ${st.expect}`);
      return;
    }
    check(st.from === 'client' || st.from === 'server', v, `${at} from`);
    check(/^(shared|lease:[1-9][0-9]*)$/.test(st.stream), v, `${at} stream ${st.stream}`);
    roundTrip(v, st.message, st.cbor, at);
    checkMessageFields(v, st.message);
    const m = st.message;
    checkEq(st.kind_name, LAYOUT[m[0]]?.[0], v, `${at} kind name`);
    const opens = st.from === 'client' && !opened.has(st.stream);
    if (opens) opened.add(st.stream);
    checkEq(!!st.opens_stream, opens, v, `${at} opens_stream`);
    if (opens) checkEq(st.header, st.stream === 'shared' ? '00' : '01', v, `${at} header`);
    if (m[0] === 16) {
      if (m[1] !== 0) checkEq(m[1] % 2, st.from === 'client' ? 0 : 1, v, `${at}: client call IDs are even, server call IDs odd`);
      else checkEq(st.stream, 'shared', v, `${at}: notifications use the shared lane`);
      const facet = state.doc[3].find((f) => f[P.id] === m[2]);
      const meth = facet?.[P.services].flatMap((sv) => sv[2]).find((x) => x[0] === m[3]);
      if (!meth && m[1] === 0) check(sc.steps[i + 1]?.expect === 'no_reply', v, `${at}: a notification to a missing facet or method is dropped`);
      else if (!meth) checkEq(errorFor.get(m[1]), 12, v, `${at}: a Request to a missing facet or method is answered with Error(unimplemented)`);
      else if (m[1] === 0) check(meth[5] & 0x2, v, `${at}: call ID 0 only for notifications`);
    }
    if (m[0] === 1 && m[5][0] === 2) checkEq(hex(schemaHash(m[5][2])), m[5][1].$bytes, v, `${at}: inline schema hash`);
    if (m[0] === 1) checkEq(m[5][1].$bytes, hex(schemaHash(state.doc)), v, `${at}: Welcome offers the scenario schema`);
    if (m[0] === 3) {
      pending = state.apply(m[3]);
      checkEq(hex(schemaHash(pending.doc)), m[2].$bytes, v, `${at}: SchemaUpdate hash after applying the delta`);
      checkEq(m[2].$bytes, byName.get(sc.given.delta).hash, v, `${at}: given.delta`);
    }
    if (m[0] === 4 && pending) { state = pending; pending = null; }
    if (m[0] === 18 && Array.isArray(m[2]) && m[2][0] >= 64 && st.from === 'server') {
      check(state.doc[3][0][P.types].some((t) => t[1] === m[2][0]), v, `${at}: dynamic type ${m[2][0]} is acknowledged before use`);
    }
    if ('counted_bytes' in st) {
      checkEq(st.counted_bytes, counted(m), v, `${at} counted bytes`);
      const key = `${m[1]}/${st.from}`;
      const rem = Number(credit.get(key));
      if (st.violation) {
        check(rem <= 0 && counted(m) > 0, v, `${at}: violation = counted data with no credit left`);
        checkEq(st.credit_before, rem, v, `${at} credit before`);
      } else {
        check(rem > 0 || counted(m) === 0, v, `${at}: sent with credit left, or counts zero bytes`);
        credit.set(key, rem - counted(m));
        checkEq(st.credit_after, rem - counted(m), v, `${at} credit after`);
      }
    } else if (m[0] === 24) {
      const key = `${m[1]}/${st.from === 'client' ? 'server' : 'client'}`;
      credit.set(key, Number(credit.get(key)) + m[2]);
      checkEq(st.credit_after, credit.get(key), v, `${at} credit after grant`);
    }
  });
}

let total = 0;
for (const [f, doc] of Object.entries(files)) {
  const fn = dispatch[f];
  if (!fn) { failures.push(`${f}: no checker for this file`); continue; }
  const before = failures.length;
  for (const v of doc.vectors) {
    try { fn(v, doc); } catch (e) { failures.push(`${v.name}: exception ${e.stack}`); }
  }
  if (f === 'schema.json') {
    try { checkSchemaModules(); } catch (e) { failures.push(`schema modules: exception ${e.stack}`); }
  }
  total += doc.vectors.length;
  console.log(`${f.padEnd(16)} ${String(doc.vectors.length).padStart(3)} vectors  ${failures.length === before ? 'ok' : `${failures.length - before} FAILED`}`);
}
{
  const before = failures.length;
  for (const [f, sc] of scenarioFiles) {
    try { checkScenario(f, sc); } catch (e) { failures.push(`scenarios/${f}: exception ${e.stack}`); }
  }
  console.log(`${'scenarios/'.padEnd(16)} ${String(scenarioFiles.length).padStart(3)} scenarios ${failures.length === before ? 'ok' : `${failures.length - before} FAILED`}`);
}
if (failures.length) {
  console.log(`\n${failures.length} failure(s) in ${checks} checks:`);
  for (const f of failures) console.log(`  FAIL ${f}`);
  process.exit(1);
}
console.log(`\nall ${total} vectors verified (${checks} checks)`);
