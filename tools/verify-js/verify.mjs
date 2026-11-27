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
  P, SchemaState, DeltaError, canonicalPart, canonicalIface, canonicalSchema, partHash, partHashInput, ifaceHash,
  schemaHash, schemaHashInput, conforms, validatePart, validateIface, validateSchema,
} from './lib/schema.mjs';
import {
  DOMAIN, ed25519Sign, ed25519Verify, fileHash, keyId, moduleInPart, privateKeyFromSeed, publicKeyRaw, sha256, signedBytes, verifyModule,
} from './lib/signing.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const dir = process.argv[2] ?? join(here, '..', '..', 'test-vectors');
const files = Object.fromEntries(
  readdirSync(dir).filter((f) => f.endsWith('.json')).sort().map((f) => [f, JSON.parse(readFileSync(join(dir, f), 'utf8'))]),
);
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

function checkEncoding(v) {
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
      expectOk(() => validateSchema(offer[2]), v, 'inline schema invalid');
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
      expectOk(() => validateSchema(m[5][2]), v, 'client schema invalid');
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
        checkEq(p.hex, p.what.startsWith('framed') ? r.framed : r.cbor, v, `part ${p.what}`);
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
      check(remaining > 0, v, `step ${i}: send allowed only with credit > 0`);
      roundTrip(v, s.message, s.cbor, `step ${i}`);
      remaining -= counted(s.message);
      checkEq(s.counted_bytes, counted(s.message), v, `step ${i} counted`);
      checkEq(s.remaining_after, remaining, v, `step ${i} remaining`);
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

function partHashesOf(doc) {
  return canonicalSchema(doc)[3].map((p) => ({ part_id: p[P.id], part_name: p[P.name], part_hash: hex(partHash(p)) }));
}

function checkSchema(v) {
  switch (v.type) {
    case 'part': {
      expectOk(() => validatePart(v.input), v, 'JS part validation');
      check(eqTJ(canonicalPart(v.input), v.canonical), v, 'canonical part');
      checkEq(hex(encTJ(canonicalPart(v.input))), v.canonical_cbor, v, 'canonical part bytes');
      checkEq(hex(encTJ(partHashInput(v.input))), v.hash_input_cbor, v, 'part hash input (id 0, name "")');
      checkEq(hex(partHash(v.input)), v.part_hash, v, 'part hash');
      checkCanonical(v, v.canonical_cbor, 'canonical part');
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
      expectOk(() => validatePart(v.part), v, 'part validation');
      const iface = byName.get(v.interface).input;
      const got = conforms(v.part, iface);
      checkEq(got === null, v.expected_conforms, v, 'conforms');
      check(eqTJ(got, v.first_mismatch), v, `first mismatch ${JSON.stringify(got)}`);
      if (v.part[P.implements]) checkEq(v.part[P.implements].$bytes, hex(ifaceHash(iface)), v, 'implements = interface hash');
      break;
    }
    case 'schema': {
      expectOk(() => validateSchema(v.input), v, 'JS schema validation');
      check(eqTJ(canonicalSchema(v.input), v.canonical), v, 'canonical schema');
      checkEq(hex(encTJ(canonicalSchema(v.input))), v.canonical_cbor, v, 'canonical schema bytes (JS canonicalised from unsorted input)');
      checkEq(unhex(v.canonical_cbor).length, v.canonical_length, v, 'canonical length');
      check(eqTJ(partHashesOf(v.input), v.part_hashes), v, 'part hashes');
      check(eqTJ(schemaHashInput(v.input), v.hash_input), v, 'schema hash input');
      checkEq(hex(encTJ(schemaHashInput(v.input))), v.hash_input_cbor, v, 'schema hash input bytes');
      checkEq(hex(schemaHash(v.input)), v.hash, v, 'schema hash');
      checkCanonical(v, v.canonical_cbor, 'canonical schema');
      roundTrip(v, v.canonical, v.canonical_cbor, 'canonical');
      break;
    }
    case 'part_hash_invariance': {
      const [pa] = v.schema_a[3];
      const [pb] = v.schema_b[3];
      check(pa[P.id] !== pb[P.id] && pa[P.name] !== pb[P.name], v, 'parts differ in id and name');
      checkEq(hex(partHash(pa)), v.part_hash, v, 'part hash a');
      checkEq(hex(partHash(pb)), v.part_hash, v, 'part hash b');
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
        check(eqTJ(partHashesOf(st.doc), v.part_hashes), v, 'part hashes after delta');
        checkEq(hex(schemaHash(st.doc)), v.hash, v, 'hash after delta');
        check(eqTJ(st.removedIds(), v.removed_part_ids_after), v, `removed part ids ${JSON.stringify(st.removedIds())}`);
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
      checkEq(moduleInPart(v.part_name, v.module_id), v.expected_valid, v, 'module id within part name');
      break;
    case 'part_web_keys': {
      const keys = Object.keys(v.part_annotations).filter((k) => k.startsWith('web.'));
      check(eqTJ(keys.filter((k) => k === 'web.modules'), v.honoured_web_keys), v, 'honoured keys');
      check(eqTJ(keys.filter((k) => k !== 'web.modules').sort(), [...v.ignored_web_keys].sort()), v, 'ignored keys');
      break;
    }
    default: check(false, v, `unknown type ${v.type}`);
  }
}

function checkSchemaModules() {
  // Every module a part of the server schema ships must be named after the part.
  const base = byName.get('schema/server-base');
  const fake = { name: 'schema/server-base (web.modules)' };
  for (const p of base.input[3]) {
    for (const m of p[P.ann]['web.modules'] ?? []) {
      check(moduleInPart(p[P.name], m.id), fake, `module ${m.id} in part ${p[P.name]}`);
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
      checkEq(cr[2], v.part_map.hub_part_id, v, 'client uses the hub part ID');
      checkEq(fr[2], v.part_map.node_part_id, v, 'forwarded call uses the node part ID');
      checkEq(cr[3], fr[3], v, 'same method ID');
      check(eqTJ(cr[5], fr[5]), v, 'same input value');
      const pl = v.payload_cbor;
      checkEq(hex(encTJ(cr[5])), pl, v, 'payload bytes');
      check(msgTail(v.client_request.cbor, pl) && msgTail(v.forwarded_request.cbor, pl), v, 'payload bytes identical in both messages');
      // Metadata rules.
      checkEq(mdGet(fr[4], 32), mdGet(cr[4], 32) - v.elapsed_ms, v, 'deadline lowered by elapsed time');
      checkEq(mdGet(fr[4], 37), v.session_principal, v, 'principal set by the hub');
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
      // Part identity across hops.
      const hubPart = byName.get('schema/server-base').input[3].find((p) => p[P.id] === v.part_map.hub_part_id);
      const nodePart = byName.get('schema/node-acme-charts').input[3].find((p) => p[P.id] === v.part_map.node_part_id);
      checkEq(hex(partHash(hubPart)), v.part_map.part_hash, v, 'hub part hash');
      checkEq(hex(partHash(nodePart)), v.part_map.part_hash, v, 'node part hash (same part)');
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
      const part = welcome[5][2][3].find((p) => p[P.id] === m[2]);
      check(part && part[P.services].some((s) => s[2].some((mm) => mm[0] === m[3])), v, 'method exists in the hub schema the node sees');
      break;
    }
    case 'schema_view': {
      const base = byName.get(v.from);
      const view = canonicalSchema(base.input);
      view[3] = view[3].filter((p) => !v.omitted_part_ids.includes(p[P.id]));
      checkEq(hex(schemaHash(view)), v.hash, v, 'view hash');
      const w = byName.get('welcome/node-pipe').message;
      checkEq(w[5][1].$bytes, v.hash, v, 'welcome/node-pipe offers this view');
      break;
    }
    case 'node_id_table':
      for (const e of v.entries) checkEq(NODE_ID.test(e.node_id), e.valid, v, `node id ${JSON.stringify(e.node_id)}`);
      break;
    case 'part_owner_table':
      for (const e of v.entries) checkEq(e.part_name === e.node_id || e.part_name.startsWith(`${e.node_id}.`), e.allowed, v, `${e.node_id} / ${e.part_name}`);
      break;
    case 'imported_name': {
      checkEq(`${v.peer_id}/${v.part_name}`, v.imported_name, v, 'imported name');
      const inv = byName.get('schema/part-hash-invariance');
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
  'handshake.json': checkMessage,
  'calls.json': checkMessage,
  'credit.json': checkCredit,
  'schema.json': checkSchema,
  'signing.json': checkSigning,
  'status.json': checkStatus,
  'hub.json': checkHub,
};

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
if (failures.length) {
  console.log(`\n${failures.length} failure(s) in ${checks} checks:`);
  for (const f of failures) console.log(`  FAIL ${f}`);
  process.exit(1);
}
console.log(`\nall ${total} vectors verified (${checks} checks)`);
