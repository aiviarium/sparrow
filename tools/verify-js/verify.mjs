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
import { encode, cdeEncodeOptions, decode } from 'cbor2';
import {
  concat, decodeCDE, decodeTJ, encTJ, eqTJ, fmtFloat, fromTJ, hex, unhex, u8eq, varintDecode, varintEncode, enc,
} from './lib/cbor.mjs';
import { SchemaState, schemaHash, canonical, canonicalBytes, validate, DeltaError } from './lib/schema.mjs';
import {
  DOMAIN, ed25519Sign, ed25519Verify, fileHash, keyId, privateKeyFromSeed, publicKeyRaw, sha256, signedBytes, verifyModule,
} from './lib/signing.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const dir = process.argv[2] ?? join(here, '..', '..', 'test-vectors');
const files = Object.fromEntries(
  readdirSync(dir).filter((f) => f.endsWith('.json')).sort().map((f) => [f, JSON.parse(readFileSync(join(dir, f), 'utf8'))]),
);
const byName = new Map();
for (const doc of Object.values(files)) for (const v of doc.vectors) byName.set(v.name, v);

const failures = [];
const notes = [];
let checks = 0;

function check(cond, vec, what) {
  checks++;
  if (!cond) failures.push(`${vec.name}: ${what}`);
  return cond;
}
function checkEq(got, want, vec, what) {
  return check(got === want, vec, `${what}: got ${got}, want ${want}`);
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
  try { decodeCDE(unhex(cborHex)); check(true, vec, ''); } catch (e) { check(false, vec, `${label} not accepted by cbor2 CDE decoder: ${e.message}`); }
}

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
    checkEq(hex(encTJ({ $float: v.decoded_float })), v.canonical_cbor, v, 'canonical float encoding');
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
      // What a JS encoder that does not know the declared type would emit.
      const naive = hex(encode(x, cdeEncodeOptions));
      if (naive !== v.cbor) notes.push(`${v.name}: a type-unaware JS encoder emits ${naive} instead of ${v.cbor}`);
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
    case 'enum':
      check(eqTJ(L.sigil, v.value), v, 'enum sigil');
      break;
    case 'union':
      check(eqTJ([L.variant_tag, L.value], v.value), v, 'union [tag, value]');
      break;
    case 'any':
      check(eqTJ([L.type_id, L.value], v.value), v, 'any [type_id, value]');
      break;
    case 'symbol':
      check(eqTJ(L.sigil ?? L.text, v.value), v, 'symbol');
      break;
    case 'map':
      // Entries are listed in arbitrary order; cbor2 must sort them the same way.
      checkEq(hex(encTJ({ $map: L.entries })), v.cbor, v, 'map key order');
      checkCanonical(v, v.cbor, 'map');
      break;
    default:
      check(false, v, `unknown rule ${v.rule}`);
  }
}

// ---------------------------------------------------------------------------
// messages (framing, handshake, calls)

const LAYOUT = { // kind -> [name, array length]
  0: ['Hello', 8], 1: ['Welcome', 7], 2: ['Ready', 2], 3: ['SchemaUpdate', 4], 4: ['SchemaAck', 2],
  5: ['AuthRefresh', 2], 6: ['AuthStatus', 3], 7: ['Ping', 2], 8: ['Pong', 2], 9: ['GoAway', 5],
  16: ['Request', 5], 17: ['Response', 3], 18: ['Item', 3], 19: ['End', 3], 20: ['Error', 5],
  21: ['Progress', 5], 22: ['Headers', 3], 23: ['Cancel', 3], 24: ['Credit', 3], 25: ['Bytes', 5],
};

const schemaHashHex = (name) => byName.get(name)?.hash;
const stateCache = new Map();

/** Schema state after the named schema vector (base or delta), recomputed in JS. */
function stateOf(name) {
  if (stateCache.has(name)) return stateCache.get(name);
  const v = byName.get(name);
  let st;
  if (v.type === 'schema') st = new SchemaState(v.input);
  else st = stateOf(v.from).apply(v.delta);
  stateCache.set(name, st);
  return st;
}

function checkOffer(v, offer) {
  const h = hex(unhex(offer[1].$bytes));
  switch (offer[0]) {
    case 0: check(Object.values(byName).length >= 0 && [...byName.values()].some((s) => s.hash === h), v, 'offer [0] names a known hash'); break;
    case 1: {
      const from = [...byName.values()].find((s) => s.hash === offer[2].$bytes);
      if (!check(from, v, 'delta offer: unknown from hash')) return;
      checkEq(hex(schemaHash(stateOf(from.name).apply(offer[3]).doc)), h, v, 'delta offer: hash after applying delta');
      break;
    }
    case 2: checkEq(hex(schemaHash(offer[2])), h, v, 'inline schema hash'); break;
    case 3:
      checkEq(offer[2], `/sparrow/schema/${Buffer.from(unhex(h)).toString('base64url')}`, v, 'out-of-band location');
      break;
    default: check(false, v, 'bad schema-offer');
  }
}

function checkMessage(v) {
  roundTrip(v, v.message, v.cbor);
  const b = unhex(v.cbor);
  checkEq(v.length, b.length, v, 'length');
  checkEq(v.framed, hex(concat(varintEncode(b.length), b)), v, 'framed = varint(length) || cbor');
  const m = v.message;
  const lay = LAYOUT[m[0]];
  if (check(lay, v, `unknown kind ${m[0]}`)) {
    checkEq(v.kind_name, lay[0], v, 'kind name');
    checkEq(m.length, lay[1], v, `${lay[0]} array length`);
  }
  if (v.matches_spec) checkEq(v.framed, v.spec_framed, v, 'bytes from the spec text');
  // Cross-file semantic checks.
  if (m[0] === 0) {
    if (m[4] !== null) check([...byName.values()].some((s) => s.type === 'schema' && s.hash === m[4].$bytes), v, 'known_schema is a schema vector hash');
    if (m[5] !== null) {
      checkEq(m[5][0], 2, v, 'client_schema tag');
      checkEq(hex(schemaHash(m[5][2])), m[5][1].$bytes, v, 'client_schema hash');
      try { validate(m[5][2]); check(true, v, ''); } catch (e) { check(false, v, `client schema invalid: ${e.message}`); }
    }
    if (m[7] === true) checkEq(m[1].length, 1, v, 'optimistic Hello lists exactly one version');
  }
  if (m[0] === 1) { checkEq(m[3].$bytes.length, 32, v, 'session_id is 16 bytes'); checkOffer(v, m[5]); }
  if (m[0] === 2) check([...byName.values()].some((s) => s.hash === m[1].$bytes), v, 'Ready names a known hash');
  if (m[0] === 3) {
    const want = schemaHashHex(v.refs?.hash);
    checkEq(m[2].$bytes, want, v, 'SchemaUpdate hash');
    checkEq(hex(schemaHash(stateOf('schema/server-base').apply(m[3]).doc)), want, v, 'SchemaUpdate delta applied in JS');
  }
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
      if (!v.decode_only) checkEq(hex(varintEncode(BigInt(v.value.$int ?? v.value))), v.encoded, v, 'varint encode');
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
      checkEq(hex(concat(...v.parts.map((p) => unhex(p.hex)))), v.bytes, v, 'stream bytes = parts');
      for (const p of v.parts) {
        if (!p.ref) continue;
        const r = byName.get(p.ref);
        checkEq(p.hex, r.type === 'message' && p.what.startsWith('framed') ? r.framed : r.cbor, v, `part ${p.what}`);
      }
      const len = varintDecode(unhex(v.bytes).subarray(1));
      checkEq(Number(len.value), unhex(v.bytes).length - 1 - len.length, v, 'length prefix covers the rest');
      if (v.reverse_bytes) checkEq(v.reverse_bytes, byName.get('example-7.7/response').framed, v, 'reverse direction');
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
      checkEq(counted(s.message), s.counted_bytes, v, `step ${i} counted`);
      remaining -= counted(s.message);
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

function checkSchema(v) {
  if (v.type === 'schema') {
    try { validate(v.input); check(true, v, ''); } catch (e) { check(false, v, `JS validation failed: ${e.message}`); }
    const c = canonical(v.input);
    check(eqTJ(c, v.canonical), v, 'JS canonical form differs from vector');
    checkEq(hex(canonicalBytes(v.input)), v.canonical_cbor, v, 'canonical bytes (JS canonicalised from unsorted input)');
    checkEq(unhex(v.canonical_cbor).length, v.canonical_length, v, 'canonical length');
    checkEq(hex(sha256(unhex(v.canonical_cbor))), v.sha256, v, 'sha256');
    checkEq(hex(schemaHash(v.input)), v.hash, v, 'hash = 0x01 || sha256');
    checkEq(v.hash.length, 66, v, 'hash is 33 bytes');
    checkCanonical(v, v.canonical_cbor, 'canonical schema');
    roundTrip(v, v.canonical, v.canonical_cbor, 'canonical');
    return;
  }
  checkEq(byName.get(v.from).hash, v.from_hash, v, 'from_hash');
  if (v.expected_valid) {
    const st = stateOf(v.name);
    checkEq(hex(encTJ(st.doc)), v.canonical_cbor, v, 'canonical bytes after delta');
    checkEq(hex(schemaHash(st.doc)), v.hash, v, 'hash after delta');
    check(eqTJ(st.retiredJSON(), v.retired_after), v, `retired ids ${JSON.stringify(st.retiredJSON())}`);
    const u = v.schema_update;
    roundTrip(v, u.message, u.cbor, 'SchemaUpdate');
    check(u.message[0] === 3 && u.message[1] === v.epoch && u.message[2].$bytes === v.hash && eqTJ(u.message[3], v.delta), v, 'SchemaUpdate fields');
  } else {
    try {
      stateOf(v.from).apply(v.delta);
      check(false, v, `invalid delta was accepted (expected ${v.expected_error})`);
    } catch (e) {
      if (!(e instanceof DeltaError)) throw e;
      checkEq(e.code, v.expected_error, v, 'error code');
    }
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
      checkEq(hex(encTJ(v.unsigned)), v.unsigned_cbor, v, 'unsigned canonical CBOR');
      checkCanonical(v, v.unsigned_cbor, 'unsigned');
      roundTrip(v, v.unsigned, v.unsigned_cbor, 'unsigned');
      const expectDomain = v.type === 'module' && !v.name.includes('wrong-domain') ? DOMAIN.module
        : v.type === 'certificate' && !v.name.includes('wrong-domain') ? DOMAIN.cert
        : v.type === 'revocation' ? DOMAIN.revoked : v.domain;
      checkEq(v.domain, expectDomain, v, 'domain string');
      const sb = signedBytes(v.domain, v.unsigned);
      checkEq(hex(sb), v.signed_bytes, v, 'signed bytes = UTF-8 domain || canonical CBOR');
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
        checkEq(hex(unhex(sig[0].$bytes)), hex(keyId(signerPub)), v, 'sig key_id');
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
      const all = doc.vectors;
      const ctx = {
        roots: ctxDef.root_public_keys.map(unhex),
        webKeys: all.filter((x) => x.type === 'certificate').map((x) => x.certificate),
        revoked: byName.get(ctxDef.web_revoked).revocation,
        now: ctxDef.now,
      };
      checkEq(ctxDef.now, Date.parse(ctxDef.now_iso) / 1000, v, 'now_iso');
      const reason = verifyModule(byName.get(v.module).entry, ctx);
      checkEq(reason, v.expected_reason, v, 'acceptance result');
      checkEq(v.expected_valid, reason === 'ok', v, 'expected_valid');
      break;
    }
    default: check(false, v, `unknown type ${v.type}`);
  }
}

function checkSigningDoc(doc) {
  const w = doc.web_annotations_example;
  const fake = { name: 'signing/web_annotations_example' };
  roundTrip(fake, w.value, w.cbor, 'web annotations');
  const okMods = doc.vectors.filter((x) => x.type === 'verify' && x.expected_valid).map((x) => byName.get(x.module).entry);
  check(eqTJ(w.value['web.modules'], okMods), fake, 'web.modules = modules that verify');
}

// ---------------------------------------------------------------------------
// status.json

const CORE_NAMES = ['ok', 'cancelled', 'unknown', 'invalid_argument', 'deadline_exceeded', 'not_found', 'already_exists',
  'permission_denied', 'resource_exhausted', 'failed_precondition', 'aborted', 'out_of_range', 'unimplemented', 'internal',
  'unavailable', 'data_loss', 'unauthenticated', 'protocol_error', 'schema_mismatch', 'unsupported_version', 'not_ready',
  'going_away', 'message_too_large'];

function checkStatus(v) {
  for (const e of v.entries) {
    const core = e.status >= 0 && e.status <= 31;
    checkEq(e.websocket_close_code, core ? 4000 + e.status : 4002, v, `ws close for ${e.status}`);
    checkEq(e.websocket_close_reason_prefix, core ? null : String(e.status), v, `ws reason for ${e.status}`);
    checkEq(e.webtransport_session_close_code, e.status, v, `wt session close for ${e.status}`);
    checkEq(e.webtransport_stream_reset_code, e.status <= 255 ? e.status : null, v, `wt reset for ${e.status}`);
    if (e.status < CORE_NAMES.length) checkEq(e.name, CORE_NAMES[e.status], v, `name of ${e.status}`);
  }
  checkEq(v.entries.filter((e) => e.status < 23).length, 23, v, 'all 23 defined core statuses present');
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
};

let total = 0;
for (const [f, doc] of Object.entries(files)) {
  const fn = dispatch[f];
  if (!fn) { failures.push(`${f}: no checker for this file`); continue; }
  const before = failures.length;
  for (const v of doc.vectors) {
    try { fn(v, doc); } catch (e) { failures.push(`${v.name}: exception ${e.stack}`); }
  }
  if (f === 'signing.json') checkSigningDoc(doc);
  total += doc.vectors.length;
  console.log(`${f.padEnd(16)} ${String(doc.vectors.length).padStart(3)} vectors  ${failures.length === before ? 'ok' : `${failures.length - before} FAILED`}`);
}
for (const n of notes) console.log(`note: ${n}`);
if (failures.length) {
  console.log(`\n${failures.length} failure(s) in ${checks} checks:`);
  for (const f of failures) console.log(`  FAIL ${f}`);
  process.exit(1);
}
console.log(`\nall ${total} vectors verified (${checks} checks)`);
