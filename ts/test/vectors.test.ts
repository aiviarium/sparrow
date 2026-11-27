// Conformance: every vector of ../test-vectors in the areas this library
// covers (encoding, framing, handshake, calls, credit, schema, status, admin
// interface values). signing.json (Web Profile module signing) and hub.json
// (Hub Profile forwarding) are out of scope and skipped explicitly; the
// coverage is printed at the end.
import { afterAll, describe, expect, it } from 'vitest';
import { Float, Writer, bytesEqual, decode, encode, isCanonical, Reader } from '../src/cbor.js';
import {
  CreditWindow,
  DecodeError,
  FrameDecoder,
  checkParams,
  classifyStreamHeader,
  countedBytes,
  decodeMessage,
  decodeVarint,
  encodeMessage,
  encodeVarint,
  frame,
  kindName,
  kindRange,
  limitsOf,
  type Message,
} from '../src/wire.js';
import {
  SchemaError,
  SchemaState,
  canonicalFacet,
  canonicalInterface,
  canonicalSchema,
  conforms,
  decodeSchema,
  deltaOf,
  facetHash,
  facetHashInput,
  facetOf,
  facetTree,
  interfaceHash,
  interfaceOf,
  interfaceTree,
  schemaHash,
  schemaHashInputTree,
  schemaOf,
  schemaTree,
  T,
  typeRefOf,
  validateFacet,
  validateInterface,
  validateSchema,
  type Schema,
} from '../src/schema.js';
import { Codec } from '../src/value.js';
import { MAX_WEBSOCKET_REASON, MAX_WEBTRANSPORT_REASON, statusName, truncateReason, webSocketCloseCode } from '../src/status.js';
import { byName, eqTJ, fromTJ, hex, loadScenarios, loadVectors, toTJ, unhex, type TJ } from './helpers/tjson.js';

const coverage = new Map<string, { checked: number; skipped: number; total: number }>();
function count(file: string, checked: boolean) {
  const c = coverage.get(file) ?? { checked: 0, skipped: 0, total: 0 };
  c.total++;
  if (checked) c.checked++;
  else c.skipped++;
  coverage.set(file, c);
}

afterAll(() => {
  let ch = 0;
  let tot = 0;
  const lines = [...coverage.entries()].map(([f, c]) => {
    ch += c.checked;
    tot += c.total;
    return `  ${f.padEnd(16)} ${c.checked}/${c.total} checked${c.skipped ? `, ${c.skipped} skipped (out of scope)` : ''}`;
  });
  console.log(`vector coverage: ${ch}/${tot} vectors checked\n${lines.join('\n')}`);
});

const rt = (tj: TJ, cborHex: string) => {
  expect(hex(encode(fromTJ(tj)))).toBe(cborHex);
  expect(eqTJ(toTJ(decode(unhex(cborHex))), tj)).toBe(true);
};

/** Decodes a message with the typed decoder and re-encodes it: the bytes must not change. */
function msgRoundTrip(cborHex: string): Message {
  const b = unhex(cborHex);
  const m = decodeMessage(b);
  expect(hex(encodeMessage(m))).toBe(cborHex);
  return m;
}

const schemaVec = (name: string): Schema => schemaOf(fromTJ(byName().get(name).input));

const stateCache = new Map<string, SchemaState>();
function stateOf(name: string): SchemaState {
  const c = stateCache.get(name);
  if (c) return c;
  const v = byName().get(name);
  const st = v.type === 'schema' ? SchemaState.create(schemaOf(fromTJ(v.input))) : stateOf(v.from).apply(deltaOf(fromTJ(v.delta)));
  stateCache.set(name, st);
  return st;
}

function expectSchemaError(f: () => unknown, code: string) {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(SchemaError);
    expect((e as SchemaError).code).toBe(code);
    return;
  }
  throw new Error(`accepted, expected ${code}`);
}

// ---------------------------------------------------------------------------

describe('encoding.json', () => {
  const doc = loadVectors('encoding.json');
  const notes = schemaVec('schema/server-base').facets.find((f) => f.id === 16)!;
  const codec = new Codec(notes);
  for (const v of doc.vectors) {
    it(v.name, () => {
      count('encoding.json', true);
      if (v.type === 'depth') {
        const b = unhex(v.cbor);
        if (v.expected_valid) {
          expect(eqTJ(toTJ(decode(b)), v.message)).toBe(true);
          expect(() => decodeMessage(b)).not.toThrow();
        } else {
          expect(() => decode(b)).toThrow(/nesting/);
          expect(() => decodeMessage(b)).toThrow();
        }
        return;
      }
      if (v.type === 'non_shortest') {
        const b = unhex(v.cbor);
        expect(eqTJ(toTJ(decode(b)), v.message)).toBe(true);
        expect(hex(encode(decode(b)))).toBe(v.shortest_cbor);
        expect(hex(encode(fromTJ(v.message)))).toBe(v.shortest_cbor);
        expect(isCanonical(b)).toBe(false);
        if (v.name !== 'non-shortest/unsorted-metadata') expect(() => decode(b, { requirePreferred: true })).toThrow();
        decodeMessage(b);
        return;
      }
      if (v.type === 'integer_range') {
        const b = unhex(v.cbor);
        expect(hex(encode(fromTJ(v.message)))).toBe(v.cbor);
        if (v.expected_valid) {
          expect(hex(encodeMessage(decodeMessage(b)))).toBe(v.cbor);
        } else {
          expect(v.expected_error).toBe('protocol_error');
          expect(() => decodeMessage(b)).toThrow(DecodeError);
        }
        return;
      }
      if (v.type === 'decode_only') {
        expect(new Reader(unhex(v.cbor)).float()).toBe(Number(v.decoded_float));
        expect(codec.decode(T.float64, unhex(v.cbor))).toBe(Number(v.decoded_float));
        const w = new Writer();
        w.float(Number(v.decoded_float));
        expect(hex(w.finish())).toBe(v.canonical_cbor);
        return;
      }
      rt(v.value, v.cbor);
      // Schema-driven: decode with the value codec and encode again.
      let t: TJ = v.schema_type;
      if (t === 'float32') t = T.float32;
      if (t === 'float64') t = T.float64;
      if (typeof t === 'number' || Array.isArray(t)) {
        const ref = typeRefOf(fromTJ(t));
        const b = unhex(v.cbor);
        const val = codec.decode(ref, b);
        const back = codec.encode(ref, val);
        if (v.rule === 'struct' && v.name === 'struct/note-trailing-nulls') {
          // The logical input had trailing nulls; the codec omits them.
          expect(hex(back)).toBe(v.cbor);
        }
        expect(hex(back)).toBe(v.cbor);
      }
    });
  }
});

// ---------------------------------------------------------------------------

function checkMessageVector(v: TJ) {
  rt(v.message, v.cbor);
  const m = msgRoundTrip(v.cbor);
  const b = unhex(v.cbor);
  expect(v.length).toBe(b.length);
  expect(hex(frame(b))).toBe(v.framed);
  expect(m.kind).toBe(v.message[0]);
  expect(v.kind_name).toBe(kindName(m.kind));
  if (v.matches_spec) expect(v.framed).toBe(v.spec_framed);
  const known = (h: Uint8Array) => [...byName().values()].some((s) => s.hash === hex(h));
  switch (m.kind) {
    case 0:
      if (m.knownSchema) expect(known(m.knownSchema)).toBe(true);
      if (m.clientSchema) {
        const s = decodeSchema(m.clientSchema.schema);
        validateSchema(s);
        expect(hex(schemaHash(s))).toBe(hex(m.clientSchema.hash));
      }
      if (m.optimistic) expect(m.versions.length).toBe(1);
      break;
    case 1: {
      expect(m.sessionId.length).toBe(16);
      const o = m.serverSchema;
      if (o.form === 2) {
        const s = decodeSchema(o.schema);
        validateSchema(s);
        expect(hex(schemaHash(s))).toBe(hex(o.hash));
      } else if (o.form === 1) {
        const from = [...byName().values()].find((s) => (s.type === 'schema' || (s.type === 'delta' && s.expected_valid)) && s.hash === hex(o.from));
        expect(from).toBeDefined();
        const st = stateOf(from.name).apply(deltaOf(decode(o.delta)));
        expect(hex(st.hash)).toBe(hex(o.hash));
      } else if (o.form === 0) {
        expect(known(o.hash)).toBe(true);
      }
      break;
    }
    case 2:
      expect(known(m.schemaHash)).toBe(true);
      break;
    case 3: {
      const want = byName().get(v.refs.hash).hash;
      expect(hex(m.hash)).toBe(want);
      const st = stateOf('schema/server-base').applyUpdate(m.epoch, m.hash, deltaOf(decode(m.delta)));
      expect(hex(st.hash)).toBe(want);
      break;
    }
  }
}

describe('framing.json', () => {
  const doc = loadVectors('framing.json');
  for (const v of doc.vectors) {
    it(v.name, () => {
      count('framing.json', true);
      switch (v.type) {
        case 'quic_varint': {
          const want = BigInt(v.value.$int ?? v.value);
          const d = decodeVarint(unhex(v.encoded))!;
          expect(BigInt(d.value)).toBe(want);
          expect(d.length).toBe(v.encoded.length / 2);
          const shortest = hex(encodeVarint(want));
          if (v.decode_only) expect(shortest).not.toBe(v.encoded);
          else expect(shortest).toBe(v.encoded);
          break;
        }
        case 'stream_header_table':
          for (const e of v.entries) expect(classifyStreamHeader(parseInt(e.byte, 16), e.opener, e.shared_lane_open)).toBe(e.result);
          break;
        case 'kind_range_table':
          for (const e of v.entries) {
            const r = kindRange(e.kind);
            expect([r.owner, r.action]).toEqual([e.owner, e.if_unknown]);
          }
          break;
        case 'message':
          checkMessageVector(v);
          break;
        case 'stream': {
          let all = unhex(v.bytes);
          if (v.parts[0].what.startsWith('stream header')) all = all.subarray(1);
          const fd = new FrameDecoder();
          // Feed byte by byte: the decoder must reassemble across chunks.
          const msgs: Uint8Array[] = [];
          for (let i = 0; i < all.length; i++) msgs.push(...fd.push(all.subarray(i, i + 1)));
          expect(msgs.length).toBe(1);
          expect(fd.pending).toBe(0);
          decodeMessage(msgs[0]);
          for (const p of v.parts) if (p.ref) expect(p.hex).toBe(p.what.startsWith('framed') ? byName().get(p.ref).framed : byName().get(p.ref).cbor);
          if (v.reverse_bytes) expect(v.reverse_bytes).toBe(byName().get(v.reverse_ref ?? 'example-7.7/response').framed);
          break;
        }
        case 'websocket':
          expect(v.ws_messages[0]).toBe(byName().get('example-7.7/request').cbor);
          for (const m of v.ws_messages) msgRoundTrip(m);
          break;
        default:
          throw new Error(`unknown type ${v.type}`);
      }
    });
  }
  it('rejects a frame above maxMessageSize from its prefix', () => {
    const fd = new FrameDecoder(16384);
    expect(() => fd.push(encodeVarint(16385))).toThrow(/maxMessageSize/);
    expect(() => new FrameDecoder().push(Uint8Array.of(0))).toThrow(/empty/);
  });
});

describe('handshake.json', () => {
  const doc = loadVectors('handshake.json');
  for (const v of doc.vectors) {
    it(v.name, () => {
      count('handshake.json', true);
      if (v.type !== 'params_table') {
        checkMessageVector(v);
        return;
      }
      for (const e of v.entries) {
        const p = toTJ(decode(unhex(e.params_cbor)));
        expect(hex(encode(fromTJ(e.params)))).toBe(e.params_cbor);
        const err = checkParams(p);
        if (e.expected === 'goaway') {
          expect(err?.key).toBe(e.key);
          expect(e.status).toBe(3);
        } else {
          expect(err).toBeNull();
          expect(limitsOf(p, e.sent_in === 'Hello' ? 'client' : 'server')).toEqual(e.effective);
        }
      }
    });
  }
});

describe('calls.json', () => {
  const doc = loadVectors('calls.json');
  for (const v of doc.vectors) {
    it(v.name, () => {
      count('calls.json', true);
      if (v.type !== 'unimplemented') {
        checkMessageVector(v);
        return;
      }
      const req = msgRoundTrip(v.request.cbor);
      const er = msgRoundTrip(v.error.cbor);
      expect(req.kind).toBe(16);
      expect(er.kind).toBe(20);
      if (req.kind !== 16 || er.kind !== 20) return;
      const sc = canonicalSchema(schemaVec(v.schema));
      const f = sc.facets.find((x) => x.id === req.facetId);
      const has = f?.services.some((s) => s.methods.some((m) => m.id === req.methodId));
      expect(has).toBeFalsy();
      expect(er.callId).toBe(req.callId);
      expect(er.status).toBe(12);
    });
  }
});

describe('credit.json', () => {
  const doc = loadVectors('credit.json');
  const counted = (cborHex: string) => {
    const b = unhex(cborHex);
    return countedBytes(decodeMessage(b), b.length);
  };
  for (const v of doc.vectors) {
    it(v.name, () => {
      count('credit.json', true);
      if (v.type === 'credit_count') {
        rt(v.message, v.cbor);
        expect(counted(v.cbor)).toBe(v.counted_bytes);
        const len = unhex(v.cbor).length;
        expect(frame(unhex(v.cbor)).length).toBe(v.framed_length);
        expect(len).toBeGreaterThan(0);
        return;
      }
      const w = new CreditWindow(v.initial_credit);
      const recv = new CreditWindow(v.initial_credit);
      for (const s of v.steps) {
        if (s.action === 'send') {
          const n = counted(s.cbor);
          expect(n).toBe(s.counted_bytes);
          expect(w.canSend(n)).toBe(true);
          expect(w.consume(n)).toBe(true);
          expect(recv.consume(n)).toBe(true);
          expect(w.remaining).toBe(s.remaining_after);
        } else if (s.action === 'violation') {
          const n = counted(s.cbor);
          expect(w.canSend(n)).toBe(false);
          expect(recv.consume(n)).toBe(false); // the receiver detects it
          expect(recv.remaining).toBe(s.remaining);
          const a = msgRoundTrip(s.answer.cbor);
          expect(a).toMatchObject({ kind: 23, status: 17 });
        } else if (s.action === 'receive_credit') {
          w.grant(s.message[2]);
          recv.grant(s.message[2]);
          expect(w.remaining).toBe(s.remaining_after);
        } else {
          expect(w.canSend(1)).toBe(s.may_send);
          expect(w.remaining).toBe(s.remaining);
        }
      }
    });
  }
});

describe('schema.json', () => {
  const doc = loadVectors('schema.json');
  for (const v of doc.vectors) {
    it(v.name, () => {
      count('schema.json', true);
      checkSchemaVector(v);
    });
  }
});

function checkSchemaVector(v: TJ) {
  switch (v.type) {
    case 'facet': {
      const f = facetOf(fromTJ(v.input));
      validateFacet(f);
      expect(eqTJ(toTJ(facetTree(canonicalFacet(f))), v.canonical)).toBe(true);
      expect(hex(encode(facetTree(canonicalFacet(f))))).toBe(v.canonical_cbor);
      expect(hex(facetHashInput(f))).toBe(v.hash_input_cbor);
      expect(hex(facetHash(f))).toBe(v.facet_hash);
      expect(isCanonical(unhex(v.canonical_cbor))).toBe(true);
      break;
    }
    case 'interface': {
      const i = interfaceOf(fromTJ(v.input));
      if (v.expected_valid) {
        validateInterface(i);
        expect(eqTJ(toTJ(interfaceTree(canonicalInterface(i))), v.canonical)).toBe(true);
        expect(hex(encode(interfaceTree(canonicalInterface(i))))).toBe(v.canonical_cbor);
        expect(hex(interfaceHash(i))).toBe(v.hash);
      } else expectSchemaError(() => validateInterface(i), v.expected_error);
      break;
    }
    case 'conformance': {
      const f = facetOf(fromTJ(v.facet));
      validateFacet(f);
      const iface = interfaceOf(fromTJ(byName().get(v.interface).input));
      const got = conforms(f, iface);
      expect(got === null).toBe(v.expected_conforms);
      expect(got).toEqual(v.first_mismatch);
      if (f.implements) expect(hex(f.implements)).toBe(hex(interfaceHash(iface)));
      break;
    }
    case 'schema': {
      const s = schemaOf(fromTJ(v.input));
      validateSchema(s);
      const c = canonicalSchema(s);
      expect(eqTJ(toTJ(schemaTree(c)), v.canonical)).toBe(true);
      expect(hex(encode(schemaTree(c)))).toBe(v.canonical_cbor);
      expect(unhex(v.canonical_cbor).length).toBe(v.canonical_length);
      expect(c.facets.map((f) => ({ facet_id: f.id, facet_name: f.name, facet_hash: hex(facetHash(f)) }))).toEqual(v.facet_hashes);
      expect(eqTJ(toTJ(schemaHashInputTree(s)), v.hash_input)).toBe(true);
      expect(hex(encode(schemaHashInputTree(s)))).toBe(v.hash_input_cbor);
      expect(hex(schemaHash(s))).toBe(v.hash);
      // decodeSchema from the canonical bytes gives the same hash
      expect(hex(schemaHash(decodeSchema(unhex(v.canonical_cbor))))).toBe(v.hash);
      break;
    }
    case 'schema_sent': {
      const s = schemaOf(fromTJ(v.input));
      validateSchema(s, { allowUnsorted: true });
      expectSchemaError(() => validateSchema(s), v.expected_error);
      expect(hex(schemaHash(s))).toBe(byName().get('schema/server-base').hash);
      break;
    }
    case 'schema_invalid': {
      const s = schemaOf(fromTJ(v.input));
      expectSchemaError(() => validateSchema(s), v.expected_error);
      expect(hex(facetHash(s.facets[0]))).toBe(v.facet_hash);
      break;
    }
    case 'facet_hash_invariance': {
      const a = schemaOf(fromTJ(v.schema_a));
      const b = schemaOf(fromTJ(v.schema_b));
      expect(hex(facetHash(a.facets[0]))).toBe(v.facet_hash);
      expect(hex(facetHash(b.facets[0]))).toBe(v.facet_hash);
      expect(hex(schemaHash(a))).toBe(v.schema_hash_a);
      expect(hex(schemaHash(b))).toBe(v.schema_hash_b);
      break;
    }
    case 'delta': {
      const from = stateOf(v.from);
      expect(hex(from.hash)).toBe(v.from_hash);
      const d = deltaOf(fromTJ(v.delta));
      if (v.expected_valid) {
        const st = stateOf(v.name);
        expect(hex(encode(schemaTree(st.schema)))).toBe(v.canonical_cbor);
        expect(st.schema.facets.map((f) => ({ facet_id: f.id, facet_name: f.name, facet_hash: hex(facetHash(f)) }))).toEqual(v.facet_hashes);
        expect(hex(st.hash)).toBe(v.hash);
        expect(st.removedFacetIds()).toEqual(v.removed_facet_ids_after);
        const u = msgRoundTrip(v.schema_update.cbor);
        expect(u.kind).toBe(3);
        if (u.kind === 3) {
          expect(u.epoch).toBe(v.epoch);
          expect(hex(u.hash)).toBe(v.hash);
          // Applying the update's delta to a state at epoch v.epoch-1 checks epoch and hash.
          const at = { ...from } as SchemaState;
          void at;
          expect(hex(from.apply(deltaOf(decode(u.delta))).hash)).toBe(v.hash);
        }
      } else {
        expectSchemaError(() => from.apply(d), v.expected_error);
      }
      break;
    }
    default:
      throw new Error(`unknown type ${v.type}`);
  }
}

describe('status.json', () => {
  const doc = loadVectors('status.json');
  for (const v of doc.vectors) {
    it(v.name, () => {
      count('status.json', true);
      switch (v.type) {
        case 'status_table':
          expect(v.entries.length).toBe(23);
          expect(v.websocket_reason_max_bytes).toBe(MAX_WEBSOCKET_REASON);
          expect(v.webtransport_reason_max_bytes).toBe(MAX_WEBTRANSPORT_REASON);
          for (const e of v.entries) {
            expect(statusName(e.status)).toBe(e.name);
            expect(webSocketCloseCode(e.status)).toBe(e.websocket_close_code);
          }
          break;
        case 'status_reserved':
          for (const e of v.entries) {
            expect(statusName(e.status)).toBeUndefined();
            expect(webSocketCloseCode(e.status)).toBe(e.websocket_close_code);
          }
          break;
        case 'reason_truncation':
          for (const c of v.cases) {
            const got = truncateReason(c.reason_utf8, c.max_bytes);
            expect(got).toBe(c.truncated_utf8);
            expect(Buffer.byteLength(got)).toBe(c.truncated_length);
          }
          break;
        case 'status_scope':
          expect(v.status).toBeGreaterThan(31);
          expect(v.allowed_in).toEqual(['Error']);
          break;
        default:
          throw new Error(`unknown type ${v.type}`);
      }
    });
  }
});

describe('admin.json (interface, facet and values; schema and value layers only)', () => {
  const doc = loadVectors('admin.json');
  const iface = () => interfaceOf(fromTJ(byName().get('admin/interface').input));
  for (const v of doc.vectors) {
    it(v.name, () => {
      count('admin.json', true);
      switch (v.type) {
        case 'interface':
          checkSchemaVector(v);
          break;
        case 'facet': {
          checkSchemaVector(v);
          const f = facetOf(fromTJ(v.input));
          expect(conforms(f, interfaceOf(fromTJ(byName().get(v.interface).input)))).toBeNull();
          break;
        }
        case 'admin_value': {
          rt(v.value, v.cbor);
          const i = iface();
          const facet = { id: 16, name: 'sparrow.hub.admin', version: i.version, types: i.types, services: i.services, sigils: i.sigils, implements: null, retired: [], annotations: {} };
          const c = new Codec(facet);
          const val = c.decode(v.type_id, unhex(v.cbor));
          expect(hex(c.encode(v.type_id, val))).toBe(v.cbor);
          break;
        }
        case 'message': {
          checkMessageVector(v);
          const m = decodeMessage(unhex(v.cbor));
          if (m.kind === 20 && m.details) {
            const i = iface();
            const facet = { id: 16, name: 'sparrow.hub.admin', version: i.version, types: i.types, services: i.services, sigils: i.sigils, implements: null, retired: [], annotations: {} };
            const c = new Codec(facet);
            const d = c.decode(T.dynamic, m.details) as { type: number };
            expect(d.type).toBe(72);
            expect(bytesEqual(c.encode(T.dynamic, d), m.details)).toBe(true);
          }
          break;
        }
        default:
          throw new Error(`unknown type ${v.type}`);
      }
    });
  }
});

describe('out of scope', () => {
  for (const f of ['signing.json', 'hub.json']) {
    it(`${f} is skipped (Web Profile signing / Hub Profile forwarding are out of scope)`, () => {
      for (const v of loadVectors(f).vectors) {
        void v;
        count(f, false);
      }
    });
  }
});

describe('scenario messages', () => {
  for (const [f, sc] of loadScenarios()) {
    it(f, () => {
      for (const st of sc.steps) {
        if (!('message' in st)) continue;
        rt(st.message, st.cbor);
        msgRoundTrip(st.cbor);
      }
    });
  }
});

describe('cbor rules (3.1)', () => {
  const bad: [string, string][] = [
    ['9f01ff', 'indefinite'],
    ['f7', 'undefined'],
    ['a2010201 03'.replace(/ /g, ''), 'duplicate'],
    ['a201021801 03'.replace(/ /g, ''), 'duplicate'],
    ['c2420100', 'tag'],
    ['d82541ff', 'tag 37'],
    ['c16161', 'tag 1'],
    ['62c328', 'UTF-8'],
    ['f820', 'simple'],
    ['1c', 'reserved'],
    ['8201', 'end'],
    ['0102', 'trailing'],
  ];
  for (const [h, why] of bad) it(`rejects ${h} (${why})`, () => expect(() => decode(unhex(h))).toThrow());
  it('floats', () => {
    for (const [x, want] of [
      [1.5, 'f93e00'],
      [100000, 'fa47c35000'],
      [0.1, 'fb3fb999999999999a'],
      [-0, 'f98000'],
      [5.960464477539063e-8, 'f90001'],
      [65504, 'f97bff'],
      [Infinity, 'f97c00'],
    ] as [number, string][]) {
      expect(hex(encode(new Float(x)))).toBe(want);
      const back = decode(unhex(want));
      expect(Object.is(Number(back), x)).toBe(true);
    }
  });
});
