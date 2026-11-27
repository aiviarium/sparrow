// Independent implementation of the part-based schema model (section 6):
// canonical forms, part / interface / schema hashes, wire shapes and
// interface conformance, validation, compatibility and delta application.
// Works on tjson trees.

import { createHash } from 'node:crypto';
import { encTJ, concat, hex } from './cbor.mjs';

const clone = (x) => JSON.parse(JSON.stringify(x));
const byNum = (f) => (a, b) => f(a) - f(b);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// part = [id, name, version, types, services, sigils, implements, retired, annotations]
export const P = { id: 0, name: 1, version: 2, types: 3, services: 4, sigils: 5, implements: 6, retired: 7, ann: 8 };
export const SPACE = { type: 0, service: 1, method: 2, sigil: 3 };
const REMOVED = 0x4;

function canonDefs(types, services, sigils) {
  types.sort(byNum((t) => t[1]));
  for (const t of types) {
    if (t[0] === 0 || t[0] === 2) t[3].sort(byNum((f) => f[0]));
    if (t[0] === 1) t[3].sort((a, b) => a - b);
  }
  services.sort(byNum((s) => s[0]));
  for (const s of services) {
    s[2].sort(byNum((m) => m[0]));
    for (const m of s[2]) m[4].sort((a, b) => a - b);
  }
  sigils.sort(byNum((s) => s[0]));
}

export function canonicalPart(p) {
  const c = clone(p);
  canonDefs(c[P.types], c[P.services], c[P.sigils]);
  c[P.retired].sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  return c;
}

export function canonicalIface(i) {
  const c = clone(i);
  canonDefs(c[2], c[3], c[4]);
  return c;
}

export function canonicalSchema(s) {
  const c = clone(s);
  c[3] = c[3].map(canonicalPart).sort(byNum((p) => p[P.id]));
  return c;
}

const h33 = (bytes) => concat([0x01], createHash('sha256').update(bytes).digest());

export function partHashInput(p) {
  const c = canonicalPart(p);
  c[P.id] = 0;
  c[P.name] = '';
  return c;
}
export const partHash = (p) => h33(encTJ(partHashInput(p)));
export const ifaceHash = (i) => h33(encTJ(canonicalIface(i)));

export function schemaHashInput(s) {
  const c = canonicalSchema(s);
  return [c[0], c[1], c[2], c[3].map((p) => [p[P.id], p[P.name], { $bytes: hex(partHash(p)) }]), c[4]];
}
export const schemaHash = (s) => h33(encTJ(schemaHashInput(s)));

// ---- wire shapes and conformance (6.5) ----

function blankType(td) {
  const c = clone(td);
  c[2] = '';
  c[c.length - 1] = {};
  if (c[0] === 0 || c[0] === 2) {
    for (const f of c[3]) {
      f[1] = '';
      f[4] = {};
      if (c[0] === 0) f[3] &= ~0x2; // hint flag: deprecated
    }
  }
  return c;
}
// A service's wire shape leaves out its method list; methods are compared one by one.
const blankService = (sd) => [sd[0], '', {}];
function blankMethod(md) {
  const c = clone(md);
  c[1] = '';
  c[5] &= ~(0x1 | 0x4); // hint flags: idempotent, shared
  c[6] = {};
  return c;
}
function blankSigil(sg) {
  const c = clone(sg);
  c[1] = '';
  c[3] = {};
  return c;
}
const bytesEq = (a, b) => hex(encTJ(a)) === hex(encTJ(b));

/** First mismatch as [space, id], or null when the part conforms. */
export function conforms(part, iface) {
  const p = canonicalPart(part);
  const i = canonicalIface(iface);
  const groups = [
    [SPACE.type, i[2], p[P.types], 1, blankType],
    [SPACE.service, i[3], p[P.services], 0, blankService],
    [SPACE.sigil, i[4], p[P.sigils], 0, blankSigil],
  ];
  for (const [space, idefs, pdefs, pos, blank] of groups) {
    for (const d of idefs) {
      const m = pdefs.find((x) => x[pos] === d[pos]);
      if (!m || !bytesEq(blank(d), blank(m))) return [space, d[pos]];
      if (space !== SPACE.service) continue;
      for (const im of d[2]) {
        const pm = m[2].find((x) => x[0] === im[0]);
        if (!pm || !bytesEq(blankMethod(im), blankMethod(pm))) return [SPACE.method, im[0]];
      }
    }
  }
  return null;
}

// ---- validation ----

export class DeltaError extends Error {
  constructor(code, detail) {
    super(`${code}: ${detail}`);
    this.code = code;
  }
}

export function containsFloat(t) {
  if (t === null || typeof t !== 'object') return false;
  if (Array.isArray(t)) return t.some(containsFloat);
  if ('$float' in t) return true;
  if ('$map' in t) return t.$map.some(([k, v]) => containsFloat(k) || containsFloat(v));
  if ('$tag' in t) return containsFloat(t.value);
  if ('$bytes' in t || '$int' in t) return false;
  return Object.values(t).some(containsFloat);
}

const LAST_BUILTIN = 11;

const isAscii = (str) => /^[\x00-\x7f]*$/.test(str);
export const NAME = /^([a-z0-9-]+(\.[a-z0-9-]+)*\/)?[a-z0-9-]+(\.[a-z0-9-]+)*$/;

// Names of types, services, methods, fields, variants and sigils are ASCII (6.1).
function checkNames(where, types, services, sigils) {
  const bad = (n) => { throw new DeltaError('invalid_name', `${where}: ${JSON.stringify(n)}`); };
  for (const t of types) {
    if (!isAscii(t[2])) bad(t[2]);
    if (t[0] === 0 || t[0] === 2) for (const f of t[3]) if (!isAscii(f[1])) bad(f[1]);
  }
  for (const s of services) {
    if (!isAscii(s[1])) bad(s[1]);
    for (const m of s[2]) if (!isAscii(m[1])) bad(m[1]);
  }
  for (const s of sigils) if (!isAscii(s[1])) bad(s[1]);
}

// Part 1 as section 9.4 defines it.
export const WEB_PART = [1, 'sparrow.web', '1.0.0', [], [[0, 'Client', [[0, 'moduleRejected', [0, 6], 0, [], 0x2, {}]], {}]], [], null, [], {}];

function validateDefs(where, types, services, sigils, retired) {
  checkNames(where, types, services, sigils);
  const ret = new Set();
  for (const [sp, id] of retired) {
    if (sp < 0 || sp > 3) throw new DeltaError('bad_retired_entry', where);
    ret.add(`${sp}:${id}`);
  }
  const d = { types: new Map(), sigils: new Map(), methods: new Map(), services: new Map() };
  for (const t of types) {
    if (t[1] < 64) throw new DeltaError('reserved_id', `${where} type ${t[1]}`);
    if (d.types.has(t[1])) throw new DeltaError('duplicate_id', `${where} type ${t[1]}`);
    if (ret.has(`0:${t[1]}`)) throw new DeltaError('retired_id_reused', `${where} type ${t[1]}`);
    d.types.set(t[1], t);
  }
  for (const s of sigils) {
    if (s[0] < 64) throw new DeltaError('reserved_id', `${where} sigil ${s[0]}`);
    if (d.sigils.has(s[0])) throw new DeltaError('duplicate_id', `${where} sigil ${s[0]}`);
    if (ret.has(`3:${s[0]}`)) throw new DeltaError('retired_id_reused', `${where} sigil ${s[0]}`);
    d.sigils.set(s[0], s[2]);
  }
  for (const s of services) {
    if (d.services.has(s[0])) throw new DeltaError('duplicate_id', `${where} service ${s[0]}`);
    if (ret.has(`1:${s[0]}`)) throw new DeltaError('retired_id_reused', `${where} service ${s[0]}`);
    d.services.set(s[0], s);
    for (const m of s[2]) {
      if (d.methods.has(m[0])) throw new DeltaError('duplicate_id', `${where} method ${m[0]}`);
      if (ret.has(`2:${m[0]}`)) throw new DeltaError('retired_id_reused', `${where} method ${m[0]}`);
      d.methods.set(m[0], m);
    }
  }
  const ref = (r, at, top) => {
    if (typeof r === 'number') {
      if (r <= LAST_BUILTIN || d.types.has(r)) return;
      throw new DeltaError('dangling_reference', `${at} -> type ${r}`);
    }
    switch (r[0]) {
      case 0: case 2: return ref(r[1], at, false);
      case 1: ref(r[1], at, false); return ref(r[2], at, false);
      case 3:
        if (!top) throw new DeltaError('stream_type_misplaced', at);
        return ref(r[1], at, false);
      case 4: return undefined;
      default: throw new DeltaError('bad_type_ref', at);
    }
  };
  for (const t of types) {
    const at = `${where} type ${t[1]}`;
    if (t[0] === 0 || t[0] === 2) for (const f of t[3]) { if (!(f[3] & REMOVED)) ref(f[2], at, false); }
    else if (t[0] === 1) {
      for (const v of t[3]) if (d.sigils.get(v) !== 0) throw new DeltaError('dangling_reference', `${at} -> sigil ${v}`);
    } else if (t[0] === 3) ref(t[3], at, false);
  }
  for (const m of d.methods.values()) {
    const at = `${where} method ${m[0]}`;
    ref(m[2], at, true);
    ref(m[3], at, true);
    for (const e of m[4]) if (e >= 32 && d.sigils.get(e) !== 1) throw new DeltaError('dangling_reference', `${at} -> error ${e}`);
    if (needsEnd(m[2], d.types) && !(m[5] & 0x8)) throw new DeltaError('missing_end_flag', `${at} input`);
    if (needsEnd(m[3], d.types) && !(m[5] & 0x10)) throw new DeltaError('missing_end_flag', `${at} output`);
  }
  return d;
}

export function validatePart(p) {
  const where = `part ${p[P.id]}`;
  if (containsFloat(p)) throw new DeltaError('float_in_canonical_data', where);
  if (!NAME.test(p[P.name])) throw new DeltaError('invalid_name', `${where}: ${JSON.stringify(p[P.name])}`);
  return validateDefs(where, p[P.types], p[P.services], p[P.sigils], p[P.retired]);
}

export function validateIface(i) {
  if (containsFloat(i)) throw new DeltaError('float_in_canonical_data', 'interface');
  const d = validateDefs('interface', i[2], i[3], i[4], []);
  const seenT = new Set();
  const seenS = new Set();
  const walk = (r) => {
    if (Array.isArray(r)) { r.slice(1).forEach(walk); return; }
    if (seenT.has(r) || !d.types.has(r)) return;
    seenT.add(r);
    const t = d.types.get(r);
    if (t[0] === 0 || t[0] === 2) t[3].forEach((f) => walk(f[2]));
    else if (t[0] === 1) t[3].forEach((v) => seenS.add(v));
    else if (t[0] === 3) walk(t[3]);
  };
  for (const m of d.methods.values()) { walk(m[2]); walk(m[3]); m[4].forEach((e) => seenS.add(e)); }
  for (const t of i[2]) if (!seenT.has(t[1])) throw new DeltaError('interface_not_closed', `type ${t[1]}`);
  for (const s of i[4]) if (!seenS.has(s[0])) throw new DeltaError('interface_not_closed', `sigil ${s[0]}`);
}

export function validateSchema(doc) {
  if (containsFloat(doc)) throw new DeltaError('float_in_canonical_data', 'schema');
  const ids = new Set();
  const names = new Set();
  for (const p of doc[3]) {
    if (ids.has(p[P.id])) throw new DeltaError('duplicate_part_id', String(p[P.id]));
    if (names.has(p[P.name])) throw new DeltaError('duplicate_part_name', p[P.name]);
    ids.add(p[P.id]);
    names.add(p[P.name]);
    if (p[P.id] < 16 && p[P.id] !== 1) throw new DeltaError('reserved_part_id', String(p[P.id]));
    if (p[P.id] === 1 && hex(partHash(p)) !== hex(partHash(WEB_PART))) throw new DeltaError('part1_mismatch', 'part 1');
    validatePart(p);
  }
}

/** A schema document as sent must also list its parts sorted by ID (6.1). */
export function validateSentSchema(doc) {
  for (let i = 1; i < doc[3].length; i++) {
    if (doc[3][i - 1][P.id] >= doc[3][i][P.id]) throw new DeltaError('parts_not_sorted', `part ${doc[3][i][P.id]}`);
  }
  validateSchema(doc);
}

function needsEnd(r, types) {
  if (Array.isArray(r) && r[0] === 3) return true;
  return hasByteStream(r, types, new Set());
}
function hasByteStream(r, types, seen) {
  if (Array.isArray(r)) {
    if (r[0] === 4) return true;
    if (r[0] === 1) return hasByteStream(r[1], types, seen) || hasByteStream(r[2], types, seen);
    return hasByteStream(r[1], types, seen);
  }
  const t = types.get(r);
  if (!t || seen.has(r)) return false;
  seen.add(r);
  if (t[0] === 0 || t[0] === 2) return t[3].some((f) => !(f[3] & REMOVED) && hasByteStream(f[2], types, seen));
  if (t[0] === 3) return hasByteStream(t[3], types, seen);
  return false;
}

// ---- compatibility (6.6 rule 2, 6.7) ----

const major = (v) => v.split('.')[0];

export function compatible(old, nw) {
  const pid = old[P.id];
  if (old[P.name] !== nw[P.name]) throw new DeltaError('part_renamed', `part ${pid}`);
  if (major(old[P.version]) !== major(nw[P.version])) throw new DeltaError('major_version_changed', `part ${pid}`);
  const newRet = new Set(nw[P.retired].map(([s, i]) => `${s}:${i}`));
  for (const [s, i] of old[P.retired]) if (!newRet.has(`${s}:${i}`)) throw new DeltaError('retired_not_carried_over', `[${s}, ${i}]`);
  const od = validatePart(old);
  const nd = validatePart(nw);
  const dropped = (space, id) => {
    if (!newRet.has(`${space}:${id}`)) throw new DeltaError('dropped_id_not_retired', `[${space}, ${id}]`);
  };
  const sortedIds = (m) => [...m.keys()].sort((a, b) => a - b);
  for (const id of sortedIds(od.types)) {
    if (!nd.types.has(id)) dropped(SPACE.type, id);
    else typeCompatible(pid, od.types.get(id), nd.types.get(id));
  }
  for (const id of sortedIds(od.services)) if (!nd.services.has(id)) dropped(SPACE.service, id);
  for (const id of sortedIds(od.methods)) {
    const om = od.methods.get(id);
    const nm = nd.methods.get(id);
    if (!nm) { dropped(SPACE.method, id); continue; }
    const fixed = 0x2 | 0x8 | 0x10;
    if (!same(om[2], nm[2]) || !same(om[3], nm[3]) || (om[5] & fixed) !== (nm[5] & fixed)) {
      throw new DeltaError('incompatible_change', `method ${id}`);
    }
  }
  for (const id of sortedIds(od.sigils)) {
    if (!nd.sigils.has(id)) dropped(SPACE.sigil, id);
    else if (nd.sigils.get(id) !== od.sigils.get(id)) throw new DeltaError('incompatible_change', `sigil ${id} kind`);
  }
}

function typeCompatible(pid, ot, nt) {
  const bad = (what) => { throw new DeltaError('incompatible_change', `part ${pid} type ${ot[1]}: ${what}`); };
  if (ot[0] !== nt[0]) bad('kind');
  if (ot[0] === 0 || ot[0] === 2) {
    const isStruct = ot[0] === 0;
    if (isStruct && (ot[4] & 1) !== (nt[4] & 1)) bad('sparse');
    const newM = new Map(nt[3].map((f) => [f[0], f]));
    const oldTags = new Set();
    for (const of_ of ot[3]) {
      const f0 = of_;
      oldTags.add(f0[0]);
      const nf = newM.get(f0[0]);
      if (!nf) bad(`tag ${f0[0]} disappeared`);
      const oRem = !!(f0[3] & REMOVED);
      const nRem = !!(nf[3] & REMOVED);
      if (oRem && !nRem) bad(`tag ${f0[0]} reused`);
      else if (!oRem && nRem) { if (isStruct && !(f0[3] & 1)) bad(`required field ${f0[0]} removed`); }
      else if (!oRem && !nRem) {
        if (!same(f0[2], nf[2])) bad(`tag ${f0[0]} type`);
        if (isStruct && (f0[3] & 1) && !(nf[3] & 1)) bad(`field ${f0[0]} made required`);
      }
    }
    if (isStruct) for (const [tag, nf] of newM) if (!oldTags.has(tag) && !(nf[3] & (1 | REMOVED))) bad(`new field ${tag} required`);
  } else if (ot[0] === 1) {
    const nv = new Set(nt[3]);
    for (const v of ot[3]) if (!nv.has(v)) bad(`enum value ${v} removed`);
  } else if (ot[0] === 3 && !same(ot[3], nt[3])) bad('alias target');
}

// ---- deltas ----

export class SchemaState {
  constructor(doc, removed) {
    this.doc = canonicalSchema(doc);
    this.removed = new Map(removed ?? []);
  }

  removedIds() { return [...this.removed.keys()].sort((a, b) => a - b); }

  apply(delta) {
    const n = new SchemaState(this.doc, this.removed);
    const doc = n.doc;
    for (const op of delta) {
      switch (op[0]) {
        case 0: {
          const p = canonicalPart(op[1]);
          const i = doc[3].findIndex((x) => x[P.id] === p[P.id]);
          if (i >= 0) {
            compatible(doc[3][i], p);
            doc[3][i] = p;
          } else {
            const last = n.removed.get(p[P.id]);
            if (last) {
              if (last[P.name] !== p[P.name] || major(last[P.version]) !== major(p[P.version])) {
                throw new DeltaError('removed_part_mismatch', `part ${p[P.id]}`);
              }
              compatible(last, p);
              n.removed.delete(p[P.id]);
            }
            doc[3].push(p);
          }
          break;
        }
        case 1: {
          const i = doc[3].findIndex((x) => x[P.id] === op[1]);
          if (i < 0) throw new DeltaError('unknown_part', String(op[1]));
          n.removed.set(op[1], doc[3].splice(i, 1)[0]);
          break;
        }
        case 2: doc[4] = clone(op[1]); break;
        case 3: doc[2] = op[1]; break;
        default: throw new DeltaError('unknown_delta_op', String(op[0]));
      }
    }
    n.doc = canonicalSchema(doc);
    validateSchema(n.doc);
    return n;
  }
}
