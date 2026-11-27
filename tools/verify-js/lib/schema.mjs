// Independent implementation of the schema canonical form, hash and delta
// application (sections 6.2-6.6), working on tjson trees.

import { createHash } from 'node:crypto';
import { encTJ, concat } from './cbor.mjs';

const clone = (x) => JSON.parse(JSON.stringify(x));
const byNum = (f) => (a, b) => f(a) - f(b);

export function canonical(doc) {
  const c = clone(doc);
  c[3].sort(byNum((t) => t[1]));
  for (const t of c[3]) {
    if (t[0] === 0 || t[0] === 2) t[3].sort(byNum((f) => f[0])); // fields / variants by tag
    if (t[0] === 1) t[3].sort((a, b) => a - b); // enum values by sigil
  }
  c[4].sort(byNum((s) => s[0]));
  for (const s of c[4]) {
    s[2].sort(byNum((m) => m[0]));
    for (const m of s[2]) m[4].sort((a, b) => a - b);
  }
  c[5].sort(byNum((s) => s[0]));
  return c;
}

export const canonicalBytes = (doc) => encTJ(canonical(doc));

export function schemaHash(doc) {
  const sha = createHash('sha256').update(canonicalBytes(doc)).digest();
  return concat([0x01], sha);
}

export class DeltaError extends Error {
  constructor(code, detail) {
    super(`${code}: ${detail}`);
    this.code = code;
  }
}

const SPACES = ['types', 'methods', 'sigils', 'services'];

export class SchemaState {
  constructor(doc, retired) {
    this.doc = canonical(doc);
    this.retired = retired ? retired.map((s) => new Set(s)) : [new Set(), new Set(), new Set(), new Set()];
  }

  retiredJSON() {
    return Object.fromEntries(SPACES.map((n, i) => [n, [...this.retired[i]].sort((a, b) => a - b)]));
  }

  apply(delta) {
    const n = new SchemaState(this.doc, this.retired);
    const doc = n.doc;
    for (const op of delta) {
      switch (op[0]) {
        case 0: {
          const td = clone(op[1]);
          if (n.retired[0].has(td[1])) throw new DeltaError('retired_id_reused', `type ${td[1]}`);
          const i = doc[3].findIndex((t) => t[1] === td[1]);
          if (i >= 0) doc[3][i] = td; else doc[3].push(td);
          break;
        }
        case 1: {
          const sd = clone(op[1]);
          if (n.retired[3].has(sd[0])) throw new DeltaError('retired_id_reused', `service ${sd[0]}`);
          for (const m of sd[2]) if (n.retired[1].has(m[0])) throw new DeltaError('retired_id_reused', `method ${m[0]}`);
          const i = doc[4].findIndex((s) => s[0] === sd[0]);
          if (i >= 0) {
            checkServiceReplace(doc[4][i], sd);
            doc[4][i] = sd;
          } else doc[4].push(sd);
          break;
        }
        case 2: {
          const sg = clone(op[1]);
          if (n.retired[2].has(sg[0])) throw new DeltaError('retired_id_reused', `sigil ${sg[0]}`);
          if (doc[5].some((s) => s[0] === sg[0])) throw new DeltaError('duplicate_id', `sigil ${sg[0]}`);
          doc[5].push(sg);
          break;
        }
        case 3:
          n.retire(op[1], op[2]);
          break;
        case 4:
          doc[6] = clone(op[1]);
          break;
        case 5:
          doc[2] = op[1];
          break;
        default:
          throw new DeltaError('unknown_delta_op', String(op[0]));
      }
    }
    n.doc = canonical(doc);
    validate(n.doc);
    return n;
  }

  retire(space, id) {
    const doc = this.doc;
    const drop = (arr, pos) => {
      const i = arr.findIndex((x) => x[pos] === id);
      if (i < 0) throw new DeltaError('unknown_id_retired', `${SPACES[space]} ${id}`);
      return arr.splice(i, 1)[0];
    };
    if (space === 0) drop(doc[3], 1);
    else if (space === 1) {
      const svc = doc[4].find((s) => s[2].some((m) => m[0] === id));
      if (!svc) throw new DeltaError('unknown_id_retired', `method ${id}`);
      drop(svc[2], 0);
    } else if (space === 2) drop(doc[5], 0);
    else if (space === 3) {
      const s = drop(doc[4], 0);
      for (const m of s[2]) this.retired[1].add(m[0]);
    } else throw new DeltaError('unknown_id_space', String(space));
    this.retired[space].add(id);
  }
}

function checkServiceReplace(old, nw) {
  const fixed = 0x2 | 0x8 | 0x10;
  for (const om of old[2]) {
    const nm = nw[2].find((m) => m[0] === om[0]);
    if (!nm) throw new DeltaError('method_dropped_without_retire', `method ${om[0]}`);
    if (JSON.stringify(om[2]) !== JSON.stringify(nm[2]) || JSON.stringify(om[3]) !== JSON.stringify(nm[3]) ||
        (om[5] & fixed) !== (nm[5] & fixed)) {
      throw new DeltaError('incompatible_method_change', `method ${om[0]}`);
    }
  }
}

const LAST_BUILTIN = 11;

export function validate(doc) {
  const types = new Map();
  for (const t of doc[3]) {
    if (t[1] < 64) throw new DeltaError('reserved_id', `type ${t[1]}`);
    if (types.has(t[1])) throw new DeltaError('duplicate_id', `type ${t[1]}`);
    types.set(t[1], t);
  }
  const sigils = new Map();
  for (const s of doc[5]) {
    if (s[0] < 64) throw new DeltaError('reserved_id', `sigil ${s[0]}`);
    if (sigils.has(s[0])) throw new DeltaError('duplicate_id', `sigil ${s[0]}`);
    sigils.set(s[0], s[2]);
  }
  const ref = (r, where, top) => {
    if (typeof r === 'number') {
      if (r <= LAST_BUILTIN || types.has(r)) return;
      throw new DeltaError('dangling_reference', `${where} -> type ${r}`);
    }
    switch (r[0]) {
      case 0: case 2: return ref(r[1], where, false);
      case 1: ref(r[1], where, false); return ref(r[2], where, false);
      case 3:
        if (!top) throw new DeltaError('stream_type_misplaced', where);
        return ref(r[1], where, false);
      case 4: return;
      default: throw new DeltaError('bad_type_ref', where);
    }
  };
  for (const t of doc[3]) {
    const where = `type ${t[1]}`;
    if (t[0] === 0) t[3].forEach((f) => ref(f[2], where, false));
    else if (t[0] === 1) {
      for (const v of t[3]) if (sigils.get(v) !== 0) throw new DeltaError('dangling_reference', `${where} -> sigil ${v}`);
    } else if (t[0] === 2) t[3].forEach((v) => ref(v[2], where, false));
    else if (t[0] === 3) ref(t[3], where, false);
  }
  const services = new Set();
  const methods = new Set();
  for (const s of doc[4]) {
    if (s[0] < 64) throw new DeltaError('reserved_id', `service ${s[0]}`);
    if (services.has(s[0])) throw new DeltaError('duplicate_id', `service ${s[0]}`);
    services.add(s[0]);
    for (const m of s[2]) {
      const where = `method ${m[0]}`;
      if (m[0] < 32) throw new DeltaError('reserved_id', where);
      if (methods.has(m[0])) throw new DeltaError('duplicate_id', where);
      methods.add(m[0]);
      ref(m[2], where, true);
      ref(m[3], where, true);
      for (const e of m[4]) {
        if (e < 32) continue;
        if (sigils.get(e) !== 1) throw new DeltaError('dangling_reference', `${where} -> error ${e}`);
      }
      if (needsEnd(m[2], types) && !(m[5] & 0x8)) throw new DeltaError('missing_end_flag', `${where} input`);
      if (needsEnd(m[3], types) && !(m[5] & 0x10)) throw new DeltaError('missing_end_flag', `${where} output`);
    }
  }
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
  if (t[0] === 0 || t[0] === 2) return t[3].some((f) => hasByteStream(f[2], types, seen));
  if (t[0] === 3) return hasByteStream(t[3], types, seen);
  return false;
}
