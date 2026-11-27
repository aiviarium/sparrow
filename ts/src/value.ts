// Schema-driven encoding and decoding of payload values (spec 3.4, 6.3).
//
// JS representation of each schema type:
//
//   unit                null
//   bool                boolean
//   int, uint           number when it is a safe integer, otherwise bigint
//                       (encoders take either)
//   float32, float64    number (always encoded as a float; float32 is rounded)
//   string              string
//   bytes               Uint8Array
//   timestamp           Date, to the millisecond: float seconds are rounded to the nearest
//                       millisecond, halves up (Math.round(seconds * 1000)), as Go's
//                       cbor.Time.UnixMilli; NaN, infinities and times outside Date's range
//                       (±8.64e12 s) are refused. Encoders also take a number (or bigint) of
//                       epoch seconds; integer seconds are sent as an integer (core 6.3)
//   uuid                string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (encoders also take 16 bytes)
//   dynamic             { type: TypeId, value }   (encoders also take a type name)
//   symbol              string; a sigil without a kind-2 name decodes as a number
//   enum                the value name (string): the sigil name without the `<enum name>.` prefix
//                       (core 6.5); encoders also take the full sigil name or the sigil number;
//                       an unknown value decodes as its sigil number
//   struct, sparse      an object keyed by field name; absent optional fields are left out
//   union               { variant: name, value }; an unknown variant decodes as
//                       { variant: tag, value: <generic CBOR value> }
//   alias               the target's representation
//   [0, T] list         Array
//   [1, K, V] map       an object when K is string, otherwise a Map
//   [2, T] optional     null (or undefined when encoding) or T's representation
//   [4] inside a value  the byte token (a nonzero number)

import { CborError, MAJOR_TEXT, MAJOR_UINT, Reader, TAG_EPOCH_TIME, TAG_UUID, Writer, decodeNext, validate } from './cbor.js';
import {
  BUILTIN_NAMES,
  MAX_BUILTIN_TYPE,
  SigilKind,
  T,
  isOptional,
  isRemoved,
  isSparse,
  reachesByteStream,
  typeIndex,
  validateFacet,
  type Facet,
  type Field,
  type TypeDef,
  type TypeRef,
} from './schema.js';

/** A value that does not match its type. */
export class ValueError extends Error {
  constructor(
    readonly path: string,
    msg: string,
  ) {
    super(path ? `value: ${path}: ${msg}` : `value: ${msg}`);
    this.name = 'ValueError';
  }
}

/** A dynamic value: [type_id, value]. */
export interface DynamicValue {
  type: number | string;
  value: unknown;
}

/** A union value. */
export interface UnionValue {
  variant: string | number;
  value?: unknown;
}

export const MAX_VALUE_DEPTH = 64;

/** The largest magnitude of a Date's time value, in milliseconds (ECMA-262 21.4.1.1). */
const MAX_DATE_MS = 8.64e15;

const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;
const U64_MAX = (1n << 64n) - 1n;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

function intOf(v: unknown): bigint | null {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number' && Number.isInteger(v)) return BigInt(v);
  return null;
}

function setProp(o: Record<string, unknown>, k: string, v: unknown): void {
  Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
}

/** Formats 16 bytes as a UUID string. */
export function uuidToString(b: Uint8Array): string {
  let h = '';
  for (let i = 0; i < 16; i++) h += b[i].toString(16).padStart(2, '0');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Parses a UUID string (with or without hyphens) into 16 bytes. */
export function uuidFromString(s: string): Uint8Array {
  const h = s.replace(/-/g, '');
  if (!/^[0-9a-fA-F]{32}$/.test(h)) throw new Error(`not a UUID: ${JSON.stringify(s)}`);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

/** Encodes and decodes values of one facet's types. */
export class Codec {
  readonly facet: Facet;
  readonly types: Map<number, TypeDef>;
  private symbols = new Map<string, number>();
  private symbolNames = new Map<number, string>();
  private sigilNames = new Map<number, string>();
  private typeNames = new Map<string, number>();

  /** The facet must be valid (it is validated here). */
  constructor(facet: Facet, opts: { validate?: boolean } = {}) {
    if (opts.validate !== false) validateFacet(facet);
    this.facet = facet;
    this.types = typeIndex(facet.types);
    for (const s of facet.sigils) {
      this.sigilNames.set(s.id, s.name);
      if (s.kind === SigilKind.symbol) {
        this.symbols.set(s.name, s.id);
        this.symbolNames.set(s.id, s.name);
      }
    }
    for (const t of facet.types) this.typeNames.set(t.name, t.id);
  }

  /** Resolves a type name (a named type of the facet or a built-in name) to its TypeId. */
  typeId(name: string | number): number | undefined {
    if (typeof name === 'number') return name;
    const b = BUILTIN_NAMES.indexOf(name as (typeof BUILTIN_NAMES)[number]);
    if (b >= 0) return b;
    return this.typeNames.get(name);
  }

  sigilName(id: number): string | undefined {
    return this.sigilNames.get(id);
  }

  /** The name an enum value is shown as: its sigil name without the `<enum name>.` prefix. */
  private enumValueName(td: { name: string }, s: number): string | undefined {
    const n = this.sigilNames.get(s);
    if (n === undefined) return undefined;
    const prefix = `${td.name}.`;
    return n.length > prefix.length && n.startsWith(prefix) ? n.slice(prefix.length) : n;
  }

  /**
   * Encodes v as type t: a method's whole input or output, or one stream
   * item. A whole-value [4] encodes as null (data travels as token 0).
   */
  encode(t: TypeRef, v: unknown): Uint8Array {
    const w = new Writer(32);
    this.write(w, t, v);
    return w.finish();
  }

  /** Writes v as type t into a writer. */
  write(w: Writer, t: TypeRef, v: unknown): void {
    if (Array.isArray(t) && t[0] === 4) {
      if (v !== null && v !== undefined) throw new ValueError('', 'a whole-value byte stream carries no value; send Bytes with token 0');
      w.null();
      return;
    }
    if (Array.isArray(t) && t[0] === 3) throw new ValueError('', 'a stream is not a value; encode each item with its element type');
    this.enc(w, t, v, '', 0, false);
  }

  /** Decodes b as type t (see encode). Validates b against 3.1 unless trusted. */
  decode(t: TypeRef, b: Uint8Array, opts: { trusted?: boolean } = {}): unknown {
    if (!opts.trusted) {
      try {
        validate(b);
      } catch (e) {
        throw new ValueError('', (e as Error).message);
      }
    }
    const r = new Reader(b);
    let v: unknown;
    try {
      if (Array.isArray(t) && t[0] === 4) {
        r.null();
        return null;
      }
      if (Array.isArray(t) && t[0] === 3) throw new ValueError('', 'a stream is not a value; decode each item with its element type');
      v = this.dec(r, t, '', 0, false);
    } catch (e) {
      if (e instanceof CborError) throw new ValueError('', e.message);
      throw e;
    }
    if (!r.done) throw new ValueError('', 'trailing data');
    return v;
  }

  // -------------------------------------------------------------------------

  private enc(w: Writer, t: TypeRef, v: unknown, path: string, depth: number, inDyn: boolean): void {
    if (depth > MAX_VALUE_DEPTH) throw new ValueError(path, `nested deeper than ${MAX_VALUE_DEPTH} levels`);
    if (typeof t === 'number') {
      this.encNamed(w, t, v, path, depth, inDyn);
      return;
    }
    switch (t[0]) {
      case 0: {
        if (!Array.isArray(v)) throw new ValueError(path, `list needs an array, got ${describe(v)}`);
        w.arrayHead(v.length);
        for (let i = 0; i < v.length; i++) this.enc(w, t[1], v[i], `${path}[${i}]`, depth + 1, inDyn);
        return;
      }
      case 1: {
        let entries: [unknown, unknown][];
        if (v instanceof Map) entries = [...v.entries()];
        else if (v && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Uint8Array)) entries = Object.entries(v);
        else throw new ValueError(path, `map needs a Map or an object, got ${describe(v)}`);
        const enc: { k: Uint8Array; v: Uint8Array }[] = [];
        for (const [k, x] of entries) {
          const kw = new Writer(16);
          this.enc(kw, t[1], k, `${path}.key`, depth + 1, inDyn);
          const vw = new Writer(16);
          this.enc(vw, t[2], x, `${path}[${String(k)}]`, depth + 1, inDyn);
          enc.push({ k: kw.finish(), v: vw.finish() });
        }
        enc.sort((a, b) => cmp(a.k, b.k));
        for (let i = 1; i < enc.length; i++) if (cmp(enc[i - 1].k, enc[i].k) === 0) throw new ValueError(path, 'duplicate map key');
        w.mapHead(enc.length);
        for (const e of enc) {
          w.bytes(e.k);
          w.bytes(e.v);
        }
        return;
      }
      case 2:
        if (v === null || v === undefined) w.null();
        else this.enc(w, t[1], v, path, depth + 1, inDyn);
        return;
      case 3:
        throw new ValueError(path, "[3, T] is only allowed as a method's whole input or output");
      case 4: {
        if (inDyn) throw new ValueError(path, '[4] must not appear inside a dynamic value');
        const tok = intOf(v);
        if (tok === null || tok <= 0n || tok > MAX_SAFE) throw new ValueError(path, `a byte stream inside a value is a nonzero token of at most 2^53 - 1, got ${describe(v)}`);
        w.uint(tok);
        return;
      }
    }
    throw new ValueError(path, 'bad type reference');
  }

  private encNamed(w: Writer, id: number, v: unknown, path: string, depth: number, inDyn: boolean): void {
    switch (id) {
      case T.unit:
        if (v !== null && v !== undefined) throw new ValueError(path, `unit must be null, got ${describe(v)}`);
        w.null();
        return;
      case T.bool:
        if (typeof v !== 'boolean') throw new ValueError(path, `bool needs a boolean, got ${describe(v)}`);
        w.bool(v);
        return;
      case T.int: {
        const n = intOf(v);
        if (n === null || n < I64_MIN || n > I64_MAX) throw new ValueError(path, `int needs a signed 64-bit integer, got ${describe(v)}`);
        w.int(n);
        return;
      }
      case T.uint: {
        const n = intOf(v);
        if (n === null || n < 0n || n > U64_MAX) throw new ValueError(path, `uint needs an unsigned 64-bit integer, got ${describe(v)}`);
        w.uint(n);
        return;
      }
      case T.float32:
      case T.float64: {
        let f: number;
        if (typeof v === 'number') f = v;
        else if (typeof v === 'bigint') f = Number(v);
        else throw new ValueError(path, `float needs a number, got ${describe(v)}`);
        w.float(id === T.float32 ? Math.fround(f) : f);
        return;
      }
      case T.string:
        if (typeof v !== 'string') throw new ValueError(path, `string needs a string, got ${describe(v)}`);
        w.text(v);
        return;
      case T.bytes:
        if (!(v instanceof Uint8Array)) throw new ValueError(path, `bytes needs a Uint8Array, got ${describe(v)}`);
        w.byteString(v);
        return;
      case T.timestamp: {
        // Integer seconds when there is no fraction, else float seconds (core 6.3).
        let s: number | bigint;
        if (v instanceof Date) {
          const ms = v.getTime();
          if (Number.isNaN(ms)) throw new ValueError(path, 'invalid Date');
          s = ms / 1000;
        } else if ((typeof v === 'number' && Number.isFinite(v)) || typeof v === 'bigint') {
          s = v;
        } else throw new ValueError(path, `timestamp needs a Date or epoch seconds, got ${describe(v)}`);
        let n = intOf(s);
        if (n !== null && (n < -MAX_SAFE || n > MAX_SAFE)) {
          // A message holds no integer beyond ±(2^53 - 1) (3.1): as Go's cbor.AppendTime,
          // an integral number beyond it goes as a float.
          if (typeof s === 'bigint') throw new ValueError(path, `timestamp ${s} s is beyond ±(2^53 - 1)`);
          n = null;
        }
        w.tag(TAG_EPOCH_TIME);
        if (n !== null) w.int(typeof s === 'number' && Number.isSafeInteger(s) ? s : n);
        else w.float(s as number);
        return;
      }
      case T.uuid: {
        let b: Uint8Array;
        try {
          b = typeof v === 'string' ? uuidFromString(v) : (v as Uint8Array);
        } catch (e) {
          throw new ValueError(path, (e as Error).message);
        }
        if (!(b instanceof Uint8Array) || b.length !== 16) throw new ValueError(path, `uuid needs a UUID string or 16 bytes, got ${describe(v)}`);
        w.tag(TAG_UUID);
        w.byteString(b);
        return;
      }
      case T.dynamic: {
        if (!v || typeof v !== 'object' || !('type' in v)) throw new ValueError(path, `dynamic needs { type, value }, got ${describe(v)}`);
        const d = v as DynamicValue;
        const tid = this.typeId(d.type);
        if (tid === undefined) throw new ValueError(path, `dynamic type ${String(d.type)} is not defined in facet ${this.facet.name}`);
        this.checkDynamicType(tid, path);
        w.arrayHead(2);
        w.uint(tid);
        this.enc(w, tid, d.value, `${path}.value`, depth + 1, true);
        return;
      }
      case T.symbol:
        if (typeof v === 'string') {
          const s = this.symbols.get(v);
          if (s !== undefined) w.uint(s);
          else w.text(v);
          return;
        }
        if (Number.isSafeInteger(v) && (v as number) >= 0) {
          w.uint(v as number);
          return;
        }
        throw new ValueError(path, `symbol needs a string or a sigil of at most 2^53 - 1, got ${describe(v)}`);
    }
    const td = this.types.get(id);
    if (!td) throw new ValueError(path, `type ${id} is not defined in facet ${this.facet.name}`);
    switch (td.kind) {
      case 'alias':
        this.enc(w, td.target, v, path, depth + 1, inDyn);
        return;
      case 'enum': {
        let s: number | undefined;
        if (typeof v === 'number') s = td.values.includes(v) ? v : undefined;
        else if (typeof v === 'string') {
          s = td.values.find((x) => this.sigilNames.get(x) === v); // the full sigil name
          if (s === undefined) s = td.values.find((x) => this.enumValueName(td, x) === v);
        }
        if (s === undefined) throw new ValueError(path, `${describe(v)} is not a value of enum ${td.name}`);
        w.uint(s);
        return;
      }
      case 'union': {
        if (!v || typeof v !== 'object' || !('variant' in v)) throw new ValueError(path, `union ${td.name} needs { variant, value }, got ${describe(v)}`);
        const u = v as UnionValue;
        const f = td.variants.find((x) => (typeof u.variant === 'number' ? x.tag === u.variant : x.name === u.variant));
        if (!f || isRemoved(f)) throw new ValueError(path, `union ${td.name} has no variant ${String(u.variant)}`);
        w.arrayHead(2);
        w.uint(f.tag);
        this.enc(w, f.type, u.value ?? null, `${path}.${f.name}`, depth + 1, inDyn);
        return;
      }
      case 'struct':
        this.encStruct(w, td.fields, isSparse(td), td.name, v, path, depth, inDyn);
        return;
    }
  }

  private encStruct(w: Writer, fields: Field[], sparse: boolean, name: string, v: unknown, path: string, depth: number, inDyn: boolean): void {
    if (!v || typeof v !== 'object' || Array.isArray(v) || v instanceof Map || v instanceof Uint8Array) {
      throw new ValueError(path, `struct ${name} needs an object, got ${describe(v)}`);
    }
    const o = v as Record<string, unknown>;
    const byName = new Map(fields.map((f) => [f.name, f]));
    for (const k of Object.keys(o)) {
      const f = byName.get(k);
      if (!f) {
        if (o[k] === undefined) continue;
        throw new ValueError(path, `struct ${name} has no field ${JSON.stringify(k)}`);
      }
      if (isRemoved(f) && o[k] !== undefined && o[k] !== null) throw new ValueError(path, `field ${k} of ${name} is removed`);
    }
    const enc = new Map<number, Uint8Array>();
    for (const f of fields) {
      if (isRemoved(f)) continue;
      const x = Object.prototype.hasOwnProperty.call(o, f.name) ? o[f.name] : undefined;
      if (x === undefined || x === null) {
        if (!isOptional(f) && !nullable(f.type)) throw new ValueError(path, `required field ${f.name} of ${name} is missing`);
        continue;
      }
      const fw = new Writer(16);
      this.enc(fw, f.type, x, `${path}.${f.name}`, depth + 1, inDyn);
      enc.set(f.tag, fw.finish());
    }
    const tags = [...enc.keys()].sort((a, b) => a - b);
    if (sparse) {
      w.mapHead(tags.length);
      for (const t of tags) {
        w.uint(t);
        w.bytes(enc.get(t)!);
      }
      return;
    }
    if (tags.length === 0) {
      w.arrayHead(0);
      return;
    }
    const n = tags[tags.length - 1] + 1;
    if (n > 1 << 20) throw new ValueError(path, `field tag ${n - 1} too sparse for a positional struct`);
    w.arrayHead(n);
    for (let t = 0; t < n; t++) {
      const b = enc.get(t);
      if (b) w.bytes(b);
      else w.null();
    }
  }

  private checkDynamicType(id: number, path: string): void {
    if (id <= MAX_BUILTIN_TYPE) return;
    if (!this.types.has(id)) throw new ValueError(path, `dynamic type ${id} is not defined in facet ${this.facet.name}`);
    if (reachesByteStream(id, this.types)) throw new ValueError(path, `dynamic type ${id} reaches [4], which must not appear inside a dynamic value`);
  }

  // -------------------------------------------------------------------------

  private dec(r: Reader, t: TypeRef, path: string, depth: number, inDyn: boolean): unknown {
    if (depth > MAX_VALUE_DEPTH) throw new ValueError(path, `nested deeper than ${MAX_VALUE_DEPTH} levels`);
    if (typeof t === 'number') return this.decNamed(r, t, path, depth, inDyn);
    switch (t[0]) {
      case 0: {
        const n = this.wrap(path, () => r.arrayHead());
        const out = new Array(n);
        for (let i = 0; i < n; i++) out[i] = this.dec(r, t[1], `${path}[${i}]`, depth + 1, inDyn);
        return out;
      }
      case 1: {
        const n = this.wrap(path, () => r.mapHead());
        if (this.isStringType(t[1])) {
          const out: Record<string, unknown> = {};
          for (let i = 0; i < n; i++) {
            const k = this.dec(r, t[1], `${path}.key`, depth + 1, inDyn) as string;
            setProp(out, k, this.dec(r, t[2], `${path}[${k}]`, depth + 1, inDyn));
          }
          return out;
        }
        const out = new Map<unknown, unknown>();
        for (let i = 0; i < n; i++) {
          const k = this.dec(r, t[1], `${path}.key`, depth + 1, inDyn);
          out.set(k, this.dec(r, t[2], `${path}[${String(k)}]`, depth + 1, inDyn));
        }
        return out;
      }
      case 2:
        if (r.peekNull()) {
          r.null();
          return null;
        }
        return this.dec(r, t[1], path, depth + 1, inDyn);
      case 3:
        throw new ValueError(path, "[3, T] is only allowed as a method's whole input or output");
      case 4: {
        if (inDyn) throw new ValueError(path, '[4] must not appear inside a dynamic value');
        const u = this.wrap(path, () => r.uintNumber());
        if (u === 0) throw new ValueError(path, 'a byte stream inside a value is a nonzero token');
        return u;
      }
    }
    throw new ValueError(path, 'bad type reference');
  }

  private isStringType(t: TypeRef): boolean {
    for (let i = 0; i < 64; i++) {
      if (t === T.string) return true;
      if (typeof t !== 'number') return false;
      const td = this.types.get(t);
      if (!td || td.kind !== 'alias') return false;
      t = td.target;
    }
    return false;
  }

  private wrap<X>(path: string, f: () => X): X {
    try {
      return f();
    } catch (e) {
      if (e instanceof CborError) throw new ValueError(path, e.message);
      throw e;
    }
  }

  private decNamed(r: Reader, id: number, path: string, depth: number, inDyn: boolean): unknown {
    switch (id) {
      case T.unit:
        this.wrap(path, () => r.null());
        return null;
      case T.bool:
        return this.wrap(path, () => r.bool());
      case T.int: {
        const n = this.wrap(path, () => r.int());
        if (typeof n === 'bigint' && (n < I64_MIN || n > I64_MAX)) throw new ValueError(path, 'int out of the signed 64-bit range');
        return n;
      }
      case T.uint:
        return this.wrap(path, () => r.uint());
      case T.float32:
      case T.float64:
        return this.wrap(path, () => r.float());
      case T.string:
        return this.wrap(path, () => r.text());
      case T.bytes:
        return this.wrap(path, () => r.bytes()).slice();
      case T.timestamp: {
        const tag = this.wrap(path, () => r.tag());
        if (tag !== TAG_EPOCH_TIME) throw new ValueError(path, 'timestamp needs tag 1');
        const s = this.wrap(path, () => r.float());
        // new Date(s * 1000) would truncate: 1.001 s is 1000.9999999999999 ms.
        const ms = Math.round(s * 1000);
        if (!Number.isFinite(ms) || Math.abs(ms) > MAX_DATE_MS) throw new ValueError(path, `timestamp ${s} is not finite or outside the range of Date`);
        return new Date(ms === 0 ? 0 : ms);
      }
      case T.uuid: {
        const tag = this.wrap(path, () => r.tag());
        if (tag !== TAG_UUID) throw new ValueError(path, 'uuid needs tag 37');
        const b = this.wrap(path, () => r.bytes());
        if (b.length !== 16) throw new ValueError(path, 'uuid needs 16 bytes');
        return uuidToString(b);
      }
      case T.dynamic: {
        const n = this.wrap(path, () => r.arrayHead());
        if (n !== 2) throw new ValueError(path, 'dynamic needs [type_id, value]');
        const tid = this.wrap(path, () => r.uintNumber());
        this.checkDynamicType(tid, path);
        return { type: tid, value: this.dec(r, tid, `${path}.value`, depth + 1, true) };
      }
      case T.symbol: {
        const m = this.wrap(path, () => r.peekMajor());
        if (m === MAJOR_UINT) {
          const s = this.wrap(path, () => r.uintNumber());
          return this.symbolNames.get(s) ?? s;
        }
        if (m === MAJOR_TEXT) return this.wrap(path, () => r.text());
        throw new ValueError(path, 'symbol needs a sigil or a text string');
      }
    }
    const td = this.types.get(id);
    if (!td) throw new ValueError(path, `type ${id} is not defined in facet ${this.facet.name}`);
    switch (td.kind) {
      case 'alias':
        return this.dec(r, td.target, path, depth + 1, inDyn);
      case 'enum': {
        const s = this.wrap(path, () => r.uintNumber());
        if (td.values.includes(s)) return this.enumValueName(td, s) ?? s;
        return s;
      }
      case 'union': {
        const n = this.wrap(path, () => r.arrayHead());
        if (n !== 2) throw new ValueError(path, `union ${td.name} needs [variant_tag, value]`);
        const tag = this.wrap(path, () => r.uintNumber());
        const f = td.variants.find((x) => x.tag === tag);
        if (!f || isRemoved(f)) return { variant: tag, value: decodeNext(r) };
        return { variant: f.name, value: this.dec(r, f.type, `${path}.${f.name}`, depth + 1, inDyn) };
      }
      case 'struct':
        return this.decStruct(r, td.fields, isSparse(td), td.name, path, depth, inDyn);
    }
  }

  private decStruct(r: Reader, fields: Field[], sparse: boolean, name: string, path: string, depth: number, inDyn: boolean): unknown {
    const out: Record<string, unknown> = {};
    const byTag = new Map(fields.map((f) => [f.tag, f]));
    const field = (tag: number) => {
      const f = byTag.get(tag);
      if (!f || isRemoved(f) || r.peekNull()) {
        this.wrap(path, () => r.skip());
        return;
      }
      const x = this.dec(r, f.type, `${path}.${f.name}`, depth + 1, inDyn);
      if (x !== null) setProp(out, f.name, x);
    };
    if (sparse) {
      let n: number;
      try {
        n = r.mapHead();
      } catch (e) {
        throw new ValueError(path, `sparse struct ${name} needs a map: ${(e as Error).message}`);
      }
      for (let i = 0; i < n; i++) {
        field(this.wrap(path, () => r.uintNumber()));
      }
    } else {
      let n: number;
      try {
        n = r.arrayHead();
      } catch (e) {
        throw new ValueError(path, `struct ${name} needs an array: ${(e as Error).message}`);
      }
      for (let i = 0; i < n; i++) field(i);
    }
    for (const f of fields) {
      if (!isRemoved(f) && !isOptional(f) && !nullable(f.type) && !Object.prototype.hasOwnProperty.call(out, f.name)) {
        throw new ValueError(path, `required field ${f.name} of ${name} is missing`);
      }
    }
    return out;
  }
}

function nullable(t: TypeRef): boolean {
  return t === T.unit || (Array.isArray(t) && t[0] === 2);
}

function cmp(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function describe(v: unknown): string {
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';
  if (typeof v === 'bigint') return `${v}n`;
  if (typeof v === 'string') return JSON.stringify(v.length > 40 ? `${v.slice(0, 40)}...` : v);
  if (typeof v !== 'object') return `${typeof v} ${String(v)}`;
  return Object.prototype.toString.call(v).slice(8, -1);
}

