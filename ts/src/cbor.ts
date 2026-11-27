// A small CBOR codec for the subset Sparrow uses (spec section 3).
//
// Encoding always uses preferred serialization and sorts map keys by the
// bytewise order of their encoded form, so every encoding is also Core
// Deterministic Encoding (3.2). Decoding validates the rules of 3.1:
// definite lengths, valid UTF-8, unique map keys, only tags 1 and 37 (tag 1
// holding an integer or float, tag 37 holding 16 bytes), simple values
// false/true/null only, and at most 64 levels of nesting (arrays, maps and
// tags count; the outermost item is level 1; scalars add no level).
// Receivers accept integers and lengths that are not in shortest form.
//
// Generic JS representation of a CBOR data item:
//
//   unsigned/negative integer   number when |n| <= 2^53-1, otherwise bigint (encoders
//                               write a number outside the safe range as a float)
//   float                       number; a float with an integral value (or -0)
//                               decodes as a Float, so it re-encodes as a float
//   byte string                 Uint8Array
//   text string                 string
//   array                       Array
//   map                         Map (encoders also take plain objects, keyed by text)
//   tag                         Tag
//   false, true, null           false, true, null
//
// Raw wraps an already encoded data item; encoders copy its bytes.

/** CBOR tag numbers Sparrow uses (3.5). */
export const TAG_EPOCH_TIME = 1;
export const TAG_UUID = 37;
export const TAG_SELF_DESCRIBED = 55799;

/** The nesting limit of section 3.1. */
export const MAX_DEPTH = 64;

/** A tagged data item. */
export class Tag {
  constructor(
    readonly tag: number,
    readonly value: unknown,
  ) {}
}

/** A float, encoded as a float even when its value is integral. */
export class Float {
  constructor(readonly value: number) {}
  valueOf(): number {
    return this.value;
  }
}

/** An encoded CBOR data item, copied verbatim by the encoder. */
export class Raw {
  constructor(readonly bytes: Uint8Array) {}
}

/** A malformed or disallowed CBOR item. */
export class CborError extends Error {
  constructor(
    message: string,
    readonly offset = -1,
  ) {
    super(offset >= 0 ? `cbor: ${message} at offset ${offset}` : `cbor: ${message}`);
    this.name = 'CborError';
  }
}

export const MAJOR_UINT = 0;
export const MAJOR_NEG = 1;
export const MAJOR_BYTES = 2;
export const MAJOR_TEXT = 3;
export const MAJOR_ARRAY = 4;
export const MAJOR_MAP = 5;
export const MAJOR_TAG = 6;
export const MAJOR_SIMPLE = 7;

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const U64_MAX = (1n << 64n) - 1n;
const utf8enc = new TextEncoder();
const utf8dec = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Encodes a string as UTF-8. */
export function utf8(s: string): Uint8Array {
  return utf8enc.encode(s);
}

/** Decodes UTF-8, throwing on invalid input. */
export function fromUtf8(b: Uint8Array): string {
  return utf8dec.decode(b);
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/** A growable byte buffer with CBOR primitives. */
export class Writer {
  private buf: Uint8Array;
  private view: DataView;
  length = 0;

  constructor(initial = 64) {
    this.buf = new Uint8Array(initial);
    this.view = new DataView(this.buf.buffer);
  }

  private reserve(n: number): void {
    if (this.length + n <= this.buf.length) return;
    let size = this.buf.length * 2;
    while (size < this.length + n) size *= 2;
    const nb = new Uint8Array(size);
    nb.set(this.buf.subarray(0, this.length));
    this.buf = nb;
    this.view = new DataView(nb.buffer);
  }

  byte(b: number): void {
    this.reserve(1);
    this.buf[this.length++] = b;
  }

  bytes(b: Uint8Array): void {
    this.reserve(b.length);
    this.buf.set(b, this.length);
    this.length += b.length;
  }

  /** Writes an item head in its shortest form. */
  head(major: number, arg: number | bigint): void {
    const m = major << 5;
    if (typeof arg === 'bigint') {
      if (arg < 0n || arg > U64_MAX) throw new CborError(`argument ${arg} out of range`);
      if (arg < 0x100000000n) {
        this.head(major, Number(arg));
        return;
      }
      this.reserve(9);
      this.buf[this.length] = m | 27;
      this.view.setBigUint64(this.length + 1, arg);
      this.length += 9;
      return;
    }
    if (!Number.isInteger(arg) || arg < 0) throw new CborError(`argument ${arg} is not a uint`);
    if (arg < 24) {
      this.byte(m | arg);
    } else if (arg < 0x100) {
      this.reserve(2);
      this.buf[this.length] = m | 24;
      this.buf[this.length + 1] = arg;
      this.length += 2;
    } else if (arg < 0x10000) {
      this.reserve(3);
      this.buf[this.length] = m | 25;
      this.view.setUint16(this.length + 1, arg);
      this.length += 3;
    } else if (arg < 0x100000000) {
      this.reserve(5);
      this.buf[this.length] = m | 26;
      this.view.setUint32(this.length + 1, arg);
      this.length += 5;
    } else {
      this.reserve(9);
      this.buf[this.length] = m | 27;
      this.view.setBigUint64(this.length + 1, BigInt(arg));
      this.length += 9;
    }
  }

  uint(n: number | bigint): void {
    this.head(MAJOR_UINT, n);
  }

  int(n: number | bigint): void {
    if (typeof n === 'number') {
      if (!Number.isSafeInteger(n)) {
        if (!Number.isInteger(n)) throw new CborError(`${n} is not an integer`);
        this.int(BigInt(n));
        return;
      }
      if (n >= 0) this.head(MAJOR_UINT, n);
      else this.head(MAJOR_NEG, -1 - n);
      return;
    }
    if (n >= 0n) this.head(MAJOR_UINT, n);
    else this.head(MAJOR_NEG, -1n - n);
  }

  text(s: string): void {
    // Most strings are short and ASCII; encodeInto avoids an extra copy.
    const max = s.length * 3;
    if (max < 24) {
      this.reserve(1 + max);
      const r = utf8enc.encodeInto(s, this.buf.subarray(this.length + 1));
      this.buf[this.length] = (MAJOR_TEXT << 5) | r.written;
      this.length += 1 + r.written;
      return;
    }
    const b = utf8enc.encode(s);
    this.head(MAJOR_TEXT, b.length);
    this.bytes(b);
  }

  byteString(b: Uint8Array): void {
    this.head(MAJOR_BYTES, b.length);
    this.bytes(b);
  }

  arrayHead(n: number): void {
    this.head(MAJOR_ARRAY, n);
  }

  mapHead(n: number): void {
    this.head(MAJOR_MAP, n);
  }

  tag(t: number): void {
    this.head(MAJOR_TAG, t);
  }

  null(): void {
    this.byte(0xf6);
  }

  bool(b: boolean): void {
    this.byte(b ? 0xf5 : 0xf4);
  }

  /** Writes a float in the shortest width that keeps it exact. */
  float(x: number): void {
    if (Number.isNaN(x)) {
      this.reserve(3);
      this.buf[this.length] = 0xf9;
      this.buf[this.length + 1] = 0x7e;
      this.buf[this.length + 2] = 0x00;
      this.length += 3;
      return;
    }
    const h = toHalf(x);
    if (h >= 0) {
      this.reserve(3);
      this.buf[this.length] = 0xf9;
      this.view.setUint16(this.length + 1, h);
      this.length += 3;
      return;
    }
    if (Math.fround(x) === x) {
      this.reserve(5);
      this.buf[this.length] = 0xfa;
      this.view.setFloat32(this.length + 1, x);
      this.length += 5;
      return;
    }
    this.reserve(9);
    this.buf[this.length] = 0xfb;
    this.view.setFloat64(this.length + 1, x);
    this.length += 9;
  }

  /** Encodes any value of the generic representation. */
  value(v: unknown, depth = 0): void {
    if (depth > 1000) throw new CborError('value nested too deeply to encode');
    switch (typeof v) {
      case 'boolean':
        this.bool(v);
        return;
      case 'string':
        this.text(v);
        return;
      case 'number':
        // Like cbor2: a number beyond the safe integer range is not exact, so it travels as a float.
        if (Number.isSafeInteger(v) && !Object.is(v, -0)) this.int(v);
        else this.float(v);
        return;
      case 'bigint':
        this.int(v);
        return;
      case 'undefined':
        throw new CborError('undefined cannot be encoded (3.1)');
      case 'object':
        break;
      default:
        throw new CborError(`cannot encode a ${typeof v}`);
    }
    if (v === null) {
      this.null();
      return;
    }
    if (v instanceof Uint8Array) {
      this.byteString(v);
      return;
    }
    if (Array.isArray(v)) {
      this.arrayHead(v.length);
      for (const x of v) this.value(x, depth + 1);
      return;
    }
    if (v instanceof Raw) {
      this.bytes(v.bytes);
      return;
    }
    if (v instanceof Float) {
      this.float(v.value);
      return;
    }
    if (v instanceof Tag) {
      this.tag(v.tag);
      this.value(v.value, depth + 1);
      return;
    }
    if (v instanceof Map) {
      this.map(v.entries(), v.size, depth);
      return;
    }
    if (ArrayBuffer.isView(v) || v instanceof ArrayBuffer || v instanceof Date) {
      throw new CborError(`cannot encode a ${Object.prototype.toString.call(v)}; use Uint8Array or the value codec`);
    }
    const entries = Object.entries(v as Record<string, unknown>).filter(([, x]) => x !== undefined);
    this.map(entries, entries.length, depth);
  }

  /** Writes a map with its keys in Core Deterministic order. */
  map(entries: Iterable<[unknown, unknown]>, size: number, depth = 0): void {
    const items: { k: Uint8Array; v: unknown }[] = [];
    for (const [k, x] of entries) items.push({ k: encode(k), v: x });
    if (items.length !== size) throw new CborError('map size changed while encoding');
    items.sort((a, b) => compareBytes(a.k, b.k));
    for (let i = 1; i < items.length; i++) {
      if (compareBytes(items[i - 1].k, items[i].k) === 0) throw new CborError('duplicate map key');
    }
    this.mapHead(items.length);
    for (const it of items) {
      this.bytes(it.k);
      this.value(it.v, depth + 1);
    }
  }

  /** Returns the bytes written so far (a copy). */
  finish(): Uint8Array {
    return this.buf.slice(0, this.length);
  }
}

const f32buf = new Float32Array(1);
const u32buf = new Uint32Array(f32buf.buffer);

/** Returns the half-precision bits of x if x is exactly representable, else -1. */
function toHalf(x: number): number {
  if (Math.fround(x) !== x) return -1;
  f32buf[0] = x;
  const bits = u32buf[0];
  const sign = (bits >>> 16) & 0x8000;
  const exp = (bits >>> 23) & 0xff;
  const mant = bits & 0x7fffff;
  if (exp === 0xff) return mant ? -1 : sign | 0x7c00;
  if (exp === 0) return mant === 0 ? sign : -1;
  const e = exp - 127;
  if (e > 15 || e < -24) return -1;
  if (e >= -14) {
    if (mant & 0x1fff) return -1;
    return sign | ((e + 15) << 10) | (mant >>> 13);
  }
  const full = 0x800000 | mant;
  const s = -(e + 1);
  if (full & ((1 << s) - 1)) return -1;
  return sign | (full >>> s);
}

function fromHalf(h: number): number {
  const sign = h & 0x8000 ? -1 : 1;
  const e = (h >> 10) & 0x1f;
  const m = h & 0x3ff;
  if (e === 0) return sign * m * 2 ** -24;
  if (e === 31) return m ? NaN : sign * Infinity;
  return sign * (1 + m / 1024) * 2 ** (e - 15);
}

/** Compares two byte strings bytewise (shorter first on a common prefix). */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/** Reports whether two byte strings are equal. */
export function bytesEqual(a: Uint8Array | null | undefined, b: Uint8Array | null | undefined): boolean {
  if (!a || !b) return a === b;
  return a.length === b.length && compareBytes(a, b) === 0;
}

/** Encodes a value of the generic representation (Core Deterministic Encoding). */
export function encode(v: unknown): Uint8Array {
  const w = new Writer();
  w.value(v);
  return w.finish();
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/** Options for decoding and validation. */
export interface DecodeOptions {
  /** Deepest nesting level allowed; default 64. */
  maxDepth?: number;
  /** Tags a profile registered beyond 1 and 37. */
  extraTags?: number[];
  /** Reject floats anywhere (canonical data, 3.2). */
  noFloats?: boolean;
  /** Reject integers, lengths and floats not in preferred serialization. */
  requirePreferred?: boolean;
}

interface Head {
  major: number;
  info: number;
  arg: number | bigint;
  size: number;
}

/**
 * A pull reader over one buffer. It assumes nothing about validity; use
 * validate() first when the input is untrusted, as the wire decoder does.
 */
export class Reader {
  off: number;
  private view: DataView;

  constructor(
    readonly buf: Uint8Array,
    off = 0,
  ) {
    this.off = off;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  get done(): boolean {
    return this.off >= this.buf.length;
  }

  /** Reads the head at the current offset without consuming it. */
  peekHead(): Head {
    const b = this.buf;
    const off = this.off;
    if (off >= b.length) throw new CborError('unexpected end of input', off);
    const ib = b[off];
    const major = ib >> 5;
    const info = ib & 0x1f;
    if (info < 24) return { major, info, arg: info, size: 1 };
    const need = (n: number) => {
      if (off + 1 + n > b.length) throw new CborError('unexpected end of input', off);
    };
    switch (info) {
      case 24:
        need(1);
        return { major, info, arg: b[off + 1], size: 2 };
      case 25:
        need(2);
        return { major, info, arg: this.view.getUint16(off + 1), size: 3 };
      case 26:
        need(4);
        return { major, info, arg: this.view.getUint32(off + 1), size: 5 };
      case 27: {
        need(8);
        const big = this.view.getBigUint64(off + 1);
        return { major, info, arg: big <= MAX_SAFE ? Number(big) : big, size: 9 };
      }
      case 31:
        if (major >= 2 && major <= 5) throw new CborError('indefinite length is not allowed (3.1)', off);
        if (major === 7) throw new CborError('break code outside an indefinite item', off);
        throw new CborError('malformed item', off);
      default:
        throw new CborError(`reserved additional information ${info}`, off);
    }
  }

  peekMajor(): number {
    if (this.off >= this.buf.length) throw new CborError('unexpected end of input', this.off);
    return this.buf[this.off] >> 5;
  }

  peekNull(): boolean {
    return this.off < this.buf.length && this.buf[this.off] === 0xf6;
  }

  private headOf(major: number, what: string): Head {
    const h = this.peekHead();
    if (h.major !== major) throw new CborError(`expected ${what}`, this.off);
    this.off += h.size;
    return h;
  }

  /** Reads an unsigned integer. */
  uint(): number | bigint {
    return this.headOf(MAJOR_UINT, 'an unsigned integer').arg;
  }

  /**
   * Reads an unsigned integer of at most 2^53 - 1, the bound of every integer
   * a message defines itself (3.1).
   */
  uintNumber(): number {
    const at = this.off;
    const v = this.uint();
    if (typeof v === 'bigint') throw new CborError(`integer ${v} is beyond 2^53 - 1`, at);
    return v;
  }

  /** Reads any integer. */
  int(): number | bigint {
    const h = this.peekHead();
    if (h.major === MAJOR_UINT) {
      this.off += h.size;
      return h.arg;
    }
    if (h.major === MAJOR_NEG) {
      this.off += h.size;
      if (typeof h.arg === 'bigint' || h.arg >= Number.MAX_SAFE_INTEGER) {
        const n = -1n - BigInt(h.arg);
        return n >= -MAX_SAFE ? Number(n) : n;
      }
      return -1 - h.arg;
    }
    throw new CborError('expected an integer', this.off);
  }

  private len(h: Head): number {
    if (typeof h.arg === 'bigint' || h.arg > this.buf.length - this.off) {
      throw new CborError('length exceeds remaining input', this.off - h.size);
    }
    return h.arg;
  }

  /** Reads a byte string, returning a view into the buffer. */
  bytes(): Uint8Array {
    const h = this.headOf(MAJOR_BYTES, 'a byte string');
    const n = this.len(h);
    const out = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return out;
  }

  text(): string {
    const start = this.off;
    const h = this.headOf(MAJOR_TEXT, 'a text string');
    const n = this.len(h);
    const s = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    try {
      return utf8dec.decode(s);
    } catch {
      throw new CborError('invalid UTF-8 in text string', start);
    }
  }

  arrayHead(): number {
    const h = this.headOf(MAJOR_ARRAY, 'an array');
    if (typeof h.arg === 'bigint' || h.arg > this.buf.length - this.off) {
      throw new CborError('array length exceeds remaining input', this.off - h.size);
    }
    return h.arg;
  }

  mapHead(): number {
    const h = this.headOf(MAJOR_MAP, 'a map');
    if (typeof h.arg === 'bigint' || h.arg > (this.buf.length - this.off) / 2) {
      throw new CborError('map size exceeds remaining input', this.off - h.size);
    }
    return h.arg;
  }

  tag(): number | bigint {
    return this.headOf(MAJOR_TAG, 'a tag').arg;
  }

  bool(): boolean {
    const b = this.buf[this.off];
    if (b === 0xf4 || b === 0xf5) {
      this.off++;
      return b === 0xf5;
    }
    throw new CborError('expected a bool', this.off);
  }

  null(): void {
    if (!this.peekNull()) throw new CborError('expected null', this.off);
    this.off++;
  }

  /** Reads a float (any width) or an integer where a float is declared (3.1). */
  float(): number {
    const b = this.buf[this.off];
    switch (b) {
      case 0xf9:
        this.need(3);
        this.off += 3;
        return fromHalf(this.view.getUint16(this.off - 2));
      case 0xfa:
        this.need(5);
        this.off += 5;
        return this.view.getFloat32(this.off - 4);
      case 0xfb:
        this.need(9);
        this.off += 9;
        return this.view.getFloat64(this.off - 8);
    }
    const major = this.peekMajor();
    if (major === MAJOR_UINT || major === MAJOR_NEG) return Number(this.int());
    throw new CborError('expected a float', this.off);
  }

  private need(n: number): void {
    if (this.off + n > this.buf.length) throw new CborError('unexpected end of input', this.off);
  }

  /** Skips one item (assumed valid) and returns its bytes as a view. */
  raw(): Uint8Array {
    const start = this.off;
    this.skip();
    return this.buf.subarray(start, this.off);
  }

  /** Skips one item; structure is checked, content rules are not. */
  skip(): void {
    let pending = 1;
    while (pending > 0) {
      pending--;
      const h = this.peekHead();
      this.off += h.size;
      switch (h.major) {
        case MAJOR_BYTES:
        case MAJOR_TEXT:
          this.off += this.len(h);
          break;
        case MAJOR_ARRAY:
          pending += this.lenCount(h, 1);
          break;
        case MAJOR_MAP:
          pending += this.lenCount(h, 2);
          break;
        case MAJOR_TAG:
          pending++;
          break;
        case MAJOR_SIMPLE:
          if (h.info === 24) throw new CborError('simple values other than false, true and null are not allowed', this.off - 2);
          break;
      }
      if (this.off > this.buf.length) throw new CborError('unexpected end of input', this.off);
    }
  }

  private lenCount(h: Head, per: number): number {
    if (typeof h.arg === 'bigint' || h.arg * per > this.buf.length - this.off) {
      throw new CborError('length exceeds remaining input', this.off - h.size);
    }
    return h.arg * per;
  }
}

function isPreferred(h: Head): boolean {
  const a = h.arg;
  switch (h.info) {
    case 24:
      return (a as number) >= 24;
    case 25:
      return (a as number) >= 0x100;
    case 26:
      return (a as number) >= 0x10000;
    case 27:
      return typeof a === 'bigint' || a >= 0x100000000;
  }
  return true;
}

const ALLOWED_TAGS = new Set([TAG_EPOCH_TIME, TAG_UUID]);

/** Decodes one item with every 3.1 check; builds the generic value when build is set. */
function item(r: Reader, depth: number, o: DecodeOptions, maxDepth: number, build: boolean): unknown {
  const start = r.off;
  const b = r.buf[start];
  if (b === undefined) throw new CborError('unexpected end of input', start);
  const major = b >> 5;
  if ((major === MAJOR_ARRAY || major === MAJOR_MAP || major === MAJOR_TAG) && depth > maxDepth) {
    throw new CborError(`nesting deeper than ${maxDepth} levels`, start);
  }
  if (major === MAJOR_SIMPLE) {
    const info = b & 0x1f;
    switch (info) {
      case 20:
        r.off++;
        return false;
      case 21:
        r.off++;
        return true;
      case 22:
        r.off++;
        return null;
      case 23:
        throw new CborError('undefined is not allowed (3.1)', start);
      case 25:
      case 26:
      case 27: {
        if (o.noFloats) throw new CborError('float in canonical data (3.2)', start);
        const x = r.float();
        if (o.requirePreferred) {
          const w = new Writer(9);
          w.float(x);
          if (w.length !== r.off - start) throw new CborError('float not in shortest form', start);
        }
        if (!build) return undefined;
        return Number.isInteger(x) || Object.is(x, -0) ? new Float(x) : x;
      }
      default:
        if (info === 31) throw new CborError('break code outside an indefinite item', start);
        if (info >= 28) throw new CborError(`reserved additional information ${info}`, start);
        throw new CborError('simple values other than false, true and null are not allowed (3.1)', start);
    }
  }
  const h = r.peekHead();
  if (o.requirePreferred && !isPreferred(h)) throw new CborError('integer or length not in shortest form', start);
  switch (major) {
    case MAJOR_UINT:
    case MAJOR_NEG:
      return r.int();
    case MAJOR_BYTES: {
      const v = r.bytes();
      return build ? v.slice() : undefined;
    }
    case MAJOR_TEXT:
      return r.text();
    case MAJOR_ARRAY: {
      const n = r.arrayHead();
      if (!build) {
        for (let i = 0; i < n; i++) item(r, depth + 1, o, maxDepth, false);
        return undefined;
      }
      const out = new Array(n);
      for (let i = 0; i < n; i++) out[i] = item(r, depth + 1, o, maxDepth, true);
      return out;
    }
    case MAJOR_MAP: {
      const n = r.mapHead();
      const seen = new Set<string>();
      const out = build ? new Map<unknown, unknown>() : null;
      for (let i = 0; i < n; i++) {
        const koff = r.off;
        const k = item(r, depth + 1, o, maxDepth, true);
        const kb = hexKey(encode(k));
        if (seen.has(kb)) throw new CborError('duplicate map key (3.1)', koff);
        seen.add(kb);
        const v = item(r, depth + 1, o, maxDepth, build);
        if (out) out.set(k, v);
      }
      return out ?? undefined;
    }
    case MAJOR_TAG: {
      const t = r.tag();
      const tn = typeof t === 'bigint' ? -1 : t;
      if (!ALLOWED_TAGS.has(tn) && !(o.extraTags && o.extraTags.includes(tn))) {
        throw new CborError(`tag ${t} is not allowed (3.5)`, start);
      }
      const cstart = r.off;
      if (tn === TAG_EPOCH_TIME) {
        const m = r.peekMajor();
        const fb = r.buf[r.off];
        if (!(m === MAJOR_UINT || m === MAJOR_NEG || fb === 0xf9 || fb === 0xfa || fb === 0xfb)) {
          throw new CborError('tag 1 must hold an integer or a float', cstart);
        }
      } else if (tn === TAG_UUID) {
        if (r.peekMajor() !== MAJOR_BYTES) throw new CborError('tag 37 must hold 16 bytes', cstart);
        const h2 = r.peekHead();
        if (h2.arg !== 16) throw new CborError('tag 37 must hold 16 bytes', cstart);
      }
      const v = item(r, depth + 1, o, maxDepth, build);
      return build ? new Tag(tn, v) : undefined;
    }
  }
  throw new CborError('malformed item', start);
}

function hexKey(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return s;
}

/** Checks that b is exactly one data item following the rules of 3.1. */
export function validate(b: Uint8Array, o: DecodeOptions = {}): void {
  const r = new Reader(b);
  item(r, 1, o, o.maxDepth ?? MAX_DEPTH, false);
  if (!r.done) throw new CborError('trailing bytes after data item', r.off);
}

/** Decodes exactly one data item into the generic representation, validating 3.1. */
export function decode(b: Uint8Array, o: DecodeOptions = {}): unknown {
  const r = new Reader(b);
  const v = item(r, 1, o, o.maxDepth ?? MAX_DEPTH, true);
  if (!r.done) throw new CborError('trailing bytes after data item', r.off);
  return v;
}

/** Decodes the next data item from a reader (validating it), for callers that walk a buffer. */
export function decodeNext(r: Reader, o: DecodeOptions = {}, depth = 1): unknown {
  return item(r, depth, o, o.maxDepth ?? MAX_DEPTH, true);
}

/** Returns the Core Deterministic Encoding of an encoded item. */
export function canonical(b: Uint8Array, o: DecodeOptions = {}): Uint8Array {
  return encode(decode(b, o));
}

/** Reports whether b is valid and already in Core Deterministic Encoding. */
export function isCanonical(b: Uint8Array, o: DecodeOptions = {}): boolean {
  try {
    return bytesEqual(canonical(b, o), b);
  } catch {
    return false;
  }
}

/** Strips a leading self-described CBOR tag (55799), allowed on stored schema files. */
export function stripSelfDescribed(b: Uint8Array): Uint8Array {
  if (b.length >= 3 && b[0] === 0xd9 && b[1] === 0xd9 && b[2] === 0xf7) return b.subarray(3);
  return b;
}

/** Reports whether a generic value contains a float anywhere. */
export function containsFloat(v: unknown): boolean {
  if (v instanceof Float) return true;
  if (typeof v === 'number') return !Number.isSafeInteger(v) || Object.is(v, -0);
  if (Array.isArray(v)) return v.some(containsFloat);
  if (v instanceof Map) {
    for (const [k, x] of v) if (containsFloat(k) || containsFloat(x)) return true;
    return false;
  }
  if (v instanceof Tag) return containsFloat(v.value);
  if (v instanceof Raw) {
    try {
      decode(v.bytes, { noFloats: true, maxDepth: 1 << 10 });
      return false;
    } catch {
      return true;
    }
  }
  if (v && typeof v === 'object' && !(v instanceof Uint8Array)) return Object.values(v).some(containsFloat);
  return false;
}

/** Converts a JS number or bigint to the generic integer form (number when safe). */
export function normInt(n: number | bigint): number | bigint {
  if (typeof n === 'bigint' && n >= -MAX_SAFE && n <= MAX_SAFE) return Number(n);
  return n;
}

/** Hex encoding, lowercase. */
export function toHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

/** Decodes lowercase or uppercase hex. */
export function fromHex(s: string): Uint8Array {
  if (s.length % 2) throw new Error('odd hex length');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const v = parseInt(s.substr(i * 2, 2), 16);
    if (Number.isNaN(v)) throw new Error('bad hex');
    out[i] = v;
  }
  return out;
}

/** Concatenates byte strings. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
