// CBOR helpers on top of cbor2, plus conversion between the vectors'
// typed JSON ("tjson", see test-vectors/README.md) and cbor2 values.
//
// Encoding: cbor2 with the RFC 8949 section 4.2.1 key sort
// (sortCoreDeterministic). We deliberately do NOT use cdeEncodeOptions as a
// whole, because it sets ignoreOriginalEncoding, which turns floats with
// integral values (1.0) into integers (0x01). A float in tjson is wrapped
// with encodedNumber(x, 'f') so cbor2 writes the shortest exact float width.

import { encode, decode, cdeEncodeOptions, cdeDecodeOptions, encodedNumber, getEncoded, Tag } from 'cbor2';

export const ENCODE_OPTS = { sortKeys: cdeEncodeOptions.sortKeys };

const passTag = (t) => t;
const DECODE_OPTS = {
  boxed: true,
  rejectDuplicateKeys: true,
  rejectUndefined: true,
  // Keep tags 1 and 37 as Tag objects instead of Date etc.
  tags: new Map([[1, passTag], [37, passTag]]),
};

export const hex = (u8) => Buffer.from(u8).toString('hex');
export const unhex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
export const concat = (...parts) => new Uint8Array(Buffer.concat(parts.map((p) => Buffer.from(p))));

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

/** tjson -> value ready for cbor2.encode */
export function fromTJ(t) {
  if (t === null || typeof t === 'boolean' || typeof t === 'string') return t;
  if (typeof t === 'number') {
    if (!Number.isInteger(t)) throw new Error(`tjson: bare non-integer number ${t}`);
    return t;
  }
  if (Array.isArray(t)) return t.map(fromTJ);
  if ('$int' in t) return BigInt(t.$int);
  if ('$float' in t) return encodedNumber(Number(t.$float), 'f');
  if ('$bytes' in t) return unhex(t.$bytes);
  if ('$tag' in t) return new Tag(t.$tag, fromTJ(t.value));
  if ('$map' in t) return new Map(t.$map.map(([k, v]) => [fromTJ(k), fromTJ(v)]));
  return new Map(Object.entries(t).map(([k, v]) => [k, fromTJ(v)]));
}

export const enc = (v) => encode(v, ENCODE_OPTS);
export const encTJ = (t) => enc(fromTJ(t));

/** Decode bytes, then convert to tjson. */
export function decodeTJ(bytes) {
  return toTJ(decode(bytes, DECODE_OPTS));
}

/** Throws unless the bytes are valid Core Deterministic Encoding. */
export function decodeCDE(bytes) {
  return decode(bytes, { ...cdeDecodeOptions, tags: DECODE_OPTS.tags });
}

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

function intTJ(b) {
  const big = BigInt(b);
  return big > MAX_SAFE || big < -MAX_SAFE ? { $int: big.toString() } : Number(big);
}

export function toTJ(x) {
  if (x === null) return null;
  if (x === undefined) throw new Error('undefined in decoded value');
  if (typeof x === 'boolean') return x;
  if (x instanceof Boolean) return x.valueOf();
  if (typeof x === 'string') return x;
  if (x instanceof String) return x.valueOf();
  if (typeof x === 'bigint' || x instanceof BigInt) return intTJ(x.valueOf());
  if (typeof x === 'number' || x instanceof Number) {
    const e = getEncoded(x);
    const n = x.valueOf();
    if (e ? e[0] >> 5 === 7 : !Number.isInteger(n)) return { $float: fmtFloat(n) };
    return intTJ(n);
  }
  if (x instanceof Uint8Array) return { $bytes: hex(x) };
  if (x instanceof Tag) return { $tag: Number(x.tag), value: toTJ(x.contents) };
  if (Array.isArray(x)) return Array.from(x, toTJ);
  if (x instanceof Map) {
    const entries = [...x.entries()].map(([k, v]) => [toTJ(k), toTJ(v)]);
    const allText = entries.every(([k]) => typeof k === 'string' && !k.startsWith('$'));
    entries.sort((a, b) => Buffer.compare(Buffer.from(encTJ(a[0])), Buffer.from(encTJ(b[0]))));
    if (allText) return Object.fromEntries(entries);
    return { $map: entries };
  }
  throw new Error(`toTJ: unsupported ${Object.prototype.toString.call(x)}`);
}

export function fmtFloat(n) {
  if (Number.isNaN(n)) return 'NaN';
  if (n === Infinity) return 'Infinity';
  if (n === -Infinity) return '-Infinity';
  if (Object.is(n, -0)) return '-0';
  return String(n);
}

/** Structural equality on tjson; floats compared by value (NaN == NaN). */
export function eqTJ(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => eqTJ(x, b[i]));
  }
  if (!isObj(a)) return false;
  if ('$float' in a || '$float' in b) {
    if (!('$float' in a && '$float' in b)) return false;
    return Object.is(Number(a.$float), Number(b.$float));
  }
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && eqTJ(a[k], b[k]));
}

export const u8eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));

// QUIC variable-length integers (RFC 9000, section 16).
export function varintEncode(v) {
  const n = BigInt(v);
  if (n < 64n) return Uint8Array.of(Number(n));
  if (n < 16384n) return Uint8Array.of(0x40 | Number(n >> 8n), Number(n & 0xffn));
  const len = n < 1n << 30n ? 4 : n < 1n << 62n ? 8 : 0;
  if (!len) throw new Error('varint too large');
  const out = new Uint8Array(len);
  let x = n;
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  out[0] |= len === 4 ? 0x80 : 0xc0;
  return out;
}

export function varintDecode(u8) {
  const len = 1 << (u8[0] >> 6);
  let v = BigInt(u8[0] & 0x3f);
  for (let i = 1; i < len; i++) v = (v << 8n) | BigInt(u8[i]);
  return { value: v, length: len };
}

/** Convert tjson to a plain JS tree that is easy to manipulate (schemas). */
export function plain(t) {
  if (t === null || typeof t !== 'object') return t;
  if (Array.isArray(t)) return t.map(plain);
  if ('$int' in t) return BigInt(t.$int);
  return t; // $float, $bytes, $tag, $map and text maps stay as tjson
}
