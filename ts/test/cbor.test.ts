// The CBOR codec against cbor2 as a differential reference (random values),
// plus decoder robustness on random and truncated input.
import { cdeEncodeOptions, decode as c2decode, encode as c2encode, Tag as C2Tag } from 'cbor2';
import { describe, expect, it } from 'vitest';
import { CborError, Tag, decode, encode, toHex, validate } from '../src/cbor.js';
import { decodeMessage } from '../src/wire.js';
import { sha256, sha256Pure } from '../src/sha256.js';

function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

function gen(r: () => number, depth = 0): unknown {
  const k = Math.floor(r() * (depth > 3 ? 6 : 10));
  switch (k) {
    case 0:
      return Math.floor((r() - 0.5) * 2 ** (r() * 53));
    case 1: {
      const big = BigInt(Math.floor(r() * 2 ** 32)) * 2n ** 32n + BigInt(Math.floor(r() * 2 ** 32));
      return r() < 0.5 ? big : -big - 1n;
    }
    case 2:
      return [1.5, 0.1, -2.75, 1e300, 5.960464477539063e-8, 3.4028234663852886e38, Math.PI, -0.5][Math.floor(r() * 8)];
    case 3:
      return ['', 'a', 'héllo', '✓', '𝄞', 'x'.repeat(30)][Math.floor(r() * 6)];
    case 4:
      return Uint8Array.from({ length: Math.floor(r() * 40) }, () => Math.floor(r() * 256));
    case 5:
      return [true, false, null][Math.floor(r() * 3)];
    case 6:
    case 7:
      return Array.from({ length: Math.floor(r() * 5) }, () => gen(r, depth + 1));
    case 8: {
      const m = new Map<unknown, unknown>();
      const n = Math.floor(r() * 5);
      for (let i = 0; i < n; i++) m.set(r() < 0.5 ? `k${Math.floor(r() * 100)}` : Math.floor(r() * 1000) - 500, gen(r, depth + 1));
      return m;
    }
    default:
      return r() < 0.5 ? new Tag(1, Math.floor(r() * 2e9)) : new Tag(37, Uint8Array.from({ length: 16 }, () => Math.floor(r() * 256)));
  }
}

function toC2(v: unknown): unknown {
  if (v instanceof Tag) return new C2Tag(v.tag, toC2(v.value));
  if (Array.isArray(v)) return v.map(toC2);
  if (v instanceof Map) return new Map([...v].map(([k, x]) => [toC2(k), toC2(x)]));
  return v;
}

const c2opts = { sortKeys: cdeEncodeOptions.sortKeys };
const passTag = (t: unknown) => t;

describe('cbor differential (cbor2)', () => {
  it('encodes random values exactly like cbor2 with deterministic key order', () => {
    const r = rng(42);
    for (let i = 0; i < 3000; i++) {
      const v = gen(r);
      const mine = encode(v);
      const theirs = c2encode(toC2(v) as never, c2opts);
      expect(toHex(mine), JSON.stringify(v, (_, x) => (typeof x === 'bigint' ? `${x}n` : x))).toBe(toHex(theirs));
      // and decodes them back to the same encoding
      expect(toHex(encode(decode(theirs)))).toBe(toHex(theirs));
      // cbor2 reads ours
      c2decode(mine, { tags: new Map([[1, passTag], [37, passTag]]) } as never);
    }
  });

  it('never crashes on random or truncated input', () => {
    const r = rng(7);
    for (let i = 0; i < 5000; i++) {
      const b = Uint8Array.from({ length: Math.floor(r() * 30) }, () => Math.floor(r() * 256));
      try {
        validate(b);
      } catch (e) {
        expect(e).toBeInstanceOf(CborError);
      }
      try {
        decodeMessage(b);
      } catch (e) {
        expect((e as Error).name).toMatch(/DecodeError|UnknownKindError/);
      }
    }
    const good = encode([16, 2, 16, 3, new Map([[32, 5]]), ['a', new Tag(1, 5)]]);
    for (let n = 0; n < good.length; n++) expect(() => decodeMessage(good.subarray(0, n))).toThrow();
  });

  it('rejects huge lengths without allocating', () => {
    expect(() => decode(Uint8Array.from([0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))).toThrow(/length/);
    expect(() => decode(Uint8Array.from([0x5a, 0xff, 0xff, 0xff, 0xff]))).toThrow(/length/);
  });

  it('pure-JS SHA-256 matches node:crypto', () => {
    const r = rng(3);
    for (const n of [0, 1, 55, 56, 63, 64, 65, 1000, 70000]) {
      const b = Uint8Array.from({ length: n }, () => Math.floor(r() * 256));
      expect(toHex(sha256Pure(b))).toBe(toHex(sha256(b)));
    }
  });
});
