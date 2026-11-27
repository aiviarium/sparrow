// Inputs for the property tests: the hex strings of ../test-vectors and
// seeded mutations of them (fuzz.test.ts, and the Go differential checks in
// interop.test.ts).
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fromHex as unhex } from '../../src/cbor.js';
import { VECTORS, loadVectors } from './tjson.js';

export const ITERS = Number(process.env.SPARROW_FUZZ_ITERS ?? 2000);
export const SEED = Number(process.env.SPARROW_FUZZ_SEED ?? 20261127);

/** Inputs that once broke a decoder (hex), kept as regression cases for every target. */
export const CRASHERS: string[] = [
  '9b0000000100000000', // array of 2^32 elements: refused before any allocation
  'bb0000000100000000',
  '5b0000000100000000',
  '82c1fbfff8000000000000f6', // timestamp NaN
];

export function rng(seed: number) {
  let s = seed >>> 0;
  const next = () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32;
  };
  return { f: next, n: (k: number) => Math.floor(next() * k) };
}

export function seedsOf(files?: string[]): Uint8Array[] {
  const out = new Map<string, Uint8Array>();
  const walk = (v: unknown) => {
    if (typeof v === 'string') {
      if (v.length >= 2 && v.length % 2 === 0 && v.length <= 1 << 17 && /^[0-9a-f]+$/.test(v)) out.set(v, unhex(v));
    } else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  };
  const names = files ?? readdirSync(VECTORS).filter((f) => f.endsWith('.json'));
  for (const f of names) walk(loadVectors(f));
  if (!files) for (const f of readdirSync(join(VECTORS, 'scenarios')).filter((x) => x.endsWith('.json'))) walk(JSON.parse(readFileSync(join(VECTORS, 'scenarios', f), 'utf8')));
  for (const c of CRASHERS) out.set(c, unhex(c));
  return [...out.values()];
}

const HOSTILE = [
  [0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
  [0x5a, 0x7f, 0xff, 0xff, 0xff],
  [0x7b, 0, 0, 0, 1, 0, 0, 0, 0],
  [0xbf],
  [0x9f],
  [0x5f],
  [0xf7],
  [0xd8, 0x37],
  [0xc1, 0xf9, 0x7e, 0x00],
  [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
  [0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
  [0xc0, 0, 0, 0, 0x40, 0, 0, 0],
];

export function mutate(r: ReturnType<typeof rng>, seeds: Uint8Array[], b: Uint8Array): Uint8Array {
  let a = [...b];
  const ops = 1 + r.n(4);
  for (let k = 0; k < ops; k++) {
    const at = a.length ? r.n(a.length) : 0;
    switch (r.n(9)) {
      case 0:
        if (a.length) a[at] ^= 1 << r.n(8);
        break;
      case 1:
        if (a.length) a[at] = r.n(256);
        break;
      case 2:
        a.splice(at, 0, ...Array.from({ length: 1 + r.n(8) }, () => r.n(256)));
        break;
      case 3:
        a.splice(at, 1 + r.n(8));
        break;
      case 4:
        a = a.slice(0, at);
        break;
      case 5: {
        const n = 1 + r.n(16);
        a.splice(at, 0, ...a.slice(at, at + n));
        break;
      }
      case 6: {
        const o = seeds[r.n(seeds.length)];
        const from = r.n(o.length + 1);
        a.splice(at, r.n(8), ...o.subarray(from, from + 1 + r.n(32)));
        break;
      }
      case 7:
        a.splice(at, r.n(4), ...HOSTILE[r.n(HOSTILE.length)]);
        break;
      default:
        if (a.length) a[at] = [0x00, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x80, 0xa0, 0xc0, 0xf6, 0xff][r.n(11)];
    }
  }
  return Uint8Array.from(a);
}

/** The inputs of one target: every seed as it is, then mutations. */
export function* inputs(seeds: Uint8Array[], salt: number, iters = ITERS): Generator<Uint8Array> {
  const r = rng(SEED ^ salt);
  for (const s of seeds) yield s;
  for (let i = 0; i < iters; i++) {
    const s = r.f() < 0.05 ? Uint8Array.from({ length: r.n(64) }, () => r.n(256)) : seeds[r.n(seeds.length)];
    yield mutate(r, seeds, s);
  }
}

