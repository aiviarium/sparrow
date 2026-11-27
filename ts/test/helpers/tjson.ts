// Typed JSON of the test vectors (test-vectors/README.md) <-> the generic CBOR representation.
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Float, Tag, encode, compareBytes, fromHex, toHex } from '../../src/cbor.js';

export const VECTORS = process.env.SPARROW_VECTORS ?? join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'test-vectors');

export type TJ = any;

export function loadVectors(file: string): { vectors: TJ[]; [k: string]: TJ } {
  return JSON.parse(readFileSync(join(VECTORS, file), 'utf8'));
}

export function loadScenarios(): [string, TJ][] {
  const dir = join(VECTORS, 'scenarios');
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => [f, JSON.parse(readFileSync(join(dir, f), 'utf8'))]);
}

let byNameCache: Map<string, TJ> | undefined;
export function byName(): Map<string, TJ> {
  if (byNameCache) return byNameCache;
  const m = new Map<string, TJ>();
  for (const f of readdirSync(VECTORS).filter((x) => x.endsWith('.json'))) {
    for (const v of loadVectors(f).vectors) m.set(v.name, v);
  }
  byNameCache = m;
  return m;
}

export function fromTJ(t: TJ): unknown {
  if (t === null || typeof t === 'boolean' || typeof t === 'string' || typeof t === 'number') return t;
  if (Array.isArray(t)) return t.map(fromTJ);
  if ('$int' in t) {
    const b = BigInt(t.$int);
    return b >= BigInt(-Number.MAX_SAFE_INTEGER) && b <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(b) : b;
  }
  if ('$float' in t) return new Float(Number(t.$float));
  if ('$bytes' in t) return fromHex(t.$bytes);
  if ('$tag' in t) return new Tag(t.$tag, fromTJ(t.value));
  if ('$map' in t) return new Map(t.$map.map(([k, v]: [TJ, TJ]) => [fromTJ(k), fromTJ(v)]));
  return new Map(Object.entries(t).map(([k, v]) => [k, fromTJ(v)]));
}

export function fmtFloat(n: number): string {
  if (Number.isNaN(n)) return 'NaN';
  if (n === Infinity) return 'Infinity';
  if (n === -Infinity) return '-Infinity';
  if (Object.is(n, -0)) return '-0';
  return String(n);
}

export function toTJ(x: unknown): TJ {
  if (x === null || typeof x === 'boolean' || typeof x === 'string') return x;
  if (typeof x === 'bigint') {
    return x > BigInt(Number.MAX_SAFE_INTEGER) || x < BigInt(-Number.MAX_SAFE_INTEGER) ? { $int: x.toString() } : Number(x);
  }
  if (typeof x === 'number') return Number.isInteger(x) && !Object.is(x, -0) ? x : { $float: fmtFloat(x) };
  if (x instanceof Float) return { $float: fmtFloat(x.value) };
  if (x instanceof Uint8Array) return { $bytes: toHex(x) };
  if (x instanceof Tag) return { $tag: x.tag, value: toTJ(x.value) };
  if (Array.isArray(x)) return x.map(toTJ);
  if (x instanceof Map) {
    const entries = [...x.entries()].map(([k, v]) => [k, v] as [unknown, unknown]);
    entries.sort((a, b) => compareBytes(encode(a[0]), encode(b[0])));
    const allText = entries.every(([k]) => typeof k === 'string' && !k.startsWith('$'));
    if (allText) return Object.fromEntries(entries.map(([k, v]) => [k, toTJ(v)]));
    return { $map: entries.map(([k, v]) => [toTJ(k), toTJ(v)]) };
  }
  throw new Error(`toTJ: unsupported ${Object.prototype.toString.call(x)}`);
}

export function eqTJ(a: TJ, b: TJ): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => eqTJ(x, b[i]));
  }
  if (typeof a !== 'object') return false;
  if ('$float' in a || '$float' in b) return '$float' in a && '$float' in b && Object.is(Number(a.$float), Number(b.$float));
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && eqTJ(a[k], b[k]));
}

export const hex = toHex;
export const unhex = fromHex;
