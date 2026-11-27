// Enum value names, integer bounds and timestamps in the value codec (core 3.1, 6.3, 6.5).
import { describe, expect, it } from 'vitest';
import { toHex } from '../src/cbor.js';
import { FacetBuilder, SchemaError, T, byteStream, field, validateFacet } from '../src/schema.js';
import { Codec, ValueError } from '../src/value.js';

const unhex = (s: string) => Uint8Array.from(s.replace(/ /g, '').match(/../g) ?? [], (h) => parseInt(h, 16));

function facet() {
  const b = new FacetBuilder('acme.test', '1.0.0', { id: 16 });
  const mode = b.enum('Mode', ['none', 'fast']);
  const level = b.enum('Level', ['none', 'high']);
  return { f: b.build(), mode, level };
}

describe('enum sigil names (core 6.5)', () => {
  it('names each value sigil <enum>.<value>, so two enums can both have none', () => {
    const { f, mode, level } = facet();
    const names = new Map(f.sigils.map((s) => [s.id, s.name]));
    expect(names.get(mode.values.none)).toBe('Mode.none');
    expect(names.get(mode.values.fast)).toBe('Mode.fast');
    expect(names.get(level.values.none)).toBe('Level.none');
  });

  it('shows the value name alone, and takes it, the full sigil name or the sigil', () => {
    const { f, mode, level } = facet();
    const c = new Codec(f);
    const t = mode.type;
    const none = toHex(c.encode(t, 'none'));
    expect(none).toBe(toHex(c.encode(t, mode.values.none)));
    expect(toHex(c.encode(t, 'Mode.none'))).toBe(none);
    expect(c.decode(t, c.encode(t, 'fast'))).toBe('fast');
    expect(c.decode(level.type, c.encode(level.type, 'none'))).toBe('none');
    expect(toHex(c.encode(level.type, 'none'))).not.toBe(none);
    expect(() => c.encode(t, 'Level.none')).toThrow(ValueError);
    expect(() => c.encode(t, 'high')).toThrow(ValueError);
    // An unknown value decodes as its sigil number.
    expect(c.decode(t, unhex('1863'))).toBe(99);
  });

  it('keeps a sigil name without the enum prefix as it is', () => {
    const f = {
      id: 16, name: 'acme.bare', version: '1.0.0',
      types: [{ kind: 'enum' as const, id: 64, name: 'State', values: [64, 65], annotations: {} }],
      services: [],
      sigils: [{ id: 64, name: 'pending', kind: 0, annotations: {} }, { id: 65, name: 'State.done', kind: 0, annotations: {} }],
      implements: null, retired: [], annotations: {},
    };
    const c = new Codec(f);
    expect(c.decode(64, c.encode(64, 'pending'))).toBe('pending');
    expect(c.decode(64, c.encode(64, 'done'))).toBe('done');
  });

  it('refuses duplicate sigil names within a facet', () => {
    const b = new FacetBuilder('acme.dup', '1.0.0');
    b.errorCode('conflict');
    b.symbol('conflict');
    expect(() => b.build()).toThrow(SchemaError);
    const { f } = facet();
    f.sigils[1] = { ...f.sigils[1], name: f.sigils[0].name };
    try {
      validateFacet(f);
      throw new Error('accepted');
    } catch (e) {
      expect((e as SchemaError).code).toBe('duplicate_sigil_name');
    }
  });

  it('refuses a kind-0 sigil listed by two enums', () => {
    const { f, mode } = facet();
    f.types.push({ kind: 'enum', id: 90, name: 'Other', values: [mode.values.fast], annotations: {} });
    try {
      validateFacet(f);
      throw new Error('accepted');
    } catch (e) {
      expect((e as SchemaError).code).toBe('sigil_in_two_enums');
    }
  });
});

// The same table as timestampMillis in go/cbor/cbor_test.go: float seconds and
// the millisecond both implementations round them to.
const timestampMillis: [number, number][] = [
  [1.001, 1001], // 1000.9999999999999 ms: new Date(s * 1000) would give 1000
  [1.0015, 1002],
  [-1.5005, -1500],
  [0.0005, 1],
  [-0.0005, 0],
  [-1.5, -1500],
  [-0.0015, -1],
  [0.00049999999999999994, 0],
  [1e-9, 0],
  [-1e-9, 0],
  [1795780800.5, 1795780800500],
  [1795780800.0015, 1795780800002],
];

function f64(x: number): string {
  const b = new DataView(new ArrayBuffer(8));
  b.setFloat64(0, x);
  return toHex(new Uint8Array(b.buffer));
}

describe('timestamps (core 6.3)', () => {
  const c = new Codec(facet().f);
  it('rounds float seconds to the nearest millisecond, halves up, as Go', () => {
    for (const [s, ms] of timestampMillis) {
      const d = c.decode(T.timestamp, unhex(`c1fb${f64(s)}`)) as Date;
      expect([s, d.getTime()]).toEqual([s, ms]);
    }
  });

  it('sends integer seconds when there is no fraction', () => {
    const cases: [unknown, string][] = [
      [new Date(0), 'c100'],
      [new Date(-1000), 'c120'],
      [new Date(1795780800000), 'c11a6b0970c0'],
      [new Date(-1500), 'c1f9be00'],
      [new Date(1795780800500), 'c1fb41dac25c30200000'],
      [2, 'c102'],
      [-0, 'c100'],
      [1.5, 'c1f93e00'],
      [-2n, 'c121'],
      [2 ** 53 - 1, 'c11b001fffffffffffff'],
      [2 ** 53, 'c1fa5a000000'], // integral, beyond 2^53 - 1: a float, as Go
      [2 ** 64, 'c1fa5f800000'],
    ];
    for (const [v, want] of cases) expect([v, toHex(c.encode(T.timestamp, v))]).toEqual([v, want]);
  });

  it('round-trips every millisecond Date, negative ones too', () => {
    for (const ms of [0, 1, -1, 999, -999, 1001, -1001, 1795780800123, -62135596800000, 8.64e15, -8.64e15]) {
      expect((c.decode(T.timestamp, c.encode(T.timestamp, new Date(ms))) as Date).getTime()).toBe(ms);
    }
  });

  it('refuses what a Date cannot hold', () => {
    for (const h of ['c1f97e00', 'c1f97c00', 'c1f9fc00', 'c11b0000080000000001', 'c13b0000080000000001', 'c1fb7e37e43c8800759c']) {
      expect(() => c.decode(T.timestamp, unhex(h)), h).toThrow(ValueError);
    }
    expect(() => c.encode(T.timestamp, new Date(NaN))).toThrow(ValueError);
    expect(() => c.encode(T.timestamp, Infinity)).toThrow(ValueError);
    expect(() => c.encode(T.timestamp, 2n ** 63n)).toThrow(ValueError);
    expect(() => c.encode(T.timestamp, 2n ** 53n)).toThrow(ValueError);
  });
});

describe('integers a message defines (core 3.1)', () => {
  const { f, mode } = facet();
  const c = new Codec(f);
  it('keeps the 64-bit range of int and uint values', () => {
    for (const [t, v, h] of [
      [T.uint, 2n ** 64n - 1n, '1bffffffffffffffff'],
      [T.int, -(2n ** 63n), '3b7fffffffffffffff'],
      [T.uint, 2n ** 53n, '1b0020000000000000'],
    ] as const) {
      expect(toHex(c.encode(t, v))).toBe(h);
      expect(c.decode(t, unhex(h))).toBe(v);
    }
  });

  it('refuses sigils and byte tokens beyond 2^53 - 1', () => {
    const big = '1b0020000000000000';
    expect(() => c.decode(mode.type, unhex(big))).toThrow(ValueError);
    expect(() => c.decode(T.symbol, unhex(big))).toThrow(ValueError);
    const b = new FacetBuilder('acme.up', '1.0.0', { id: 16 });
    const up = b.struct('Up', [field('data', byteStream())]);
    const u = new Codec(b.build());
    expect(() => u.decode(up, unhex(`81${big.slice(0)}`))).toThrow(ValueError);
    expect(u.decode(up, unhex('811b001fffffffffffff'))).toEqual({ data: Number.MAX_SAFE_INTEGER });
    expect(() => u.encode(up, { data: 2n ** 53n })).toThrow(ValueError);
    expect(() => c.encode(T.symbol, 2 ** 53)).toThrow(ValueError);
  });
});
