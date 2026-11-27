// Property tests ("fuzzing") of every decoder of untrusted input: CBOR, the
// wire messages, framing (the pipe binding's FrameDecoder), schema
// documents and deltas, the value codec, and the handshake of both roles.
//
// Inputs are the hex strings of ../test-vectors and mutations of them
// (bit flips, random bytes, insertions, deletions, truncations, splices,
// hostile CBOR heads), from a seeded generator. Properties: only the
// implementation's own error types are thrown, nothing hangs, round trips
// hold where they apply (decode, encode, decode gives the same bytes), and
// decoders allocate no more than the input warrants.
//
// SPARROW_FUZZ_ITERS sets the iterations per target (default 2000; CI's
// long run uses more), SPARROW_FUZZ_SEED the seed. A failing input is
// printed as hex: add it to CRASHERS (test/helpers/fuzz.ts) with the fix.
import { describe, expect, it } from 'vitest';
import { CborError, decode, encode, isCanonical, toHex, validate } from '../src/cbor.js';
import { DecodeError, FrameDecoder, FramingError, ParamError, TooLargeError, UnknownKindError, decodeMessage, encodeMessage, frame } from '../src/wire.js';
import {
  SchemaError,
  canonicalFacet,
  canonicalSchema,
  decodeDelta,
  decodeFacet,
  decodeInterface,
  decodeSchema,
  encodeDelta,
  encodeFacet,
  encodeInterface,
  encodeSchema,
  facetHash,
  interfaceHash,
  schemaHash,
  validateFacet,
  validateInterface,
  validateSchema,
  schemaOf,
  type TypeRef,
} from '../src/schema.js';
import { Codec, ValueError } from '../src/value.js';
import { Session, SparrowError } from '../src/session.js';
import { memPair } from '../src/transport/mem.js';
import * as lib from '../src/index.js';
import { facets } from './fixture/interop.mjs';
import { byName, fromTJ } from './helpers/tjson.js';
import { ITERS, SEED, inputs, mutate, rng, seedsOf } from './helpers/fuzz.js';
import { flush } from './helpers/clock.js';

// ---------------------------------------------------------------------------

type ErrClass = abstract new (...a: never[]) => Error;

/** Runs f(b); an exception must be one of the allowed classes. Returns undefined when f threw. */
function only<T>(b: Uint8Array, allowed: ErrClass[], f: () => T): T | undefined {
  try {
    return f();
  } catch (e) {
    if (allowed.some((c) => e instanceof c)) return undefined;
    throw new Error(`input ${toHex(b)}: unexpected ${(e as Error)?.constructor?.name}: ${(e as Error)?.message}`, { cause: e });
  }
}

function sameBytes(b: Uint8Array, x: Uint8Array, y: Uint8Array, what: string) {
  if (toHex(x) !== toHex(y)) throw new Error(`input ${toHex(b)}: ${what} not stable: ${toHex(x)} then ${toHex(y)}`);
}

const ALL = seedsOf();

describe('fuzz', () => {
  it('CBOR: decode, validate and canonical re-encoding', () => {
    for (const b of inputs(ALL, 1)) {
      const v = only(b, [CborError], () => decode(b));
      const valid = only(b, [CborError], () => (validate(b), true)) ?? false;
      if (valid !== (v !== undefined || isNullItem(b))) throw new Error(`input ${toHex(b)}: decode and validate disagree`);
      if (!valid) continue;
      const e = encode(v);
      expect(isCanonical(e)).toBe(true);
      sameBytes(b, e, encode(decode(e)), 'CBOR re-encoding');
      if (e.length > b.length) throw new Error(`input ${toHex(b)}: re-encoding grew from ${b.length} to ${e.length} bytes`);
    }
  });

  it('wire: every message kind, with round trips', () => {
    const allowed = [CborError, DecodeError, UnknownKindError, ParamError];
    for (const b of inputs(seedsOf(['framing.json', 'handshake.json', 'calls.json', 'credit.json']), 2)) {
      const m = only(b, allowed, () => decodeMessage(b));
      if (!m) continue;
      const e = encodeMessage(m);
      sameBytes(b, e, encodeMessage(decodeMessage(e)), 'message re-encoding');
    }
  });

  it('framing: the same messages however the bytes are chunked; the limit before the body', () => {
    const r = rng(SEED ^ 3);
    const msgs = seedsOf(['calls.json']).slice(0, 64);
    for (let i = 0; i < ITERS; i++) {
      let stream: Uint8Array = new Uint8Array(0);
      const n = 1 + r.n(6);
      for (let k = 0; k < n; k++) stream = cat(stream, frame(msgs[r.n(msgs.length)]));
      if (r.f() < 0.5) stream = mutate(r, msgs, stream);
      const limit = 16384 + r.n(4) * 30000;
      const whole = runFrames(stream, [stream.length], limit);
      const cuts: number[] = [];
      for (let left = stream.length; left > 0; ) {
        const k = Math.min(left, 1 + r.n(8));
        cuts.push(k);
        left -= k;
      }
      const chopped = runFrames(stream, cuts, limit);
      if (JSON.stringify(whole) !== JSON.stringify(chopped)) throw new Error(`stream ${toHex(stream)}: ${JSON.stringify(whole)} vs ${JSON.stringify(chopped)}`);
    }
    // A prefix claiming 2^30 bytes with no body is refused at once, holding nothing.
    const fd = new FrameDecoder(1 << 20);
    expect(() => fd.push(Uint8Array.of(0xc0, 0, 0, 0, 0x40, 0, 0, 0))).toThrow(TooLargeError);
    // A prefix within the limit buffers only what arrived.
    const fd2 = new FrameDecoder(1 << 20);
    expect(fd2.push(Uint8Array.of(0x80, 0x0f, 0xff, 0xff, 1, 2, 3))).toEqual([]);
    expect(fd2.pending).toBe(7);
  });

  it('schema documents, facets, interfaces and deltas: decode, validate, canonical form, hashes', () => {
    const allowed = [CborError, SchemaError];
    for (const b of inputs(seedsOf(['schema.json', 'admin.json', 'handshake.json']), 4)) {
      const s = only(b, allowed, () => decodeSchema(b));
      if (s && only(b, allowed, () => (validateSchema(s), true))) {
        const c = encodeSchema(canonicalSchema(s));
        sameBytes(b, c, encodeSchema(canonicalSchema(decodeSchema(c))), 'canonical schema');
        expect(schemaHash(s).length).toBe(33);
      }
      const f = only(b, allowed, () => decodeFacet(b));
      if (f && f.id >= 16 && only(b, allowed, () => (validateFacet(f), true))) {
        const c = encodeFacet(canonicalFacet(f));
        sameBytes(b, c, encodeFacet(canonicalFacet(decodeFacet(c))), 'canonical facet');
        expect(facetHash(f).length).toBe(33);
      }
      const i = only(b, allowed, () => decodeInterface(b));
      if (i && only(b, allowed, () => (validateInterface(i), true))) {
        sameBytes(b, encodeInterface(i), encodeInterface(decodeInterface(encodeInterface(i))), 'interface');
        expect(interfaceHash(i).length).toBe(33);
      }
      const d = only(b, allowed, () => decodeDelta(b));
      if (d) sameBytes(b, encodeDelta(d), encodeDelta(decodeDelta(encodeDelta(d))), 'delta');
    }
  });

  it('values: every type of a facet, with round trips', () => {
    const notes = schemaOf(fromTJ(byName().get('schema/server-base').input)).facets.find((f) => f.id === 16)!;
    const c = new Codec(notes);
    const types: TypeRef[] = [...notes.types.map((t) => t.id), ...Array.from({ length: 12 }, (_, k) => k), [0, 6], [1, 6, 3], [2, 2]];
    const r = rng(SEED ^ 5);
    for (const b of inputs(seedsOf(['encoding.json', 'calls.json']), 5)) {
      const t = types[r.n(types.length)];
      const v = only(b, [CborError, ValueError], () => c.decode(t, b));
      if (v === undefined) continue;
      const e = only(b, [ValueError], () => c.encode(t, v));
      if (!e) continue; // unknown enum values and variants decode (forward compatibility) but cannot be re-sent, as in Go
      sameBytes(b, e, c.encode(t, c.decode(t, e)), `value of type ${JSON.stringify(t)}`);
    }
  });

  it('handshake: arbitrary first messages each way end in a session or a close, never an exception', async () => {
    const f = facets(lib);
    const seeds = seedsOf(['handshake.json']);
    const hs = Math.max(50, Math.floor(ITERS / 10));
    let n = 0;
    for (const b of inputs(seeds, 6, hs)) {
      // As the server: the input is the client's first message, then Ready.
      {
        const [a, s] = memPair({ lingerMs: 0 });
        const p = Session.accept(s, { schema: f.serverSchema, helloTimeoutMs: 1000 });
        a.start({ message: () => {}, error: () => {}, close: () => {} });
        a.send(b);
        await settle(p, () => a.close(lib.Status.ok, ''));
      }
      // As the client: the input is the server's answer to Hello.
      {
        const [c, s] = memPair({ lingerMs: 0 });
        s.start({ message: () => s.send(b), error: () => {}, close: () => {} });
        const p = Session.connect(c, { schema: f.clientSchema });
        await settle(p, () => s.close(lib.Status.ok, ''));
      }
      n++;
    }
    expect(n).toBe(seeds.length + hs);
  });
});

function isNullItem(b: Uint8Array): boolean {
  return b.length === 1 && b[0] === 0xf6;
}

function cat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const o = new Uint8Array(a.length + b.length);
  o.set(a);
  o.set(b, a.length);
  return o;
}

function runFrames(stream: Uint8Array, cuts: number[], limit: number): string[] {
  const fd = new FrameDecoder(limit);
  const out: string[] = [];
  let off = 0;
  let pushed = 0;
  try {
    for (const k of cuts) {
      const part = stream.slice(off, off + k);
      off += k;
      pushed += part.length;
      for (const m of fd.push(part)) out.push(toHex(m));
      if (fd.pending > pushed) throw new Error('the decoder holds more than it was given');
      if (fd.error) throw fd.error;
    }
  } catch (e) {
    if (e instanceof TooLargeError || e instanceof FramingError) out.push(`error ${e.constructor.name}`);
    else throw e;
  }
  return out;
}

/** Waits until the handshake promise settles (either way), ends the peer, and lets everything run out. */
async function settle(p: Promise<Session>, end: () => Promise<void>): Promise<void> {
  let s: Session | undefined;
  const r = await Promise.race([
    p.then(
      (x) => ((s = x), 'ok'),
      (e) => {
        if (!(e instanceof SparrowError)) throw e;
        return 'failed';
      },
    ),
    flush().then(() => 'pending'),
  ]);
  void r;
  await end();
  await p.then(
    () => {},
    (e) => {
      if (!(e instanceof SparrowError)) throw e;
    },
  );
  if (s) await s.closed;
}
