// The interop facets, their handlers and the client-side check suite,
// shared by the session tests (TS <-> TS), the pipe tests and the Go interop
// tests (go/cmd/sparrow-interop implements the same facets in Go). Plain
// ESM taking the library as a parameter, so the same code runs against
// ../../src (vitest) and ../../dist (child processes).

/** Builds the server facet interop.test (facet 16) and the client facet interop.client. */
export function facets(lib) {
  const { FacetBuilder, T, field, optionalField, variant, list, mapOf, optional, stream, byteStream } = lib;
  const b = new FacetBuilder('interop.test', '1.0.0', { id: 16 });
  b.errorCode('interop_failed');
  const FailInfo = b.struct('FailInfo', [field('reason', T.string), field('code', T.uint)]);
  const Color = b.enum('Color', ['red', 'green', 'blue']).type;
  const Point = b.struct('Point', [field('x', T.int), field('y', T.int), optionalField('label', T.string)]);
  const Shape = b.union('Shape', [variant('circle', T.float64), variant('square', Point), variant('none', T.unit)]);
  const Filter = b.sparseStruct('Filter', [optionalField('limit', T.uint), optionalField('query', T.string)]);
  b.symbol('sym.hello');
  const Everything = b.struct('Everything', [
    field('s', T.string),
    field('i', T.int),
    field('u', T.uint),
    field('f', T.float64),
    field('b', T.bool),
    field('data', T.bytes),
    field('ts', T.timestamp),
    field('id', T.uuid),
    field('tags', list(T.string)),
    field('scores', mapOf(T.string, T.int)),
    field('color', Color),
    field('shape', Shape),
    field('point', Point),
    field('filter', Filter),
    optionalField('opt', T.string),
    field('dyn', T.dynamic),
    field('sym', T.symbol),
    field('big', T.int),
    field('f32', T.float32),
  ]);
  const svc = b.service('Test');
  svc.method('echo', T.string, T.string, { idempotent: true });
  svc.method('count', T.uint, stream(T.uint));
  svc.method('sum', stream(T.int), T.int);
  svc.method('upper', stream(T.string), stream(T.string));
  svc.notification('log', T.string);
  svc.method('lastLog', T.unit, T.string);
  svc.method('fail', T.string, T.unit, { errors: ['interop_failed'] });
  svc.method('slow', T.uint, T.unit);
  svc.method('wasCancelled', T.unit, T.bool);
  svc.method('progress', T.uint, T.string);
  svc.method('roundtrip', Everything, Everything);
  svc.method('callback', T.string, T.string);
  svc.method('upload', byteStream(), T.uint);
  svc.method('download', T.uint, byteStream());
  svc.method('headers', T.unit, stream(T.string));
  svc.method('optional', optional(T.string), optional(T.string));
  void FailInfo;
  const server = b.build();

  const c = new FacetBuilder('interop.client', '1.0.0', { id: 16 });
  const cs = c.service('Client');
  cs.method('greet', T.string, T.string);
  cs.method('count', T.uint, stream(T.uint));
  const client = c.build();
  return {
    server,
    client,
    serverSchema: lib.makeSchema('interop.server', '1.0.0', [server]),
    clientSchema: lib.makeSchema('interop.client', '1.0.0', [client]),
  };
}

/** Handlers of interop.test. */
export function serverHandlers(lib) {
  const { SparrowError, Status } = lib;
  const st = { lastLog: '', cancelled: false };
  const sleep = (ms, signal) =>
    new Promise((res, rej) => {
      const t = setTimeout(res, ms);
      signal.addEventListener('abort', () => {
        clearTimeout(t);
        rej(signal.reason);
      }, { once: true });
    });
  return {
    state: st,
    handlers: {
      'interop.test': {
        echo: (s) => s,
        count: async function* (n) {
          for (let i = 1; i <= n; i++) yield i;
        },
        sum: async (items) => {
          let s = 0n;
          for await (const v of items) s += BigInt(v);
          return s;
        },
        upper: async function* (items, ctx) {
          ctx.sendHeaders({ 'x-mode': 'upper' });
          for await (const s of items) yield s.toUpperCase();
        },
        log: (s) => {
          st.lastLog = s;
        },
        lastLog: () => st.lastLog,
        fail: (msg) => {
          throw new SparrowError('interop_failed', msg, { type: 'FailInfo', value: { reason: msg, code: 7 } });
        },
        slow: async (ms, ctx) => {
          st.cancelled = false;
          try {
            await sleep(ms, ctx.signal);
          } catch (e) {
            st.cancelled = true;
            throw e;
          }
          return null;
        },
        wasCancelled: async () => {
          // the Cancel and the handler's abort race the next call slightly
          for (let i = 0; i < 50 && !st.cancelled; i++) await new Promise((r) => setTimeout(r, 10));
          return st.cancelled;
        },
        progress: async (n, ctx) => {
          for (let i = 1; i <= n; i++) await ctx.progress(i, n, `step ${i}`);
          return 'done';
        },
        roundtrip: (v) => v,
        callback: async (s, ctx) => ctx.session.call('interop.client', 'greet', s),
        upload: async (_, ctx) => (await ctx.bytes(0)).length,
        download: async (n, ctx) => {
          const b = new Uint8Array(n);
          for (let i = 0; i < n; i++) b[i] = i & 0xff;
          await ctx.sendBytes(0, b, true);
        },
        headers: async (_, ctx) => {
          ctx.sendHeaders({ 'x-test': 'yes' });
          ctx.setTrailers({ 'x-done': true });
          await ctx.send('a');
          await ctx.send('b');
        },
        optional: (s) => (s === null ? null : `${s}!`),
      },
    },
  };
}

/** Handlers of interop.client. */
export function clientHandlers() {
  return {
    'interop.client': {
      greet: (s) => `hello, ${s}`,
      count: async function* (n) {
        for (let i = 1; i <= n; i++) yield i;
      },
    },
  };
}

export function everything() {
  return {
    s: 'héllo ✓',
    i: -42,
    u: 4294967296,
    f: 1.5,
    b: true,
    data: new Uint8Array([0, 1, 2, 255]),
    ts: new Date(Date.UTC(2026, 10, 27, 12, 0, 0, 500)),
    id: '6f1c2e4a-8b3d-4f5e-9a7b-0c1d2e3f4a5b',
    tags: ['a', 'b'],
    scores: { alice: 3, bob: -1 },
    color: 'green',
    shape: { variant: 'square', value: { x: 1, y: 2, label: 'p' } },
    point: { x: -7, y: 9007199254740991 },
    filter: { query: 'q' },
    dyn: { type: 'Point', value: { x: 3, y: 4 } },
    sym: 'sym.hello',
    big: -9223372036854775808n,
    f32: 0.5,
  };
}

function assert(cond, what) {
  if (!cond) throw new Error(`check failed: ${what}`);
}

function eq(a, b, what) {
  const j = (x) =>
    JSON.stringify(x, (_, v) => {
      if (typeof v === 'bigint') return `${v}n`;
      if (v instanceof Uint8Array) return `bytes:${[...v]}`;
      if (v instanceof Map) return [...v.entries()];
      if (v && typeof v === 'object' && !Array.isArray(v)) return Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : 1)));
      return v;
    });
  assert(j(a) === j(b), `${what}: got ${j(a)}, want ${j(b)}`);
}

/**
 * The client side of the interop checks: calls every shape of interop.test
 * on a session whose peer serves it. Returns the names of the checks.
 */
export async function runClientSuite(session, lib, log = () => {}) {
  const { SparrowError, Status } = lib;
  const done = [];
  const check = async (name, f) => {
    log(`check ${name}`);
    await f();
    done.push(name);
  };
  const F = 'interop.test';
  await check('unary', async () => eq(await session.call(F, 'echo', 'hi'), 'hi', 'echo'));
  await check('unary-optional', async () => {
    eq(await session.call(F, 'optional', null), null, 'optional null');
    eq(await session.call(F, 'optional', 'x'), 'x!', 'optional x');
  });
  await check('server-stream', async () => {
    const got = [];
    for await (const v of session.stream(F, 'count', 300)) got.push(v);
    eq(got.length, 300, 'count items');
    eq(got[299], 300, 'last item');
  });
  await check('server-stream-credit', async () => {
    // A tiny initial credit makes the callee wait for Credit grants.
    const got = [];
    for await (const v of session.stream(F, 'count', 50, { credit: 8 })) got.push(v);
    eq(got.length, 50, 'items with credit 8');
  });
  await check('client-stream', async () => {
    async function* nums() {
      for (let i = 1; i <= 5000; i++) yield i;
    }
    eq(await session.call(F, 'sum', nums()), 12502500, 'sum');
  });
  await check('bidi-stream', async () => {
    const call = session.stream(F, 'upper', ['a', 'bc', 'def']);
    const got = [];
    for await (const v of call) got.push(v);
    eq(got, ['A', 'BC', 'DEF'], 'upper');
    const h = await call.headers;
    eq(h.get('x-mode'), 'upper', 'headers');
  });
  await check('bidi-interleaved', async () => {
    const call = session.open(F, 'upper');
    const it = call[Symbol.asyncIterator]();
    for (const s of ['x', 'y', 'z']) {
      await call.send(s);
      const r = await it.next();
      eq(r.value, s.toUpperCase(), 'interleaved item');
    }
    await call.end();
    eq((await it.next()).done, true, 'end of stream');
  });
  await check('notification', async () => {
    session.notify(F, 'log', 'note to self');
    let got = '';
    for (let i = 0; i < 100 && got !== 'note to self'; i++) {
      got = await session.call(F, 'lastLog');
      if (got !== 'note to self') await new Promise((r) => setTimeout(r, 10));
    }
    eq(got, 'note to self', 'lastLog');
  });
  await check('error-details', async () => {
    try {
      await session.call(F, 'fail', 'boom');
      assert(false, 'fail did not throw');
    } catch (e) {
      assert(e instanceof SparrowError, `not a SparrowError: ${e}`);
      eq(e.code, 'interop_failed', 'error code');
      assert(e.status >= 64, 'error status is a facet sigil');
      eq(e.rawMessage, 'boom', 'message');
      eq(e.details?.typeName, 'FailInfo', 'details type');
      eq(e.details?.value, { reason: 'boom', code: 7 }, 'details value');
      eq(e.remote, true, 'remote');
    }
  });
  await check('cancel', async () => {
    const ac = new AbortController();
    const p = session.call(F, 'slow', 10000, { signal: ac.signal });
    setTimeout(() => ac.abort(), 50);
    try {
      await p;
      assert(false, 'slow was not cancelled');
    } catch (e) {
      eq(e.status, Status.cancelled, 'cancelled status');
    }
    eq(await session.call(F, 'wasCancelled'), true, 'callee saw the cancel');
  });
  await check('deadline', async () => {
    try {
      await session.call(F, 'slow', 10000, { timeoutMs: 100 });
      assert(false, 'slow did not time out');
    } catch (e) {
      eq(e.status, Status.deadline_exceeded, 'deadline status');
    }
    eq(await session.call(F, 'wasCancelled'), true, 'callee saw the deadline');
  });
  await check('progress', async () => {
    const seen = [];
    const r = await session.call(F, 'progress', 5, { onProgress: (p) => seen.push(p) });
    eq(r, 'done', 'progress result');
    eq(seen.length, 5, 'progress messages');
    eq(seen[4], { done: 5, total: 5, note: 'step 5' }, 'last progress');
  });
  await check('values', async () => {
    const v = everything();
    const got = await session.call(F, 'roundtrip', v);
    eq(got.ts.getTime(), v.ts.getTime(), 'timestamp');
    eq({ ...got, ts: 0 }, { ...v, ts: 0, dyn: { type: got.dyn.type, value: { x: 3, y: 4 } } }, 'roundtrip');
    eq(session.peerFacet(F).types.find((t) => t.id === got.dyn.type).name, 'Point', 'dynamic type');
  });
  await check('callback', async () => eq(await session.call(F, 'callback', 'server'), 'hello, server', 'callback'));
  await check('upload', async () => eq(await session.call(F, 'upload', new Uint8Array(40000).fill(7)), 40000, 'upload'));
  await check('download', async () => {
    const b = await session.call(F, 'download', 50000);
    eq(b.length, 50000, 'download length');
    eq(b[257], 1, 'download content');
  });
  await check('headers-trailers', async () => {
    const call = session.stream(F, 'headers');
    const got = [];
    for await (const v of call) got.push(v);
    eq(got, ['a', 'b'], 'items');
    eq((await call.headers).get('x-test'), 'yes', 'headers');
    eq((await call.trailers).get('x-done'), true, 'trailers');
  });
  await check('concurrent', async () => {
    const rs = await Promise.all(Array.from({ length: 50 }, (_, i) => session.call(F, 'echo', `n${i}`)));
    eq(rs[49], 'n49', 'concurrent');
  });
  return done;
}
