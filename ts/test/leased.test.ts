// Leased streams and WebTransport framing/stream tests (spec 4.2, 4.3, 4.5, 7.5).
import { describe, expect, it } from 'vitest';
import * as lib from '../src/index.js';
import {
  FacetBuilder,
  Session,
  SparrowError,
  Status,
  T,
  makeSchema,
  memLeasedPair,
  stream,
  webTransportConn,
  type Stream,
  type WebTransportBidiStreamLike,
  type WebTransportLike,
} from '../src/index.js';
import { clientHandlers, facets, runClientSuite, serverHandlers } from './fixture/interop.mjs';
import { FakeClock, flush } from './helpers/clock.js';
import { eventually } from './helpers/wait.js';

async function leasedPair(srvOpts = {}, cliOpts = {}) {
  const f = facets(lib);
  const sh = serverHandlers(lib);
  const [a, b] = memLeasedPair();
  const [srv, cli] = await Promise.all([
    Session.accept(b, { schema: f.serverSchema, handlers: sh.handlers, ...srvOpts }),
    Session.connect(a, { schema: f.clientSchema, handlers: clientHandlers(), ...cliOpts }),
  ]);
  return { srv, cli, f, sh, a, b };
}

describe('leased streams over memLeasedPair', () => {
  it('runs the full interop suite over leased streams', async () => {
    const { srv, cli, a } = await leasedPair();
    const done = await runClientSuite(cli, lib);
    expect(done.length).toBeGreaterThan(15);
    // Leased streams were actually opened and reused.
    expect(a.streams.size).toBeGreaterThan(0);
    await cli.close();
    await srv.closed;
  });

  it('reuses released leased streams and routes shared/notifications on the shared lane', async () => {
    const fb = new FacetBuilder('test.lease', '1.0.0', { id: 16 });
    const svc = fb.service('S');
    svc.method('normal', T.string, T.string);
    svc.method('sub', T.unit, stream(T.uint), { shared: true });
    svc.notification('ping', T.string);
    const sc = makeSchema('s', '1.0.0', [fb.build()]);

    const notes: string[] = [];
    const [a, b] = memLeasedPair();
    const [srv, cli] = await Promise.all([
      Session.accept(b, {
        schema: sc,
        handlers: {
          'test.lease': {
            normal: (x: string) => x.toUpperCase(),
            sub: async function* () {
              yield 1;
              yield 2;
            },
            ping: (s: string) => {
              notes.push(s);
            },
          },
        },
      }),
      Session.connect(a),
    ]);

    // Shared method and notification should not open any leased stream.
    const got: unknown[] = [];
    for await (const v of cli.stream('test.lease', 'sub')) got.push(v);
    expect(got).toEqual([1, 2]);
    cli.notify('test.lease', 'ping', 'hi');
    await eventually(() => notes.length === 1, 'notification delivered');
    expect(a.streams.size).toBe(0);

    // Sequential normal calls should reuse a single leased stream.
    expect(await cli.call('test.lease', 'normal', 'a')).toBe('A');
    expect(await cli.call('test.lease', 'normal', 'b')).toBe('B');
    expect(await cli.call('test.lease', 'normal', 'c')).toBe('C');
    expect(a.streams.size).toBe(1);

    await cli.close();
    await srv.closed;
  });

  it('falls back to the shared lane when maxStreams is exhausted', async () => {
    const fb = new FacetBuilder('test.pool', '1.0.0', { id: 16 });
    fb.service('S').method('hold', T.uint, T.uint);
    const sc = makeSchema('s', '1.0.0', [fb.build()]);

    const releases: Array<() => void> = [];
    const [a, b] = memLeasedPair();
    const [srv, cli] = await Promise.all([
      Session.accept(b, {
        schema: sc,
        params: { maxStreams: 2, maxConcurrentCalls: 10 },
        handlers: {
          'test.pool': {
            hold: (n: number) =>
              new Promise<number>((resolve) => {
                releases.push(() => resolve(n * 10));
              }),
          },
        },
      }),
      Session.connect(a),
    ]);

    const p1 = cli.call('test.pool', 'hold', 1);
    const p2 = cli.call('test.pool', 'hold', 2);
    const p3 = cli.call('test.pool', 'hold', 3); // falls back to shared lane
    await eventually(() => releases.length === 3, 'all 3 calls arrived');
    expect(a.streams.size).toBe(2);
    for (const r of releases) r();
    expect(await Promise.all([p1, p2, p3])).toEqual([10, 20, 30]);

    await cli.close();
    await srv.closed;
  });

  it('resets excess incoming streams above local maxStreams with resource_exhausted', async () => {
    const fb = new FacetBuilder('test.excess', '1.0.0', { id: 16 });
    fb.service('S').method('echo', T.string, T.string);
    const sc = makeSchema('s', '1.0.0', [fb.build()]);

    const [a, b] = memLeasedPair();
    const [srv, cli] = await Promise.all([
      Session.accept(b, { schema: sc, params: { maxStreams: 1 } }),
      Session.connect(a),
    ]);

    const s1: Stream = await a.openStream();
    const s2: Stream = await a.openStream();
    let s2Closed: { code: number; remote: boolean; reset: boolean } | undefined;
    s1.start({ message: () => {}, error: () => {}, close: () => {} });
    s2.start({
      message: () => {},
      error: () => {},
      close: (info) => {
        s2Closed = info;
      },
    });
    await eventually(() => s2Closed !== undefined, 'excess stream reset');
    expect(s2Closed).toEqual({ code: Status.resource_exhausted, remote: true, reset: true });
    s1.closeWrite();
    s2.closeWrite();

    await cli.close();
    await srv.closed;
  });

  it('shrinks idle leased streams after 30 s while keeping 2 warm', async () => {
    const clock = new FakeClock();
    const fb = new FacetBuilder('test.shrink', '1.0.0', { id: 16 });
    fb.service('S').method('hold', T.uint, T.uint);
    const sc = makeSchema('s', '1.0.0', [fb.build()]);

    const releases: Array<() => void> = [];
    const [a, b] = memLeasedPair();
    const [srv, cli] = await Promise.all([
      Session.accept(b, {
        schema: sc,
        clock,
        params: { maxStreams: 5 },
        handlers: {
          'test.shrink': {
            hold: (n: number) =>
              new Promise<number>((resolve) => {
                releases.push(() => resolve(n));
              }),
          },
        },
      }),
      Session.connect(a, { clock }),
    ]);

    const calls = [1, 2, 3, 4].map((n) => cli.call('test.shrink', 'hold', n));
    await eventually(() => releases.length === 4, '4 calls arrived');
    expect(a.streams.size).toBe(4);
    for (const r of releases) r();
    await Promise.all(calls);

    // Advance 35 s: 2 excess streams should be write-closed, 2 stay open.
    await clock.advance(35_000);
    await flush();
    const openCount = [...a.streams].filter((s) => !s.closed).length;
    expect(openCount).toBe(2);

    await cli.close();
    await srv.closed;
  });

  it('resets a leased stream when Cancel goes unanswered for cancelGiveUpMs', async () => {
    const clock = new FakeClock();
    const fb = new FacetBuilder('test.cancel', '1.0.0', { id: 16 });
    fb.service('S').method('hang', T.unit, T.unit);
    const sc = makeSchema('s', '1.0.0', [fb.build()]);

    const [a, b] = memLeasedPair();
    const [srv, cli] = await Promise.all([
      Session.accept(b, {
        schema: sc,
        clock,
        handlers: {
          'test.cancel': {
            hang: () => new Promise(() => {}), // ignores signal and never resolves
          },
        },
      }),
      Session.connect(a, { clock, cancelGiveUpMs: 500 }),
    ]);

    const call = cli.open('test.cancel', 'hang');
    await eventually(() => srv.openCalls === 1, 'call started on server');
    for (const s of b.streams) s.drop = true; // the server's Error(cancelled) never arrives
    call.cancel();
    await expect(call.result()).rejects.toMatchObject({ status: Status.cancelled });

    await clock.advance(500);
    await flush();
    // Stream should have been resetWrite'd.
    const [st] = [...a.streams];
    expect(st.closed).toBe(true);

    // After another 500 ms, the reset timer releases the held call count.
    await clock.advance(500);
    await flush();
    expect(cli.openCalls).toBe(0);

    await cli.close();
    await srv.closed;
  });
});

describe('webTransportConn mock framing', () => {
  function fakeWT(): { client: WebTransportLike; server: WebTransportLike } {
    type PairStream = { a: WebTransportBidiStreamLike; b: WebTransportBidiStreamLike };
    function makeStreamPair(): PairStream {
      const makePipe = () => {
        const q: Uint8Array[] = [];
        let waiter: ((v: { value?: Uint8Array; done: boolean }) => void) | undefined;
        let closed = false;
        let aborted: unknown;
        return {
          readable: {
            getReader() {
              return {
                read() {
                  if (q.length > 0) return Promise.resolve({ value: q.shift()!, done: false });
                  if (aborted !== undefined) return Promise.reject(aborted);
                  if (closed) return Promise.resolve({ done: true });
                  return new Promise<{ value?: Uint8Array; done: boolean }>((r) => (waiter = r));
                },
                async cancel(reason?: unknown) {
                  aborted = reason ?? 0;
                  waiter?.({ done: true });
                  waiter = undefined;
                },
                releaseLock() {},
              };
            },
          },
          writable: {
            getWriter() {
              return {
                async write(chunk: Uint8Array) {
                  const copy = chunk.slice();
                  if (waiter) {
                    const w = waiter;
                    waiter = undefined;
                    w({ value: copy, done: false });
                  } else {
                    q.push(copy);
                  }
                },
                async close() {
                  closed = true;
                  if (waiter) {
                    const w = waiter;
                    waiter = undefined;
                    w({ done: true });
                  }
                },
                async abort(reason?: unknown) {
                  aborted = reason ?? 0;
                  if (waiter) {
                    const w = waiter;
                    waiter = undefined;
                    w({ done: true });
                  }
                },
                releaseLock() {},
              };
            },
          },
        };
      };
      const p1 = makePipe();
      const p2 = makePipe();
      return {
        a: { readable: p1.readable, writable: p2.writable },
        b: { readable: p2.readable, writable: p1.writable },
      };
    }

    interface FakePeer {
      wt: WebTransportLike;
      setOther(o: FakePeer): void;
      pushIncoming(s: WebTransportBidiStreamLike): void;
      remoteClosed(info?: { closeCode?: number; reason?: string }): void;
    }
    const makePeer = (): FakePeer => {
      const incoming: WebTransportBidiStreamLike[] = [];
      let waiter: ((v: { value?: WebTransportBidiStreamLike; done: boolean }) => void) | undefined;
      let closedDone = false;
      let closeResolve!: (v: { closeCode?: number; reason?: string }) => void;
      const closed = new Promise<{ closeCode?: number; reason?: string }>((r) => (closeResolve = r));
      let other!: FakePeer;
      const wt: WebTransportLike = {
        ready: Promise.resolve(),
        closed,
        incomingBidirectionalStreams: {
          getReader() {
            return {
              read() {
                if (incoming.length) return Promise.resolve({ value: incoming.shift()!, done: false });
                if (closedDone) return Promise.resolve({ done: true });
                return new Promise((r) => (waiter = r));
              },
              async cancel() {
                closedDone = true;
                waiter?.({ done: true });
                waiter = undefined;
              },
            };
          },
        },
        async createBidirectionalStream() {
          const pair = makeStreamPair();
          other.pushIncoming(pair.b);
          return pair.a;
        },
        close(info) {
          if (closedDone) return;
          closedDone = true;
          closeResolve(info ?? { closeCode: 0, reason: '' });
          waiter?.({ done: true });
          waiter = undefined;
          other.remoteClosed(info);
        },
      };
      return {
        wt,
        setOther(o: FakePeer) {
          other = o;
        },
        pushIncoming(s: WebTransportBidiStreamLike) {
          if (waiter) {
            const w = waiter;
            waiter = undefined;
            w({ value: s, done: false });
          } else {
            incoming.push(s);
          }
        },
        remoteClosed(info?: { closeCode?: number; reason?: string }) {
          if (closedDone) return;
          closedDone = true;
          closeResolve(info ?? { closeCode: 0, reason: '' });
          waiter?.({ done: true });
          waiter = undefined;
        },
      };
    };

    const c = makePeer();
    const s = makePeer();
    c.setOther(s);
    s.setOther(c);
    return { client: c.wt, server: s.wt };
  }

  it('runs a full Session with leased streams over webTransportConn', async () => {
    const { client, server } = fakeWT();
    const fb = new FacetBuilder('wt.echo', '1.0.0', { id: 16 });
    fb.service('E').method('echo', T.string, T.string);
    const sc = makeSchema('wt', '1.0.0', [fb.build()]);

    const cConn = webTransportConn(client, { role: 'client', lingerMs: 50 });
    const sConn = webTransportConn(server, { role: 'server', lingerMs: 50 });

    const [srv, cli] = await Promise.all([
      Session.accept(sConn, { schema: sc, handlers: { 'wt.echo': { echo: (x: string) => `wt:${x}` } } }),
      Session.connect(cConn),
    ]);

    expect(await cli.call('wt.echo', 'echo', 'hello')).toBe('wt:hello');
    await cli.close();
    await srv.closed;
  });
});
