// Session tests over the in-memory binding (TS client <-> TS server).
import { describe, expect, it } from 'vitest';
import * as lib from '../src/index.js';
import { FacetBuilder, Session, SparrowError, Status, T, field, makeSchema, memPair, stream, type SessionOptions } from '../src/index.js';
import { encodeMessage, decodeMessage } from '../src/wire.js';
import { clientHandlers, facets, runClientSuite, serverHandlers } from './fixture/interop.mjs';
import { FakeClock } from './helpers/clock.js';
import { eventually, never } from './helpers/wait.js';

function errOf(p: Promise<unknown>): Promise<SparrowError> {
  return p.then(
    () => {
      throw new Error('expected an error');
    },
    (e) => e as SparrowError,
  );
}

async function pair(srvOpts: SessionOptions = {}, cliOpts: SessionOptions = {}) {
  const f = facets(lib);
  const sh = serverHandlers(lib);
  const [a, b] = memPair();
  const [srv, cli] = await Promise.all([
    Session.accept(b, { schema: f.serverSchema, handlers: sh.handlers, ...srvOpts }),
    Session.connect(a, { schema: f.clientSchema, handlers: clientHandlers(), ...cliOpts }),
  ]);
  return { srv, cli, f, sh, a, b };
}

describe('session over mem', () => {
  it('runs the interop suite (TS client -> TS server)', async () => {
    const { srv, cli } = await pair();
    const done = await runClientSuite(cli, lib);
    expect(done.length).toBeGreaterThan(15);
    await cli.close();
    await srv.closed;
  });

  it('handshake: principal, client schema, params', async () => {
    const { srv, cli } = await pair(
      { authenticate: (h) => (h.auth?.credentials === 'secret' ? 'user:alice' : Promise.reject(new Error('bad'))), params: { maxConcurrentCalls: 7 } },
      { auth: { scheme: 'bearer', credentials: 'secret' }, params: { idleTimeoutMs: 20000 } },
    );
    expect(srv.principal).toBe('user:alice');
    expect(srv.peerSchema?.facets[0].name).toBe('interop.client');
    expect(cli.peerSchema?.facets[0].name).toBe('interop.test');
    expect(cli.limits.peer.maxConcurrentCalls).toBe(7);
    expect(srv.limits.peer.idleTimeoutMs).toBe(20000);
    expect(cli.sessionId?.length).toBe(16);
    await srv.close();
    const info = await cli.closed;
    expect(info.code).toBe(Status.going_away);
  });

  it('rejects a bad credential with GoAway(unauthenticated)', async () => {
    const f = facets(lib);
    const [a, b] = memPair();
    const srvP = Session.accept(b, { schema: f.serverSchema, authenticate: () => Promise.reject(new Error('no')) });
    srvP.catch(() => {});
    const err = await errOf(Session.connect(a, { auth: { scheme: 'bearer', credentials: 'x' } }));
    expect(err).toBeInstanceOf(SparrowError);
    expect(err.status).toBe(Status.unauthenticated);
    expect(err.notDispatched).toBe(true);
  });

  it('rejects an unsupported version with the server versions', async () => {
    const [a, b] = memPair();
    const got: unknown[] = [];
    Session.accept(b, {}).catch(() => {});
    a.start({ message: (m) => got.push(decodeMessage(m)), error: () => {}, close: () => {} });
    a.send(encodeMessage({ kind: 0, versions: [9], caps: {}, auth: null, knownSchema: null, clientSchema: null, params: {}, optimistic: false }));
    await eventually(() => got.length > 0, 'GoAway');
    expect(got[0]).toMatchObject({ kind: 9, status: Status.unsupported_version, versions: [1] });
  });

  it('rejects params below the minimums with GoAway(invalid_argument)', async () => {
    const f = facets(lib);
    const [a, b] = memPair();
    Session.accept(b, { schema: f.serverSchema }).catch(() => {});
    const err = await errOf(Session.connect(a, { params: { maxMessageSize: 100 } }));
    expect(err.status).toBe(Status.invalid_argument);
  });

  it('the server calls the client facet', async () => {
    const { srv, cli } = await pair();
    expect(await srv.call('interop.client', 'greet', 'srv')).toBe('hello, srv');
    const got: unknown[] = [];
    for await (const v of srv.stream('interop.client', 'count', 3)) got.push(v);
    expect(got).toEqual([1, 2, 3]);
    await cli.close();
  });

  it('optimistic start with a current cache', async () => {
    const f = facets(lib);
    const [a, b] = memPair();
    const srvP = Session.accept(b, { schema: f.serverSchema, handlers: serverHandlers(lib).handlers });
    const cli = await Session.connect(a, { knownSchema: f.serverSchema, optimistic: true });
    const r = await cli.call('interop.test', 'echo', 'early');
    expect(r).toBe('early');
    const srv = await srvP;
    expect(cli.welcome?.serverSchema.form).toBe(0);
    await srv.close();
  });

  it('optimistic start with a stale cache: GoAway(schema_mismatch), calls not dispatched', async () => {
    const f = facets(lib);
    const stale = makeSchema('interop.server', '0.9.0', [f.server]);
    const [a, b] = memPair();
    let ran = false;
    Session.accept(b, { schema: f.serverSchema, handlers: { 'interop.test': { echo: () => ((ran = true), 'x') } } }).catch(() => {});
    const cli = await Session.connect(a, { knownSchema: stale, optimistic: true });
    const err = await errOf(cli.call('interop.test', 'echo', 'early'));
    expect(err).toBeInstanceOf(SparrowError);
    expect(err.status).toBe(Status.schema_mismatch);
    expect(err.notDispatched).toBe(true);
    expect(ran).toBe(false);
  });

  it('GoAway drains running calls and refuses new ones', async () => {
    const { srv, cli } = await pair();
    const slow = cli.call('interop.test', 'slow', 30);
    await eventually(() => srv.openCalls === 1, 'the call to start');
    srv.goAway(Status.going_away, 'deploy', 1000);
    await eventually(() => cli.isDraining, 'the GoAway to arrive');
    const late = await errOf(cli.call('interop.test', 'echo', 'late'));
    expect(late.status).toBe(Status.going_away);
    expect(late.notDispatched).toBe(true);
    expect(await slow).toBe(null);
    const info = await cli.closed;
    expect(info.code).toBe(Status.going_away);
    expect(cli.goAwayReceived?.retryAfterMs).toBe(1000);
  });

  it('maxConcurrentCalls: calls beyond the limit wait for a slot; the callee refuses excess', async () => {
    const { srv, cli } = await pair({ params: { maxConcurrentCalls: 2 } });
    const t0 = Date.now();
    const rs = await Promise.all([1, 2, 3, 4].map(() => cli.call('interop.test', 'slow', 50)));
    expect(rs).toEqual([null, null, null, null]);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(95);
    await srv.close();
  });

  it('maxMessageSize: a too large request fails locally; a too large response becomes Error', async () => {
    const { srv, cli } = await pair({ params: { maxMessageSize: 16384 } }, { params: { maxMessageSize: 16384 } });
    const err = await errOf(cli.call('interop.test', 'echo', 'x'.repeat(20000)));
    expect(err.status).toBe(Status.message_too_large);
    expect(err.notDispatched).toBe(true);
    // The server answers its own oversized output with Error(message_too_large).
    const err2 = await errOf(srv.call('interop.client', 'greet', 'y'.repeat(16374)));
    expect(err2.status).toBe(Status.message_too_large);
    expect(await cli.call('interop.test', 'echo', 'ok')).toBe('ok');
    await cli.close();
  });

  it('a message above the read limit closes the session with message_too_large', async () => {
    const [a, b] = memPair();
    const f = facets(lib);
    const srvP = Session.accept(b, { schema: f.serverSchema, params: { maxMessageSize: 16384 } });
    const cli = await Session.connect(a, {});
    await srvP;
    // Bypass the client's own check by writing a raw oversized Request.
    a.send(new Uint8Array(20000).fill(0x60));
    const info = await cli.closed;
    expect(info.code).toBe(Status.message_too_large);
  });

  it('idle sessions stay alive with Ping/Pong and close when the peer goes silent (fake clock)', async () => {
    const clock = new FakeClock();
    const { srv, cli, a } = await pair({ params: { idleTimeoutMs: 20_000 }, clock }, { clock });
    const kinds = (l: Uint8Array[], from: number) => l.slice(from).map((m) => decodeMessage(m).kind);
    const [ca, sb] = [a.sent.length, (srv as any).conn.sent.length];
    await clock.advance(60_000);
    expect(cli.isOpen && srv.isOpen).toBe(true);
    // The client pings after half the idle timeout without traffic, the server answers.
    expect(kinds(a.sent, ca).filter((k) => k === 7).length).toBeGreaterThanOrEqual(5);
    expect(kinds((srv as any).conn.sent, sb).filter((k) => k === 8).length).toBeGreaterThanOrEqual(5);
    a.drop = true; // the client's messages (Pongs included) vanish
    await clock.advance(19_000);
    expect(srv.isOpen).toBe(true);
    await clock.advance(6_000);
    const info = await srv.closed;
    expect(info.code).toBe(Status.unavailable);
  });

  it('a Cancel left unanswered: the caller gives up after 5 s and closes the session after 30 s (fake clock)', async () => {
    const clock = new FakeClock();
    const [a, b] = memPair();
    const f = facets(lib);
    // A server whose handler ignores the Cancel, and that never answers it: a raw handler would answer,
    // so drop the server's messages for the call once it has started.
    const srvP = Session.accept(b, { schema: f.serverSchema, handlers: { 'interop.test': { slow: () => new Promise(() => {}) } }, clock });
    const cli = await Session.connect(a, { clock });
    const srv = await srvP;
    const call = cli.open('interop.test', 'slow', 1);
    const res = call.result();
    res.catch(() => {});
    await eventually(() => srv.openCalls === 1, 'the call to start');
    b.drop = true; // the server's Error(cancelled) never arrives
    call.cancel();
    expect((await errOf(res)).status).toBe(Status.cancelled);
    await clock.advance(4_000);
    expect(cli.openCalls).toBe(1); // still counted (7.5: shared lane)
    await clock.advance(26_500);
    const info = await cli.closed;
    expect(info.code).toBe(Status.protocol_error);
  });

  it('a SchemaUpdate the peer does not ack closes the session with schema_mismatch (fake clock)', async () => {
    const clock = new FakeClock();
    const { srv, cli, f } = await pair({ clock }, { clock, onPeerSchemaUpdate: () => new Promise(() => {}) });
    const b = new FacetBuilder('interop.extra', '1.0.0', { id: 17 });
    b.service('Extra').method('twice', T.string, T.string);
    const upd = srv.updateSchema(makeSchema('interop.server', '1.1.0', [f.server, b.build()]));
    upd.catch(() => {});
    await clock.advance(9_000);
    expect(srv.isOpen).toBe(true);
    await clock.advance(2_000);
    expect((await srv.closed).code).toBe(Status.schema_mismatch);
    expect((await cli.closed).code).toBe(Status.schema_mismatch);
    await expect(upd).rejects.toThrow();
  });

  it('deadlines: the callee answers deadline_exceeded, the caller cancels when its own timer fires (fake clock)', async () => {
    const clock = new FakeClock();
    const { srv, cli } = await pair({ clock }, { clock });
    const p = cli.call('interop.test', 'slow', 1_000_000, { timeoutMs: 5_000 });
    p.catch(() => {});
    await eventually(() => srv.openCalls === 1, 'the call to start');
    await clock.advance(5_000);
    expect((await errOf(p)).status).toBe(Status.deadline_exceeded);
    await eventually(() => srv.openCalls === 0 && cli.openCalls === 0, 'the call to end on both sides');
    await cli.close();
  });

  it('byte streams larger than the credit window flow both ways', async () => {
    const { srv, cli } = await pair();
    const down = (await cli.call('interop.test', 'download', 1 << 20)) as Uint8Array;
    expect(down.length).toBe(1 << 20);
    expect(down[257]).toBe(1);
    expect(await cli.call('interop.test', 'upload', new Uint8Array(1 << 20).fill(7))).toBe(1 << 20);
    // Chunk by chunk, with credit granted as each chunk is taken.
    const cc = cli.open('interop.test', 'download', 300_000);
    let n = 0;
    for await (const chunk of cc.byteChunks(0)) n += chunk.length;
    expect(n).toBe(300_000);
    await cc.result().catch(() => {});
    await eventually(() => srv.openCalls === 0 && cli.openCalls === 0, 'the calls to end');
    await cli.close();
  });

  it('credit 0: the callee waits for a Credit, which the caller grants when it starts reading', async () => {
    const { cli } = await pair();
    const cc = cli.stream('interop.test', 'count', 5, { credit: 0 });
    const got: unknown[] = [];
    for await (const v of cc) got.push(v);
    expect(got).toEqual([1, 2, 3, 4, 5]);
    expect((await cli.call('interop.test', 'download', 100_000, { credit: 0 }) as Uint8Array).length).toBe(100_000);
    await cli.close();
  });

  it('schema updates: the peer applies the delta and acks; new methods are callable', async () => {
    const { srv, cli, f } = await pair();
    const b = new FacetBuilder('interop.extra', '1.0.0', { id: 17 });
    b.service('Extra').method('twice', T.string, T.string);
    const extra = b.build();
    const updated = makeSchema('interop.server', '1.1.0', [f.server, extra]);
    (srv as any).router.handle('interop.extra', 'twice', (s: string) => s + s);
    await srv.updateSchema(updated);
    expect(cli.peerEpoch).toBe(1);
    expect(await cli.call('interop.extra', 'twice', 'ab')).toBe('abab');
    await cli.close();
  });

  it('6.6 rule 1: answers that use IDs of an unacked epoch wait, even when the request used them', async () => {
    let release!: () => void;
    const acked = new Promise<void>((r) => (release = r));
    const { srv, cli, f } = await pair({}, { onPeerSchemaUpdate: () => acked });
    const b = new FacetBuilder('interop.extra', '1.0.0', { id: 17 });
    b.errorCode('extra_failed');
    const svc = b.service('Extra');
    svc.method('twice', T.string, T.string);
    svc.method('fail', T.string, T.unit, { errors: ['extra_failed'] });
    let ran = 0;
    (srv as any).router.handle('interop.extra', 'twice', (s: string) => (ran++, s + s));
    (srv as any).router.handle('interop.extra', 'fail', (s: string) => {
      ran++;
      throw new SparrowError('extra_failed', s, { type: 'string', value: 'why' });
    });
    const upd = srv.updateSchema(makeSchema('interop.server', '1.1.0', [f.server, b.build()]));
    await eventually(() => cli.peerEpoch === 1, 'the client to apply the update');
    // The client calls the new facet before it acks (its hook has not returned).
    let twice: unknown;
    let failed: SparrowError | undefined;
    void cli.call('interop.extra', 'twice', 'ab').then((v) => (twice = v));
    void errOf(cli.call('interop.extra', 'fail', 'no')).then((e) => (failed = e));
    await eventually(() => ran === 2, 'both handlers to run');
    await never(() => twice !== undefined || failed !== undefined, 'an answer before SchemaAck');
    release();
    await upd;
    await eventually(() => twice !== undefined && failed !== undefined, 'the held answers');
    expect(twice).toBe('abab');
    expect([failed!.code, failed!.rawMessage, (failed!.details as { value: unknown }).value]).toEqual(['extra_failed', 'no', 'why']);
    await cli.close();
  });

  it('a client without a schema cannot be called; unknown methods are unimplemented', async () => {
    const f = facets(lib);
    const [a, b] = memPair();
    const [srv, cli] = await Promise.all([Session.accept(b, { schema: f.serverSchema }), Session.connect(a, {})]);
    const e1 = await errOf(srv.call('interop.client', 'greet', 'x'));
    expect(e1.status).toBe(Status.unimplemented);
    // no handler registered on the server for echo
    const e2 = await errOf(cli.call('interop.test', 'echo', 'x'));
    expect(e2.status).toBe(Status.unimplemented);
    expect(e2.remote).toBe(true);
    await cli.close();
  });

  it('handler failures: plain exceptions become unknown, wrong outputs internal', async () => {
    const b = new FacetBuilder('t.err', '1.0.0', { id: 16 });
    const s = b.service('S');
    s.method('boom', T.unit, T.unit);
    s.method('wrong', T.unit, T.string);
    s.method('items', T.unit, stream(T.uint));
    const P = b.struct('P', [field('a', T.uint)]);
    s.method('needs', P, T.unit);
    const sc = makeSchema('t', '1', [b.build()]);
    const [x, y] = memPair();
    const [srv, cli] = await Promise.all([
      Session.accept(y, {
        schema: sc,
        handlers: {
          't.err': {
            boom: () => {
              throw new Error('kaput');
            },
            wrong: () => 42,
            items: async function* () {
              yield 1;
              throw new SparrowError('not_found', 'gone');
            },
            needs: () => null,
          },
        },
      }),
      Session.connect(x, {}),
    ]);
    const e1 = await errOf(cli.call('t.err', 'boom'));
    expect([e1.status, e1.rawMessage]).toEqual([Status.unknown, 'kaput']);
    const e2 = await errOf(cli.call('t.err', 'wrong'));
    expect(e2.status).toBe(Status.internal);
    const got: unknown[] = [];
    const e3 = await (async () => {
      for await (const v of cli.stream('t.err', 'items')) got.push(v);
    })().catch((e) => e);
    expect(got).toEqual([1]);
    expect(e3.status).toBe(Status.not_found);
    const e4 = await errOf(cli.call('t.err', 'needs', {}));
    expect(e4.status).toBe(Status.invalid_argument);
    expect(e4.notDispatched).toBe(true);
    await srv.close();
  });

  it('breaking a stream loop early cancels the call', async () => {
    const { srv, cli } = await pair();
    for await (const v of cli.stream('interop.test', 'count', 100000)) {
      if (v === 3) break;
    }
    // The session is fine afterwards.
    expect(await cli.call('interop.test', 'echo', 'after')).toBe('after');
    await eventually(() => srv.openCalls === 0, 'the cancelled call to end');
    await cli.close();
  });

  it('closing the transport fails open calls with unavailable after the linger (fake clock)', async () => {
    const clock = new FakeClock();
    const { cli, srv, a } = await pair({ clock }, { clock });
    const p = cli.call('interop.test', 'slow', 5000);
    p.catch(() => {});
    await eventually(() => cli.openCalls === 1 && srv.openCalls === 1, 'the call to start');
    a.kill();
    await clock.advance(1_000);
    const e = await errOf(p);
    expect(e.status).toBe(Status.unavailable);
    expect(cli.openCalls + srv.openCalls).toBe(0);
  });
});
