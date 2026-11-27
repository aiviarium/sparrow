// The pipe binding through faults: writes chopped into 1-7 bytes, stalls,
// the byte stream ending in the middle of a message or of the handshake,
// and a child process dying in the middle of a call. Calls end with the
// right status and no session counts a call afterwards.
import { PassThrough, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import * as lib from '../src/index.js';
import { Session, SparrowError, Status, type SessionOptions } from '../src/index.js';
import { pipeConn, spawn } from '../src/transport/pipe.js';
import { clientHandlers, facets, runClientSuite, serverHandlers } from './fixture/interop.mjs';
import { FakeClock } from './helpers/clock.js';
import { rng } from './helpers/fuzz.js';
import { eventually } from './helpers/wait.js';

const childNode = fileURLToPath(new URL('./fixture/child-node.mjs', import.meta.url));

/** One direction of a byte stream with faults between its writer and its reader. */
class FaultyStream {
  readonly readable = new PassThrough();
  readonly writable: Writable;
  private queue: Uint8Array[] = [];
  private stalled = false;
  private ended = false;
  private cut = false;
  private pumping = false;
  /** Bytes delivered so far. */
  delivered = 0;
  /** End the stream (as a clean close) once this many bytes were delivered; -1 never. */
  cutAfter = -1;
  /** Cut every write into pieces of 1 to chop bytes (0: as written). */
  chop = 0;

  constructor(private readonly r = rng(1)) {
    this.writable = new Writable({
      write: (chunk: Buffer, _enc, cb) => {
        if (!this.cut) this.queue.push(new Uint8Array(chunk));
        void this.pump();
        cb();
      },
      final: (cb) => {
        this.ended = true;
        void this.pump();
        cb();
      },
    });
  }

  stall(): void {
    this.stalled = true;
  }

  resume(): void {
    this.stalled = false;
    void this.pump();
  }

  private async pump(): Promise<void> {
    if (this.pumping) return;
    this.pumping = true;
    try {
      while (!this.stalled && !this.cut && this.queue.length) {
        let b = this.queue.shift()!;
        if (this.chop > 0 && b.length > 1) {
          const k = 1 + this.r.n(this.chop);
          if (k < b.length) {
            this.queue.unshift(b.subarray(k));
            b = b.subarray(0, k);
          }
        }
        if (this.cutAfter >= 0 && this.delivered + b.length >= this.cutAfter) {
          this.readable.write(b.subarray(0, this.cutAfter - this.delivered));
          this.delivered = this.cutAfter;
          this.cut = true;
          this.queue = [];
          this.readable.end();
          return;
        }
        this.readable.write(b);
        this.delivered += b.length;
        if (this.chop > 0 && this.r.f() < 0.05) await new Promise((res) => setImmediate(res));
      }
      if (this.ended && !this.queue.length && !this.cut && !this.stalled) this.readable.end();
    } finally {
      this.pumping = false;
    }
  }
}

function faultyPair(seed: number) {
  const c2s = new FaultyStream(rng(seed));
  const s2c = new FaultyStream(rng(seed + 1));
  return {
    c2s,
    s2c,
    cli: pipeConn(s2c.readable, c2s.writable, { lingerMs: 50 }),
    srv: pipeConn(c2s.readable, s2c.writable, { lingerMs: 50 }),
  };
}

async function sessions(seed: number, srvOpts: SessionOptions = {}, cliOpts: SessionOptions = {}, tune?: (p: ReturnType<typeof faultyPair>) => void) {
  const f = facets(lib);
  const p = faultyPair(seed);
  tune?.(p);
  const [srv, cli] = await Promise.all([
    Session.accept(p.srv, { schema: f.serverSchema, handlers: serverHandlers(lib).handlers, lingerMs: 50, ...srvOpts }),
    Session.connect(p.cli, { schema: f.clientSchema, handlers: clientHandlers(), lingerMs: 50, ...cliOpts }),
  ]);
  return { ...p, srv, cli };
}

function errOf(p: Promise<unknown>): Promise<SparrowError> {
  return p.then(
    () => {
      throw new Error('expected an error');
    },
    (e) => e as SparrowError,
  );
}

const idle = (...ss: Session[]) => ss.every((s) => s.openCalls === 0);

describe('pipe binding under faults', () => {
  it('writes chopped into 1-7 bytes: every call shape works', async () => {
    const { srv, cli } = await sessions(7, {}, {}, (p) => {
      p.c2s.chop = 7;
      p.s2c.chop = 7;
    });
    const done = await runClientSuite(cli, lib);
    expect(done.length).toBeGreaterThan(15);
    expect(((await cli.call('interop.test', 'download', 200_000)) as Uint8Array).length).toBe(200_000);
    expect(await cli.call('interop.test', 'upload', new Uint8Array(200_000))).toBe(200_000);
    await eventually(() => idle(srv, cli), 'no call counted');
    await cli.close();
    await srv.closed;
  });

  it('a stall shorter than the idle timeout is a delay; a longer one ends both sessions (fake clock)', async () => {
    const clock = new FakeClock();
    const { srv, cli, c2s } = await sessions(8, { clock, params: { idleTimeoutMs: 20_000 } }, { clock });
    c2s.stall();
    const short = cli.call('interop.test', 'echo', 'delayed');
    await clock.advance(5_000);
    c2s.resume();
    expect(await short).toBe('delayed');
    const running = cli.call('interop.test', 'slow', 1_000_000);
    running.catch(() => {});
    await eventually(() => srv.openCalls === 1, 'the call to start');
    c2s.stall(); // the client's messages, Pings included, stop arriving
    await clock.advance(25_000);
    expect((await srv.closed).code).toBe(Status.unavailable);
    await clock.advance(1_000);
    expect((await errOf(running)).status).toBe(Status.unavailable);
    expect(idle(srv, cli)).toBe(true);
  });

  it('the stream ends in the middle of a message: the call fails with unavailable, nothing stays counted', async () => {
    const { srv, cli, s2c } = await sessions(9);
    const base = s2c.delivered;
    s2c.cutAfter = base + 100_000; // inside a Bytes message of the download
    const err = await errOf(cli.call('interop.test', 'download', 1 << 20));
    expect(err.status).toBe(Status.unavailable);
    await cli.closed;
    await srv.closed;
    expect(idle(srv, cli)).toBe(true);
  });

  it('the stream ends at any point of the handshake: both sides settle, nothing hangs', async () => {
    const f = facets(lib);
    for (let cut = 1; cut < 400; cut += 7) {
      for (const dir of ['c2s', 's2c'] as const) {
        const p = faultyPair(cut);
        p[dir].cutAfter = cut;
        const srvP = Session.accept(p.srv, { schema: f.serverSchema, handlers: serverHandlers(lib).handlers, lingerMs: 20 });
        const cliP = Session.connect(p.cli, { schema: f.clientSchema, lingerMs: 20 });
        const [s, c] = await Promise.allSettled([srvP, cliP]);
        for (const r of [s, c]) if (r.status === 'rejected') expect(r.reason).toBeInstanceOf(SparrowError);
        if (c.status === 'fulfilled') await c.value.close();
        if (s.status === 'fulfilled') await s.value.close();
        if (c.status === 'fulfilled') await c.value.closed;
        if (s.status === 'fulfilled') await s.value.closed;
      }
    }
  });

  it('a child process dies in the middle of a call and of a download: unavailable at once, the child reaped', async () => {
    for (const what of ['block', 'download'] as const) {
      let stderr = '';
      const { conn, child, exited } = spawn(process.execPath, [childNode], { stdio: ['pipe', 'pipe', 'pipe'], killAfterMs: 2000 });
      child.stderr!.on('data', (d) => (stderr += d));
      const srv = await Session.accept(conn, { lingerMs: 50 });
      let err: SparrowError;
      if (what === 'block') {
        const p = srv.call('child', 'block');
        await eventually(() => stderr.includes('started'), 'the child to start the call');
        child.kill('SIGKILL');
        err = await errOf(p);
      } else {
        const cc = srv.open('child', 'download', 8 << 20);
        let n = 0;
        err = await (async () => {
          for await (const x of cc.byteChunks(0)) {
            n += x.length;
            if (n >= 64 << 10 && child.exitCode === null && !child.killed) child.kill('SIGKILL');
          }
          throw new Error('the download finished');
        })().catch((e) => e as SparrowError);
      }
      expect(err).toBeInstanceOf(SparrowError);
      expect(err.status).toBe(Status.unavailable);
      expect((await srv.closed).code).toBe(Status.unavailable);
      expect(srv.openCalls).toBe(0);
      expect((await exited).signal).toBe('SIGKILL');
    }
  });
});
