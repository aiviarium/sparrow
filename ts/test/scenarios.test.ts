// The behaviour scenarios of test-vectors/scenarios, executed against a real
// server Session over the in-memory binding (shared lane only: lease:<n>
// messages run on the shared lane, stream_idle and streams_open do not
// apply). A scripted raw client sends the client's messages and checks every
// message and expectation of the server side, as go/session/scenario_test.go
// does.
import { describe, expect, it } from 'vitest';
import { canonical, decode, fromHex, toHex } from '../src/cbor.js';
import { SchemaState, deltaOf, schemaOf, type Schema } from '../src/schema.js';
import { Session, SparrowError, Router } from '../src/session.js';
import { Codec } from '../src/value.js';
import { Status } from '../src/status.js';
import { memPair, type MemConnection } from '../src/transport/mem.js';
import { decodeMessage, encodeMessage, type Message } from '../src/wire.js';
import { byName, fromTJ, loadScenarios, type TJ } from './helpers/tjson.js';

function schemaVector(name: string): Schema {
  const v = byName().get(name);
  if (v.type === 'schema') return schemaOf(fromTJ(v.input));
  return SchemaState.create(schemaVector(v.from)).apply(deltaOf(fromTJ(v.delta))).schema;
}

class AsyncQueue<T> {
  private items: T[] = [];
  private waiters: ((v: T) => void)[] = [];
  push(v: T) {
    const w = this.waiters.shift();
    if (w) w(v);
    else this.items.push(v);
  }
  shift(timeoutMs: number): Promise<T | undefined> {
    if (this.items.length) return Promise.resolve(this.items.shift());
    return new Promise((res) => {
      const t = setTimeout(() => {
        const i = this.waiters.indexOf(w);
        if (i >= 0) this.waiters.splice(i, 1);
        res(undefined);
      }, timeoutMs);
      const w = (v: T) => {
        clearTimeout(t);
        res(v);
      };
      this.waiters.push(w);
    });
  }
  unshift(v: T) {
    this.items.unshift(v);
  }
}

class Host {
  dispatched = new Set<number>();
  logs: string[] = [];
  events = new AsyncQueue<unknown>();

  router(): Router {
    const r = new Router();
    const rec = (f: (input: any, ctx: any) => unknown) => (input: any, ctx: any) => {
      this.dispatched.add(ctx.callId);
      return f(input, ctx);
    };
    r.handle(16, 0, rec((s) => s));
    r.handle(
      16,
      1,
      rec(async function* (n: number) {
        for (let i = 1; i <= n; i++) yield i;
      }),
    );
    r.handle(
      16,
      2,
      rec(async (items: AsyncIterable<number>) => {
        let sum = 0;
        for await (const v of items) {
          if (v > 1000) throw new SparrowError(Status.out_of_range, `item ${v} exceeds 1000`);
          sum += v;
        }
        return sum;
      }),
    );
    r.handle(
      16,
      3,
      rec(async (u: { data: number }, ctx) => (await ctx.bytes(u.data)).length),
    );
    r.handle(
      16,
      4,
      rec((s: string) => {
        this.logs.push(s);
      }),
    );
    r.handle(
      16,
      5,
      rec(async (_: null, ctx) => {
        for (;;) {
          const v = await Promise.race([
            this.events.shift(60_000),
            new Promise((_, rej) => ctx.signal.addEventListener('abort', () => rej(ctx.signal.reason), { once: true })),
          ]);
          if (v === null || v === undefined) return;
          await ctx.send(v);
        }
      }),
    );
    r.handle(
      16,
      6,
      rec((s: string, ctx) => {
        const t = ctx.session.localSchema.facets[0].types.find((x: any) => x.id === 65);
        return { [t.fields[0].name]: s };
      }),
    );
    return r;
  }
}

interface Step {
  step: number;
  from?: string;
  stream?: string;
  cbor?: string;
  compare?: string;
  crossed?: boolean;
  expect?: string;
  call_id?: number;
  half?: string;
  reason?: string;
  raw?: Uint8Array;
  sentEarly?: boolean;
}

class Run {
  host = new Host();
  cli: MemConnection;
  srvConn: MemConnection;
  srv?: Session;
  srvErr?: unknown;
  srvDone: Promise<void>;
  inbox = new AsyncQueue<Uint8Array | null>();
  calls = new Map<number, number>();
  update?: Schema;
  hostSchema: Schema;
  serverClosed = false;

  constructor(readonly sc: TJ) {
    [this.cli, this.srvConn] = memPair({ lingerMs: 50 });
    this.hostSchema = schemaVector(sc.given.schema);
    if (sc.given.delta) this.update = schemaVector(sc.given.delta);
    this.cli.start({
      message: (b) => this.inbox.push(b),
      error: () => {},
      close: () => {
        this.inbox.push(null);
        void this.cli.close(Status.ok, ''); // finish this side too, so the server's close need not linger
      },
    });
    this.srvDone = Session.accept(this.srvConn, {
      schema: this.hostSchema,
      handlers: this.host.router(),
      params: sc.given.server_params ?? {},
    }).then(
      (s) => {
        this.srv = s;
        void s.closed.then(() => (this.serverClosed = true));
      },
      (e) => {
        this.srvErr = e;
        this.serverClosed = true;
      },
    );
  }

  send(b: Uint8Array) {
    try {
      this.cli.send(b);
    } catch (e) {
      if (!this.closes()) throw e;
    }
  }

  closes(): boolean {
    return this.sc.steps.some((s: Step) => s.expect === 'session_closed' || s.expect === 'transport_closed');
  }

  async recvRaw(want: number): Promise<Uint8Array> {
    for (;;) {
      const b = await this.inbox.shift(5000);
      if (b === undefined) throw new Error(`no message of kind ${want} from the server`);
      if (b === null) throw new Error(`connection closed, want kind ${want}`);
      const k = b[1] === 0x18 ? b[2] : b[1] & 0x1f;
      if (k === 7 || k === 8 || (k === 24 && want !== 24)) continue;
      return b;
    }
  }

  async handshake() {
    this.send(encodeMessage({ kind: 0, versions: [1], caps: {}, auth: null, knownSchema: null, clientSchema: null, params: {}, optimistic: false }));
    const w = decodeMessage(await this.recvRaw(1));
    if (w.kind !== 1) throw new Error('want Welcome');
    this.send(encodeMessage({ kind: 2, schemaHash: w.serverSchema.hash }));
    await this.srvDone;
    if (this.srvErr) throw this.srvErr;
  }

  clientSend(st: Step) {
    const m = decodeMessage(st.raw!);
    if (m.kind === 16) this.calls.set(m.callId, m.methodId);
    this.send(st.raw!);
  }

  trigger(st: Step) {
    if (st.sentEarly) return;
    st.sentEarly = true;
    const m = decodeMessage(st.raw!);
    switch (m.kind) {
      case 3:
        void this.srv!.updateSchema(this.update!).catch(() => {});
        break;
      case 9:
        if (m.status === Status.going_away) this.srv!.goAway(m.status, m.reason, m.retryAfterMs);
        break;
      case 18:
        if (this.calls.get(m.callId) === 5) {
          // Decode with the server's current schema: the handler re-encodes it.
          const codec = new Codec(this.srv!.localSchema!.facets.find((f) => f.id === 16)!);
          this.host.events.push(codec.decode(10, m.value));
        }
        break;
      case 19:
        if (this.calls.get(m.callId) === 5) this.host.events.push(null);
        break;
    }
  }

  async serverRecv(st: Step) {
    const want = decodeMessage(st.raw!);
    const got = await this.recvRaw(want.kind);
    const gm = decodeMessage(got);
    expect(gm.kind, `step ${st.step}: kind of ${toHex(got)}`).toBe(want.kind);
    if (st.compare === 'status') {
      expect(statusOf(gm), `step ${st.step}`).toBe(statusOf(want));
      if ('callId' in gm) expect(gm.callId).toBe((want as { callId: number }).callId);
      return;
    }
    if (want.kind === 1 && gm.kind === 1) {
      const g = { ...gm, sessionId: new Uint8Array(16) };
      const w = { ...want, sessionId: new Uint8Array(16) };
      expect(toHex(canonical(encodeMessage(g)))).toBe(toHex(canonical(encodeMessage(w))));
      return;
    }
    expect(toHex(canonical(got)), `step ${st.step}`).toBe(toHex(canonical(st.raw!)));
  }

  async quietFor(callId: number, ms: number) {
    const deadline = Date.now() + ms;
    const putBack: Uint8Array[] = [];
    for (;;) {
      const left = deadline - Date.now();
      if (left <= 0) break;
      const b = await this.inbox.shift(left);
      if (b === undefined || b === null) break;
      const m = decodeMessage(b);
      if (m.kind === 7 || m.kind === 8 || m.kind === 24) continue;
      if (!('callId' in m) || m.callId === callId) throw new Error(`unexpected message ${toHex(b)}`);
      putBack.push(b);
    }
    for (const b of putBack.reverse()) this.inbox.unshift(b);
  }

  async expectStep(i: number, st: Step) {
    const eventually = async (f: () => boolean, what: string) => {
      const end = Date.now() + 5000;
      while (!f()) {
        if (Date.now() > end) throw new Error(`step ${st.step}: ${what}`);
        await new Promise((r) => setTimeout(r, 2));
      }
    };
    switch (st.expect) {
      case 'session_ready':
        await this.srvDone;
        if (this.srvErr) throw this.srvErr;
        break;
      case 'dispatched':
        await eventually(() => this.host.dispatched.has(st.call_id!), `call ${st.call_id} not dispatched`);
        break;
      case 'not_dispatched':
        await new Promise((r) => setTimeout(r, 20));
        expect(this.host.dispatched.has(st.call_id!)).toBe(false);
        break;
      case 'call_ended':
        await this.srvDone;
        if (!this.srv) return;
        await eventually(() => !(this.srv as any).calls.has(st.call_id), `call ${st.call_id} still open`);
        break;
      case 'half_finished':
        await this.srvDone;
        await eventually(() => {
          const c = (this.srv as any).calls.get(st.call_id);
          if (!c) return true;
          return st.half === 'caller' ? c.callerDone : c.calleeDone;
        }, `${st.half} half of ${st.call_id} not finished`);
        break;
      case 'stream_idle':
      case 'streams_open':
        break; // no leased streams on this binding
      case 'held_back':
        if (st.reason === 'schema_ack') {
          for (let j = i + 1; j < this.sc.steps.length; j++) {
            const nx: Step = this.sc.steps[j];
            if (nx.from === 'server' && nx.raw) {
              const m = decodeMessage(nx.raw);
              if (m.kind === 18 && m.callId === st.call_id) {
                this.trigger(nx);
                break;
              }
            }
          }
        }
        await this.quietFor(st.call_id!, 100);
        break;
      case 'no_reply':
      case 'discarded':
        await this.quietFor(st.call_id!, 50);
        break;
      case 'session_closed':
      case 'transport_closed':
        await this.srvDone;
        await eventually(() => this.serverClosed, 'server session still open');
        break;
      case 'violation':
      case 'client_retries':
        break;
      default:
        throw new Error(`unknown expectation ${st.expect}`);
    }
  }

  async run() {
    const steps: Step[] = this.sc.steps;
    for (const s of steps) if (s.cbor) s.raw = fromHex(s.cbor);
    if (!String(this.sc.given.session).startsWith('none')) await this.handshake();
    for (let i = 0; i < steps.length; i++) {
      const st = steps[i];
      if (st.from === 'client') {
        if (st.sentEarly) continue;
        this.clientSend(st);
      } else if (st.from === 'server') {
        for (let j = i + 1; j < steps.length; j++) {
          const nx = steps[j];
          if (nx.expect) continue;
          if (nx.from !== 'client' || !nx.crossed) break;
          this.trigger(st);
          this.clientSend(nx);
          nx.sentEarly = true;
        }
        this.trigger(st);
        await this.serverRecv(st);
      } else if (st.expect) {
        await this.expectStep(i, st);
      }
    }
    if (this.srv) await this.srv.close();
    await this.srvDone;
  }
}


function statusOf(m: Message): number {
  if (m.kind === 20 || m.kind === 9 || m.kind === 23) return m.status;
  return 0;
}

describe('behaviour scenarios (server session over mem)', () => {
  for (const [f, sc] of loadScenarios()) {
    it(f, async () => {
      await new Run(sc).run();
    });
  }
  it('decodes scenario values', () => {
    expect(decode(fromHex('f6'))).toBeNull();
  });
});
