// Protocol rules checked against scripted raw peers over the in-memory binding.
import { describe, expect, it } from 'vitest';
import * as lib from '../src/index.js';
import { Session, Status, memPair } from '../src/index.js';
import { decodeMessage, encodeMessage, type Message } from '../src/wire.js';
import { encode } from '../src/cbor.js';
import { facets, serverHandlers } from './fixture/interop.mjs';

class Raw {
  inbox: Message[] = [];
  closed = false;
  private wake?: () => void;
  constructor(readonly conn: ReturnType<typeof memPair>[0]) {
    conn.start({
      message: (b) => {
        this.inbox.push(decodeMessage(b));
        this.wake?.();
      },
      error: () => {},
      close: () => {
        this.closed = true;
        this.wake?.();
      },
    });
  }
  send(m: Message | Uint8Array) {
    this.conn.send(m instanceof Uint8Array ? m : encodeMessage(m));
  }
  async next(kind: number, ms = 2000): Promise<Message> {
    const end = Date.now() + ms;
    for (;;) {
      const i = this.inbox.findIndex((m) => m.kind === kind);
      if (i >= 0) return this.inbox.splice(i, 1)[0];
      if (this.closed || Date.now() > end) throw new Error(`no message of kind ${kind}; got ${JSON.stringify(this.inbox.map((m) => m.kind))}`);
      await new Promise<void>((r) => {
        this.wake = r;
        setTimeout(r, 20);
      });
    }
  }
}

const hello: Message = { kind: 0, versions: [1], caps: {}, auth: null, knownSchema: null, clientSchema: null, params: {}, optimistic: false };

async function rawClient() {
  const f = facets(lib);
  const [a, b] = memPair({ lingerMs: 20 });
  const srvP = Session.accept(b, { schema: f.serverSchema, handlers: serverHandlers(lib).handlers });
  srvP.catch(() => {});
  const raw = new Raw(a);
  raw.send(hello);
  const w = await raw.next(1);
  return { raw, srvP, hash: (w as Extract<Message, { kind: 1 }>).serverSchema.hash, f };
}

const str = (s: string) => encode(s);

describe('server rules', () => {
  it('a call on the shared lane before Ready gets Error(not_ready)', async () => {
    const { raw, hash } = await rawClient();
    raw.send({ kind: 16, callId: 2, facetId: 16, methodId: 0, metadata: new Map(), input: str('x') });
    expect(await raw.next(20)).toMatchObject({ callId: 2, status: Status.not_ready });
    raw.send({ kind: 2, schemaHash: hash });
    raw.send({ kind: 16, callId: 4, facetId: 16, methodId: 0, metadata: new Map(), input: str('y') });
    expect(await raw.next(17)).toMatchObject({ callId: 4 });
  });

  it('Ready naming another schema closes with GoAway(schema_mismatch)', async () => {
    const { raw } = await rawClient();
    raw.send({ kind: 2, schemaHash: new Uint8Array(33) });
    expect(await raw.next(9)).toMatchObject({ status: Status.schema_mismatch });
  });

  it("a Request with the server's parity is a protocol_error", async () => {
    const { raw, hash } = await rawClient();
    raw.send({ kind: 2, schemaHash: hash });
    raw.send({ kind: 16, callId: 3, facetId: 16, methodId: 0, metadata: new Map(), input: str('x') });
    expect(await raw.next(9)).toMatchObject({ status: Status.protocol_error });
  });

  it('a Request for an open call ID is a protocol_error', async () => {
    const { raw, hash } = await rawClient();
    raw.send({ kind: 2, schemaHash: hash });
    const slow = encode(10000);
    raw.send({ kind: 16, callId: 2, facetId: 16, methodId: 7, metadata: new Map(), input: slow });
    raw.send({ kind: 16, callId: 2, facetId: 16, methodId: 7, metadata: new Map(), input: slow });
    expect(await raw.next(9)).toMatchObject({ status: Status.protocol_error });
  });

  it('unknown kinds: 48-63 are ignored, 0-47 close with protocol_error', async () => {
    const { raw, hash } = await rawClient();
    raw.send({ kind: 2, schemaHash: hash });
    raw.send(encode([50, 'ignored']));
    raw.send({ kind: 16, callId: 2, facetId: 16, methodId: 0, metadata: new Map(), input: str('still') });
    expect(await raw.next(17)).toMatchObject({ callId: 2 });
    raw.send(encode([40, 'fatal']));
    expect(await raw.next(9)).toMatchObject({ status: Status.protocol_error });
  });

  it('a notification-method Request with a call ID gets invalid_argument; Ping gets Pong', async () => {
    const { raw, hash, f } = await rawClient();
    raw.send({ kind: 2, schemaHash: hash });
    const log = f.server.services[0].methods.find((m: { name: string }) => m.name === 'log').id;
    raw.send({ kind: 16, callId: 2, facetId: 16, methodId: log, metadata: new Map(), input: str('x') });
    expect(await raw.next(20)).toMatchObject({ callId: 2, status: Status.invalid_argument });
    raw.send({ kind: 7, nonce: Number.MAX_SAFE_INTEGER });
    expect(await raw.next(8)).toMatchObject({ nonce: Number.MAX_SAFE_INTEGER });
  });

  it('an integer the message defines beyond 2^53 - 1 is a protocol_error (3.1)', async () => {
    for (const m of [
      [7, 2n ** 53n], // Ping nonce
      [24, 2, 2n ** 53n], // Credit amount
      [16, 2n ** 53n, 16, 0, new Map(), null], // call ID
      [16, 2, 16, 0, new Map([[32, 2n ** 53n]]), null], // deadline key
    ]) {
      const { raw, hash } = await rawClient();
      raw.send({ kind: 2, schemaHash: hash });
      raw.send(encode(m));
      expect(await raw.next(9)).toMatchObject({ status: Status.protocol_error });
    }
  });

  it('the deadline key makes the callee answer deadline_exceeded', async () => {
    const { raw, hash } = await rawClient();
    raw.send({ kind: 2, schemaHash: hash });
    raw.send({ kind: 16, callId: 2, facetId: 16, methodId: 7, metadata: new Map([[32, 30]]), input: encode(10000) });
    expect(await raw.next(20)).toMatchObject({ callId: 2, status: Status.deadline_exceeded });
  });

  it('no Hello within the timeout closes the connection', async () => {
    const [a, b] = memPair();
    const p = Session.accept(b, { helloTimeoutMs: 30 });
    const raw = new Raw(a);
    const e = await p.catch((x) => x);
    expect(e.status).toBe(Status.deadline_exceeded);
    void raw;
  });
});

describe('client rules', () => {
  it('a server that sends with no credit left gets Cancel(protocol_error)', async () => {
    const f = facets(lib);
    const [a, b] = memPair();
    const raw = new Raw(b);
    const cliP = Session.connect(a, {});
    const h = await raw.next(0);
    void h;
    const { encodeSchema, schemaHash } = lib.schema;
    const sc = f.serverSchema;
    const hash = schemaHash(sc);
    raw.send({ kind: 1, version: 1, caps: {}, sessionId: new Uint8Array(16), props: {}, serverSchema: { form: 2, hash, schema: encodeSchema(sc) }, params: {} });
    await raw.next(2);
    const cli = await cliP;
    const count = f.server.services[0].methods.find((m: { name: string }) => m.name === 'count').id;
    const call = cli.stream('interop.test', count, 10, { credit: 16 });
    const req = (await raw.next(16)) as Extract<Message, { kind: 16 }>;
    expect(req.metadata.get(35)).toBe(16);
    for (let i = 0; i < 6; i++) raw.send({ kind: 18, callId: req.callId, value: encode(i) }); // 4 bytes each: the fifth breaks the window
    expect(await raw.next(23)).toMatchObject({ callId: req.callId, status: Status.protocol_error });
    raw.send({ kind: 20, callId: req.callId, status: Status.cancelled, message: '', details: null });
    const err = await (async () => {
      for await (const v of call) void v;
    })().catch((e) => e);
    expect(err.status).toBe(Status.protocol_error);
  });

  it('a Welcome with params below the minimums is answered with GoAway(invalid_argument)', async () => {
    const f = facets(lib);
    const [a, b] = memPair();
    const raw = new Raw(b);
    const cliP = Session.connect(a, {});
    await raw.next(0);
    const { encodeSchema, schemaHash } = lib.schema;
    const sc = f.serverSchema;
    raw.send({
      kind: 1,
      version: 1,
      caps: {},
      sessionId: new Uint8Array(16),
      props: {},
      serverSchema: { form: 2, hash: schemaHash(sc), schema: encodeSchema(sc) },
      params: { sharedCredit: 100 },
    });
    expect(await raw.next(9)).toMatchObject({ status: Status.invalid_argument });
    expect((await cliP.catch((e) => e)).status).toBe(Status.invalid_argument);
  });
});
