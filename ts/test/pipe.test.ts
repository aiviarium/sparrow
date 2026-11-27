// The pipe binding: framing over Node streams, and a real child process (the
// started process is the client) running the interop suite on its stdio.
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import * as lib from '../src/index.js';
import { Session, Status } from '../src/index.js';
import { pipeConn, spawn } from '../src/transport/pipe.js';
import { encodeVarint } from '../src/wire.js';
import { clientHandlers, facets, runClientSuite, serverHandlers } from './fixture/interop.mjs';

const clientMain = fileURLToPath(new URL('./fixture/client-main.mjs', import.meta.url));

function streamPair() {
  const c2s = new PassThrough();
  const s2c = new PassThrough();
  return { cli: pipeConn(s2c, c2s, { lingerMs: 100 }), srv: pipeConn(c2s, s2c, { lingerMs: 100 }), c2s, s2c };
}

describe('pipe binding', () => {
  it('runs the interop suite over a pair of in-process byte streams', async () => {
    const f = facets(lib);
    const { cli: a, srv: b } = streamPair();
    const [srv, cli] = await Promise.all([
      Session.accept(b, { schema: f.serverSchema, handlers: serverHandlers(lib).handlers }),
      Session.connect(a, { schema: f.clientSchema, handlers: clientHandlers() }),
    ]);
    const done = await runClientSuite(cli, lib);
    expect(done).toContain('callback');
    await cli.close();
    const info = await srv.closed;
    expect(info.code).toBe(Status.going_away); // the status travels in GoAway only
  });

  it('reassembles messages split across chunks and accepts a non-minimal length prefix', async () => {
    const f = facets(lib);
    const c2s = new PassThrough();
    const s2c = new PassThrough();
    const srvP = Session.accept(pipeConn(c2s, s2c), { schema: f.serverSchema, handlers: serverHandlers(lib).handlers });
    const hello = lib.wire.encodeMessage({ kind: 0, versions: [1], caps: {}, auth: null, knownSchema: null, clientSchema: null, params: {}, optimistic: false });
    // length as a 4-byte varint, written one byte at a time
    const prefix = new Uint8Array([0x80, 0, 0, hello.length]);
    for (const b of [...prefix, ...hello]) c2s.write(Uint8Array.of(b));
    const got = await new Promise<Uint8Array>((res) => s2c.once('data', (d: Buffer) => res(new Uint8Array(d))));
    expect(got[0] >> 6).toBeLessThan(2); // the server writes the shortest prefix
    srvP.catch(() => {});
    c2s.end();
  });

  it('rejects a frame above maxMessageSize before reading it', async () => {
    const f = facets(lib);
    const c2s = new PassThrough();
    const s2c = new PassThrough();
    const srvP = Session.accept(pipeConn(c2s, s2c), { schema: f.serverSchema, params: { maxMessageSize: 16384 } });
    srvP.catch(() => {});
    c2s.write(encodeVarint(1 << 24)); // no body follows
    const err = await srvP.catch((e) => e);
    expect(err.status).toBe(Status.message_too_large);
  });

  it('spawns a child process that is the Sparrow client on its stdio', async () => {
    const f = facets(lib);
    const { conn, child } = spawn(process.execPath, [clientMain], { stdio: ['pipe', 'pipe', 'inherit'] });
    const exit = new Promise<number | null>((res) => child.on('exit', (code) => res(code)));
    const srv = await Session.accept(conn, {
      schema: f.serverSchema,
      handlers: serverHandlers(lib).handlers,
      authenticate: (h) => (h.auth?.credentials === 'interop' ? 'ext:ts' : Promise.reject(new Error('bad credential'))),
    });
    expect(srv.principal).toBe('ext:ts');
    // The server calls the client's facet while the client runs its suite.
    expect(await srv.call('interop.client', 'greet', 'parent')).toBe('hello, parent');
    const info = await srv.closed;
    expect(info.code).toBe(Status.going_away);
    expect(await exit).toBe(0);
  });
});
