// The WebSocket binding: a `ws` server in Node, the client through the
// WebSocket API (Node's global WebSocket where present, else the `ws` client).
import { WebSocketServer, WebSocket as WsWebSocket } from 'ws';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as lib from '../src/index.js';
import { Session, Status, type Conn } from '../src/index.js';
import { SUBPROTOCOL, connectWebSocket, webSocketConn, type WebSocketLike } from '../src/transport/websocket.js';
import { clientHandlers, facets, runClientSuite, serverHandlers } from './fixture/interop.mjs';

let wss: WebSocketServer;
let url = '';
const accepted: Conn[] = [];
const sessions: Promise<Session>[] = [];
const Ctor = ((globalThis as any).WebSocket ?? WsWebSocket) as any;

beforeAll(async () => {
  const f = facets(lib);
  wss = new WebSocketServer({
    port: 0,
    handleProtocols: (protocols) => (protocols.has(SUBPROTOCOL) ? SUBPROTOCOL : false),
    verifyClient: (info: { origin?: string }) => !info.origin || info.origin === 'http://localhost', // 4.6: check Origin
  });
  wss.on('connection', (ws) => {
    const conn = webSocketConn(ws as unknown as WebSocketLike);
    accepted.push(conn);
    const p = Session.accept(conn, { schema: f.serverSchema, handlers: serverHandlers(lib).handlers });
    p.catch(() => {});
    sessions.push(p);
  });
  await new Promise<void>((r) => wss.on('listening', () => r()));
  url = `ws://127.0.0.1:${(wss.address() as { port: number }).port}/sparrow/ws`;
});

afterAll(() => new Promise<void>((r) => wss.close(() => r())));

describe('websocket binding', () => {
  it('runs the interop suite', async () => {
    const f = facets(lib);
    const conn = await connectWebSocket(url, { WebSocket: Ctor });
    const cli = await Session.connect(conn, { schema: f.clientSchema, handlers: clientHandlers() });
    const done = await runClientSuite(cli, lib);
    expect(done).toContain('download');
    const srv = await sessions[sessions.length - 1];
    expect(await srv.call('interop.client', 'greet', 'ws')).toBe('hello, ws');
    await cli.close();
    const info = await srv.closed;
    expect(info.code).toBe(Status.going_away);
  });

  it('carries the status in the close frame (4000 + code)', async () => {
    const n = accepted.length;
    const conn = await connectWebSocket(url, { WebSocket: Ctor });
    // wait for the server side to exist
    while (accepted.length === n) await new Promise((r) => setTimeout(r, 5));
    const got = new Promise<{ code: number; reason: string }>((res) =>
      conn.start({ message: () => {}, error: () => {}, close: (i) => res(i) }),
    );
    await accepted[accepted.length - 1].close(Status.schema_mismatch, 'x'.repeat(300));
    const info = await got;
    expect(info.code).toBe(Status.schema_mismatch);
    expect(new TextEncoder().encode(info.reason).length).toBeLessThanOrEqual(123);
  });

  it('refuses a server that does not select sparrow.v1', async () => {
    const bad = new WebSocketServer({ port: 0, handleProtocols: () => false });
    await new Promise<void>((r) => bad.on('listening', () => r()));
    const u = `ws://127.0.0.1:${(bad.address() as { port: number }).port}/`;
    const err = await connectWebSocket(u, { WebSocket: Ctor }).catch((e) => e);
    expect(String(err)).toMatch(/subprotocol|closed|protocols|open/);
    await new Promise<void>((r) => bad.close(() => r()));
  });
});
