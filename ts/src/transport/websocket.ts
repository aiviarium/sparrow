// The WebSocket binding (spec 4.6): subprotocol sparrow.v1, one binary
// WebSocket message per Sparrow message (no length prefix, no stream
// header), shared lane only. The close frame carries 1000 for ok, otherwise
// 4000 + the core status code, and a reason of at most 123 bytes.
//
// Works with the browser WebSocket API, Node's global WebSocket (Node 22+),
// and server-side sockets of the `ws` package (which expose the same
// addEventListener/send/close interface).

import { MAX_WEBSOCKET_REASON, Status, fromWebSocketCloseCode, truncateReason, webSocketCloseCode } from '../status.js';
import { ConnClosedError, type Conn, type ConnHandlers } from '../transport.js';
import { DEFAULTS, FramingError, TooLargeError } from '../wire.js';

/** The subprotocol a client offers and a server selects. */
export const SUBPROTOCOL = 'sparrow.v1';

/** The part of the WebSocket interface this binding uses. */
export interface WebSocketLike {
  binaryType: string;
  readonly readyState: number;
  readonly protocol?: string;
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: string, listener: (ev: any) => void, opts?: unknown): void;
}

export interface WebSocketConnOptions {
  /** How long close waits for the peer's close frame; default 2 s. */
  lingerMs?: number;
}

class WebSocketConn implements Conn {
  readonly binding = 'websocket';
  private h?: ConnHandlers;
  private limit: number = DEFAULTS.maxMessageSize;
  private sendClosed = false;
  private notified = false;
  private early: Uint8Array[] = [];
  private earlyClose?: { code: number; reason: string };
  private readonly onClosedEv: Promise<void>;
  private markClosed!: () => void;

  constructor(
    private readonly ws: WebSocketLike,
    private readonly opts: WebSocketConnOptions,
  ) {
    this.onClosedEv = new Promise((r) => (this.markClosed = r));
    ws.binaryType = 'arraybuffer';
    ws.addEventListener('message', (ev: { data: unknown }) => this.onData(ev.data));
    ws.addEventListener('close', (ev: { code: number; reason: string }) => {
      this.markClosed();
      const code = fromWebSocketCloseCode(ev.code) ?? Status.unavailable;
      if (!this.h) {
        this.earlyClose = { code, reason: ev.reason };
        return;
      }
      this.finish(code, ev.reason ?? '', !this.sendClosed);
    });
    ws.addEventListener('error', () => {
      /* a close event follows */
    });
  }

  get closed(): boolean {
    return this.sendClosed || this.notified;
  }

  private onData(d: unknown): void {
    if (this.notified) return;
    let b: Uint8Array;
    if (d instanceof ArrayBuffer) b = new Uint8Array(d);
    else if (ArrayBuffer.isView(d)) b = new Uint8Array(d.buffer, d.byteOffset, d.byteLength).slice();
    else if (Array.isArray(d)) {
      // ws 'fragments' binary type
      const parts = d as Uint8Array[];
      const n = parts.reduce((a, p) => a + p.length, 0);
      b = new Uint8Array(n);
      let off = 0;
      for (const p of parts) {
        b.set(p, off);
        off += p.length;
      }
    } else {
      this.deliverError(new FramingError('a text WebSocket message (Sparrow uses binary messages only)'));
      return;
    }
    if (!this.h) {
      this.early.push(b);
      return;
    }
    if (b.length > this.limit) {
      this.deliverError(new TooLargeError(b.length, this.limit));
      return;
    }
    if (b.length === 0) {
      this.deliverError(new FramingError('an empty WebSocket message'));
      return;
    }
    this.h.message(b);
  }

  private deliverError(e: Error): void {
    this.h?.error(e);
  }

  start(h: ConnHandlers): void {
    this.h = h;
    const e = this.early;
    this.early = [];
    for (const b of e) this.onData(b);
    if (this.earlyClose) this.finish(this.earlyClose.code, this.earlyClose.reason, true);
  }

  setReadLimit(n: number): void {
    this.limit = n;
  }

  send(msg: Uint8Array): void {
    if (this.sendClosed || this.notified || this.ws.readyState !== 1) throw new ConnClosedError();
    this.ws.send(msg);
  }

  private finish(code: number, reason: string, remote: boolean): void {
    if (this.notified) return;
    this.notified = true;
    this.h?.close({ code, reason, remote });
  }

  async close(code: number, reason: string): Promise<void> {
    if (!this.sendClosed) {
      this.sendClosed = true;
      try {
        this.ws.close(webSocketCloseCode(code <= 31 ? code : Status.internal), truncateReason(reason, MAX_WEBSOCKET_REASON));
      } catch {
        // already closing
      }
      let t: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([this.onClosedEv, new Promise<void>((r) => (t = setTimeout(r, this.opts.lingerMs ?? 2000)))]);
      if (t) clearTimeout(t);
    }
    this.finish(code, reason, false);
  }
}

/** A connection on an open WebSocket (client or server side). */
export function webSocketConn(ws: WebSocketLike, opts: WebSocketConnOptions = {}): Conn {
  return new WebSocketConn(ws, opts);
}

export interface ConnectWebSocketOptions extends WebSocketConnOptions {
  /** The WebSocket constructor; default globalThis.WebSocket (browsers, Node 22+). */
  WebSocket?: new (url: string, protocols?: string | string[]) => WebSocketLike;
  /** Gives up opening after this long; default 10 s. */
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** Opens a WebSocket with subprotocol sparrow.v1 and returns its connection once open. */
export function connectWebSocket(url: string, opts: ConnectWebSocketOptions = {}): Promise<Conn> {
  const Ctor = opts.WebSocket ?? (globalThis as { WebSocket?: ConnectWebSocketOptions['WebSocket'] }).WebSocket;
  if (!Ctor) return Promise.reject(new Error('websocket: no WebSocket implementation; pass opts.WebSocket'));
  return new Promise((resolve, reject) => {
    const ws = new Ctor(url, [SUBPROTOCOL]);
    ws.binaryType = 'arraybuffer';
    const conn = new WebSocketConn(ws, opts);
    let done = false;
    const t = setTimeout(() => fail(new Error('websocket: open timed out')), opts.timeoutMs ?? 10_000);
    const fail = (e: Error) => {
      if (done) return;
      done = true;
      clearTimeout(t);
      try {
        ws.close();
      } catch {
        // ignore
      }
      reject(e);
    };
    opts.signal?.addEventListener('abort', () => fail(new Error('websocket: aborted')), { once: true });
    ws.addEventListener('open', () => {
      if (done) return;
      if (ws.protocol !== undefined && ws.protocol !== SUBPROTOCOL) {
        fail(new Error(`websocket: the server selected subprotocol ${JSON.stringify(ws.protocol)}, not ${SUBPROTOCOL}`));
        return;
      }
      done = true;
      clearTimeout(t);
      resolve(conn);
    });
    ws.addEventListener('error', (ev: { message?: string }) => fail(new Error(`websocket: cannot open: ${ev?.message ?? 'error'}`)));
    ws.addEventListener('close', (ev: { code: number; reason: string }) => fail(new Error(`websocket: closed before opening (${ev.code} ${ev.reason})`)));
  });
}
