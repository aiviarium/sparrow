// An in-memory binding for tests: two connected Conns with a shared lane
// (memPair) or with leased streams (memLeasedPair). Messages are delivered
// asynchronously and in order; close carries its status code and reason to the
// peer, like a WebSocket close frame.

import { Status } from '../status.js';
import {
  ConnClosedError,
  type CloseInfo,
  type Conn,
  type ConnHandlers,
  type Stream,
  type StreamCloseInfo,
  type StreamHandlers,
} from '../transport.js';
import { DEFAULTS, TooLargeError } from '../wire.js';

class MemConn implements Conn {
  readonly binding = 'mem';
  peer!: MemConn;
  private h?: ConnHandlers;
  private early: (() => void)[] = [];
  private limit: number = DEFAULTS.maxMessageSize;
  private ended = false;
  private notified = false;
  private sendClosed = false;
  private readonly onClosed: Promise<void>;
  private markClosed!: () => void;
  /** Every message this side sent, for tests. */
  readonly sent: Uint8Array[] = [];
  /** Set to drop instead of deliver (a broken network). */
  drop = false;

  constructor(private readonly linger: number) {
    this.onClosed = new Promise((r) => (this.markClosed = r));
  }

  get closed(): boolean {
    return this.sendClosed || this.notified;
  }

  start(h: ConnHandlers): void {
    this.h = h;
    const e = this.early;
    this.early = [];
    for (const f of e) f();
  }

  private run(f: () => void): void {
    if (this.h) queueMicrotask(f);
    else this.early.push(f);
  }

  setReadLimit(n: number): void {
    this.limit = n;
  }

  send(msg: Uint8Array): void {
    if (this.sendClosed || this.notified) throw new ConnClosedError();
    const b = msg.slice();
    this.sent.push(b);
    if (this.drop) return;
    this.peer.receive(b);
  }

  private receive(b: Uint8Array): void {
    this.run(() => {
      if (this.ended || this.notified) return;
      if (b.length > this.limit) {
        this.h!.error(new TooLargeError(b.length, this.limit));
        return;
      }
      this.h!.message(b);
    });
  }

  private peerFinished(info: CloseInfo): void {
    this.run(() => {
      this.ended = true;
      this.notify(info);
    });
  }

  private notify(info: CloseInfo): void {
    if (this.notified) return;
    this.notified = true;
    this.markClosed();
    this.h?.close(info);
  }

  async close(code: number, reason: string): Promise<void> {
    if (!this.sendClosed) {
      this.sendClosed = true;
      this.peer.peerFinished({ code, reason, remote: true });
      if (code !== Status.protocol_error && !this.ended) {
        await Promise.race([this.onClosed, new Promise((r) => setTimeout(r, this.linger))]);
      }
    }
    this.ended = true;
    this.notify({ code, reason, remote: false });
  }

  /** Simulates the network vanishing: both sides see the connection end. */
  kill(): void {
    this.peer.peerFinished({ code: Status.unavailable, reason: 'connection lost', remote: true });
    this.peerFinished({ code: Status.unavailable, reason: 'connection lost', remote: true });
  }
}

export type MemConnection = MemConn;

/** Returns two connected in-memory connections: [client side, server side]. */
export function memPair(opts: { lingerMs?: number } = {}): [MemConnection, MemConnection] {
  const a = new MemConn(opts.lingerMs ?? 200);
  const b = new MemConn(opts.lingerMs ?? 200);
  a.peer = b;
  b.peer = a;
  return [a, b];
}

class MemStream implements Stream {
  peer!: MemStream;
  private h?: StreamHandlers;
  private early: (() => void)[] = [];
  private limit: number = DEFAULTS.maxMessageSize;
  private writeClosed = false;
  private readClosed = false;
  private notified = false;
  drop = false;

  constructor(private readonly conn: MemLeasedConn) {}

  get closed(): boolean {
    return this.writeClosed || this.notified;
  }

  setReadLimit(n: number): void {
    this.limit = n;
  }

  start(h: StreamHandlers): void {
    this.h = h;
    const e = this.early;
    this.early = [];
    for (const f of e) f();
  }

  private run(f: () => void): void {
    if (this.h) queueMicrotask(f);
    else this.early.push(f);
  }

  send(msg: Uint8Array): void {
    if (this.writeClosed || this.notified || this.conn.closed) throw new ConnClosedError();
    const b = msg.slice();
    if (this.drop) return;
    this.peer.receive(b);
  }

  private receive(b: Uint8Array): void {
    this.run(() => {
      if (this.readClosed || this.notified) return;
      if (b.length > this.limit) {
        this.h!.error(new TooLargeError(b.length, this.limit));
        return;
      }
      this.h!.message(b);
    });
  }

  closeWrite(): void {
    if (this.writeClosed) return;
    this.writeClosed = true;
    this.peer.peerFinished({ code: Status.ok, remote: true, reset: false });
  }

  resetWrite(code: number): void {
    if (this.writeClosed) return;
    this.writeClosed = true;
    this.peer.peerFinished({ code: code <= 31 ? code : Status.internal, remote: true, reset: true });
  }

  reset(code: number): void {
    const c = code <= 31 ? code : Status.internal;
    const already = this.notified;
    this.writeClosed = true;
    this.readClosed = true;
    this.peer.peerFinished({ code: c, remote: true, reset: true });
    if (!already) this.notify({ code: c, remote: false, reset: true });
  }

  peerFinished(info: StreamCloseInfo): void {
    this.run(() => {
      this.readClosed = true;
      this.notify(info);
    });
  }

  forceClose(code: number): void {
    this.writeClosed = true;
    this.readClosed = true;
    this.notify({ code, remote: false, reset: false });
  }

  private notify(info: StreamCloseInfo): void {
    if (this.notified) return;
    this.notified = true;
    this.h?.close(info);
  }
}

class MemLeasedConn extends MemConn {
  override readonly binding = 'mem';
  readonly leases = true;
  private streamHandler?: (s: Stream) => void;
  private pendingStreams: MemStream[] = [];
  private streamLimit: number = DEFAULTS.maxMessageSize;
  readonly streams = new Set<MemStream>();

  override setReadLimit(n: number): void {
    super.setReadLimit(n);
    this.streamLimit = n;
    for (const s of this.streams) s.setReadLimit(n);
  }

  async openStream(): Promise<Stream> {
    if (this.closed) throw new ConnClosedError();
    const a = new MemStream(this);
    const b = new MemStream(this.peer as MemLeasedConn);
    a.peer = b;
    b.peer = a;
    a.setReadLimit(this.streamLimit);
    b.setReadLimit((this.peer as MemLeasedConn).streamLimit);
    this.streams.add(a);
    (this.peer as MemLeasedConn).streams.add(b);
    queueMicrotask(() => (this.peer as MemLeasedConn).deliverStream(b));
    return a;
  }

  onStream(handler: (stream: Stream) => void): void {
    this.streamHandler = handler;
    const p = this.pendingStreams;
    this.pendingStreams = [];
    for (const s of p) handler(s);
  }

  private deliverStream(s: MemStream): void {
    if (this.closed) {
      s.forceClose(Status.unavailable);
      return;
    }
    if (this.streamHandler) this.streamHandler(s);
    else this.pendingStreams.push(s);
  }

  override async close(code: number, reason: string): Promise<void> {
    await super.close(code, reason);
    for (const s of this.streams) s.forceClose(code);
  }

  override kill(): void {
    super.kill();
    for (const s of this.streams) s.peerFinished({ code: Status.unavailable, remote: true, reset: true });
    for (const s of (this.peer as MemLeasedConn).streams) s.peerFinished({ code: Status.unavailable, remote: true, reset: true });
  }
}

export type MemLeasedConnection = MemLeasedConn;

/** Returns two connected in-memory connections supporting leased streams: [client side, server side]. */
export function memLeasedPair(opts: { lingerMs?: number } = {}): [MemLeasedConnection, MemLeasedConnection] {
  const a = new MemLeasedConn(opts.lingerMs ?? 200);
  const b = new MemLeasedConn(opts.lingerMs ?? 200);
  a.peer = b;
  b.peer = a;
  return [a, b];
}
