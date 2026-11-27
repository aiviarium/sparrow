// An in-memory binding for tests: two connected Conns with a shared lane
// only. Messages are delivered asynchronously and in order; close carries
// its status code and reason to the peer, like a WebSocket close frame.

import { Status } from '../status.js';
import { ConnClosedError, type CloseInfo, type Conn, type ConnHandlers } from '../transport.js';
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
