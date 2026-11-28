// The WebTransport binding (spec 4.5): WebTransport over HTTP/3 with a
// shared lane (header 0x00) and leased bidirectional streams (header 0x01).
// Each message is length-prefixed with a QUIC varint (wire.frame /
// wire.FrameDecoder). Stream resets carry a core status code (0-255); session
// close carries a core status code and a reason up to 1024 bytes.

import { MAX_WEBTRANSPORT_REASON, Status, truncateReason } from '../status.js';
import {
  ConnClosedError,
  type CloseInfo,
  type Conn,
  type ConnHandlers,
  type Stream,
  type StreamCloseInfo,
  type StreamHandlers,
} from '../transport.js';
import {
  DEFAULTS,
  FrameDecoder,
  FramingError,
  HEADER_LEASED,
  HEADER_SHARED_LANE,
  classifyStreamHeader,
  frame,
  type Role,
} from '../wire.js';

export interface WebTransportHash {
  algorithm: 'sha-256';
  value: Uint8Array;
}

export interface WebTransportReadableLike {
  getReader(): {
    read(): Promise<{ value?: Uint8Array; done: boolean }>;
    cancel(reason?: unknown): Promise<void>;
    releaseLock(): void;
  };
}

export interface WebTransportWritableLike {
  getWriter(): {
    write(chunk: Uint8Array): Promise<void>;
    close(): Promise<void>;
    abort(reason?: unknown): Promise<void>;
    releaseLock(): void;
  };
}

export interface WebTransportBidiStreamLike {
  readonly readable: WebTransportReadableLike;
  readonly writable: WebTransportWritableLike;
}

export interface WebTransportLike {
  readonly ready: Promise<void>;
  readonly closed: Promise<{ closeCode?: number; reason?: string }>;
  readonly incomingBidirectionalStreams: {
    getReader(): {
      read(): Promise<{ value?: WebTransportBidiStreamLike; done: boolean }>;
      cancel(reason?: unknown): Promise<void>;
    };
  };
  createBidirectionalStream(): Promise<WebTransportBidiStreamLike>;
  close(closeInfo?: { closeCode?: number; reason?: string }): void;
}

export type WebTransportConstructor = new (
  url: string,
  options?: { serverCertificateHashes?: WebTransportHash[] },
) => WebTransportLike;

export interface WebTransportConnOptions {
  /** Peer role of this side ("client" opens shared lane 0x00; "server" accepts it). Default "client". */
  role?: Role;
  /** How long close waits for the peer to finish the shared lane; default 2 s. */
  lingerMs?: number;
  /** Maximum time to wait for the stream header byte on an incoming stream; default 10 s. */
  headerTimeoutMs?: number;
  /** Already-opened shared bidirectional stream (used internally by connectWebTransport). */
  sharedStream?: WebTransportBidiStreamLike;
}

export interface ConnectWebTransportOptions extends Omit<WebTransportConnOptions, 'role' | 'sharedStream'> {
  /** WebTransport constructor; defaults to globalThis.WebTransport. */
  WebTransport?: WebTransportConstructor;
  /** Pinned SHA-256 DER certificate hashes (for development self-signed certs). */
  serverCertificateHashes?: Uint8Array[];
  /** Gives up opening after this long; default 10 s. */
  timeoutMs?: number;
  signal?: AbortSignal;
}

function streamAbortReason(code: number): unknown {
  const c = code >= 0 && code <= 255 ? code : Status.internal;
  const WTE = (globalThis as { WebTransportError?: new (msg?: string, opts?: { streamErrorCode?: number }) => unknown })
    .WebTransportError;
  if (WTE) {
    try {
      return new WTE(`stream reset (${c})`, { streamErrorCode: c });
    } catch {
      // fallback to numeric code
    }
  }
  return c;
}

function extractStreamCode(err: unknown): number | undefined {
  if (typeof err === 'number' && Number.isInteger(err) && err >= 0 && err <= 255) return err;
  if (err && typeof err === 'object') {
    const code = (err as { streamErrorCode?: unknown }).streamErrorCode;
    if (typeof code === 'number' && Number.isInteger(code) && code >= 0 && code <= 255) return code;
  }
  return undefined;
}

function isResetError(err: unknown): boolean {
  if (typeof err === 'number') return true;
  if (err && typeof err === 'object') {
    if ('streamErrorCode' in err && (err as { streamErrorCode?: unknown }).streamErrorCode != null) return true;
    if ((err as { source?: unknown }).source === 'stream') return true;
  }
  return false;
}

class WTStream implements Stream {
  private readonly reader: ReturnType<WebTransportReadableLike['getReader']>;
  private readonly writer: ReturnType<WebTransportWritableLike['getWriter']>;
  private readonly decoder: FrameDecoder;
  private h?: StreamHandlers;
  private earlyMsgs: Uint8Array[] = [];
  private earlyErr?: Error;
  private earlyClose?: StreamCloseInfo;
  private hdrPending: boolean;
  private writeClosed = false;
  private readClosed = false;
  private resetFlag = false;
  private notified = false;
  private writeChain: Promise<void> = Promise.resolve();
  private readonly onReadDone: Promise<void>;
  private markReadDone!: () => void;

  constructor(
    private readonly conn: WTConn,
    raw: WebTransportBidiStreamLike,
    private readonly hdr: number,
    opener: boolean,
    limit: number,
    initialBytes?: Uint8Array,
  ) {
    this.hdrPending = opener;
    this.decoder = new FrameDecoder(limit);
    this.reader = raw.readable.getReader();
    this.writer = raw.writable.getWriter();
    this.onReadDone = new Promise((r) => (this.markReadDone = r));
    if (initialBytes && initialBytes.length > 0) {
      this.feedChunk(initialBytes);
    }
    void this.readLoop();
  }

  get closed(): boolean {
    return this.writeClosed || this.resetFlag || this.notified;
  }

  get readFinished(): Promise<void> {
    return this.onReadDone;
  }

  setReadLimit(n: number): void {
    this.decoder.maxMessageSize = n;
  }

  start(h: StreamHandlers): void {
    this.h = h;
    const msgs = this.earlyMsgs;
    this.earlyMsgs = [];
    for (const m of msgs) h.message(m);
    if (this.earlyErr) {
      const e = this.earlyErr;
      this.earlyErr = undefined;
      h.error(e);
    }
    if (this.earlyClose) {
      const c = this.earlyClose;
      this.earlyClose = undefined;
      this.notifyClose(c);
    }
  }

  send(msg: Uint8Array): void {
    if (this.writeClosed || this.resetFlag || this.notified || this.conn.closed) {
      throw new ConnClosedError();
    }
    const framed = frame(msg);
    let payload: Uint8Array;
    if (this.hdrPending) {
      this.hdrPending = false;
      payload = new Uint8Array(1 + framed.length);
      payload[0] = this.hdr;
      payload.set(framed, 1);
    } else {
      payload = framed;
    }
    this.writeChain = this.writeChain
      .then(() => this.writer.write(payload))
      .catch((err) => {
        if (!this.writeClosed && !this.resetFlag) {
          this.writeClosed = true;
          const code = extractStreamCode(err) ?? Status.unavailable;
          this.notifyClose({ code, remote: isResetError(err), reset: isResetError(err) });
        }
      });
  }

  closeWrite(): void {
    if (this.writeClosed || this.resetFlag) return;
    this.writeClosed = true;
    const sendHdr = this.hdrPending;
    this.hdrPending = false;
    this.writeChain = this.writeChain
      .then(async () => {
        if (sendHdr) await this.writer.write(Uint8Array.of(this.hdr));
        await this.writer.close();
      })
      .catch(() => {
        // stream already closed or reset
      });
  }

  resetWrite(code: number): void {
    if (this.writeClosed || this.resetFlag) return;
    this.writeClosed = true;
    this.resetFlag = true;
    this.hdrPending = false;
    void this.writer.abort(streamAbortReason(code)).catch(() => {});
  }

  reset(code: number): void {
    const already = this.notified;
    this.resetWrite(code);
    this.readClosed = true;
    this.markReadDone();
    void this.reader.cancel(streamAbortReason(code)).catch(() => {});
    if (!already) {
      this.notifyClose({ code: code <= 31 ? code : Status.internal, remote: false, reset: true });
    }
  }

  private deliverMessage(msg: Uint8Array): void {
    if (this.notified) return;
    if (this.h) this.h.message(msg);
    else this.earlyMsgs.push(msg);
  }

  private deliverError(err: Error): void {
    if (this.notified) return;
    if (this.h) this.h.error(err);
    else this.earlyErr ??= err;
  }

  private notifyClose(info: StreamCloseInfo): void {
    if (this.notified) return;
    this.notified = true;
    if (this.h) this.h.close(info);
    else this.earlyClose = info;
  }

  private feedChunk(chunk: Uint8Array): boolean {
    let msgs: Uint8Array[];
    try {
      msgs = this.decoder.push(chunk);
    } catch (e) {
      this.deliverError(e as Error);
      return false;
    }
    for (const m of msgs) this.deliverMessage(m);
    if (this.decoder.error) {
      this.deliverError(this.decoder.error);
      return false;
    }
    return true;
  }

  private async readLoop(): Promise<void> {
    try {
      for (;;) {
        const { value, done } = await this.reader.read();
        if (done) {
          this.readClosed = true;
          this.markReadDone();
          if (this.decoder.pending > 0) {
            this.deliverError(new FramingError('stream ended mid-message'));
            this.notifyClose({ code: Status.protocol_error, remote: true, reset: false });
          } else {
            this.notifyClose({ code: Status.ok, remote: true, reset: false });
          }
          return;
        }
        if (value && value.length > 0 && !this.feedChunk(value)) {
          this.readClosed = true;
          this.markReadDone();
          return;
        }
      }
    } catch (err) {
      this.readClosed = true;
      this.markReadDone();
      const reset = isResetError(err);
      const code = extractStreamCode(err) ?? Status.unavailable;
      this.notifyClose({ code, remote: true, reset });
    }
  }
}

class WTConn implements Conn {
  readonly binding = 'webtransport';
  readonly leases = true;

  private h?: ConnHandlers;
  private streamHandler?: (s: Stream) => void;
  private limit = DEFAULTS.maxMessageSize;
  private shared?: WTStream;
  private sharedOpened = false;
  private pendingStreams: WTStream[] = [];
  private trackedStreams = new Set<WTStream>();
  private sendClosed = false;
  private notified = false;
  private earlySharedMsgs: Uint8Array[] = [];
  private earlySharedErr?: Error;
  private earlyClose?: CloseInfo;
  private readonly role: Role;
  private readonly lingerMs: number;
  private readonly headerTimeoutMs: number;

  constructor(
    private readonly wt: WebTransportLike,
    opts: WebTransportConnOptions = {},
  ) {
    this.role = opts.role ?? 'client';
    this.lingerMs = opts.lingerMs ?? 2000;
    this.headerTimeoutMs = opts.headerTimeoutMs ?? 10_000;
    if (opts.sharedStream) {
      this.attachShared(opts.sharedStream, true);
    }
    void this.acceptLoop();
    void this.watchClosed();
  }

  get closed(): boolean {
    return this.sendClosed || this.notified;
  }

  setReadLimit(n: number): void {
    this.limit = n;
    this.shared?.setReadLimit(n);
    for (const s of this.trackedStreams) s.setReadLimit(n);
  }

  start(h: ConnHandlers): void {
    this.h = h;
    if (this.shared) {
      const msgs = this.earlySharedMsgs;
      this.earlySharedMsgs = [];
      for (const m of msgs) h.message(m);
      if (this.earlySharedErr) {
        const e = this.earlySharedErr;
        this.earlySharedErr = undefined;
        h.error(e);
      }
    } else if (this.role === 'client') {
      // Open shared lane asynchronously if not pre-opened.
      void this.ensureClientShared();
    }
    if (this.earlyClose) {
      const c = this.earlyClose;
      this.earlyClose = undefined;
      this.finishConn(c);
    }
  }

  private async ensureClientShared(): Promise<void> {
    if (this.shared || this.closed) return;
    try {
      await this.wt.ready;
      if (this.shared || this.closed) return;
      const raw = await this.wt.createBidirectionalStream();
      if (this.shared || this.closed) return;
      this.attachShared(raw, true);
      for (const q of this.queuedClientWrites) {
        this.shared!.send(q);
      }
      this.queuedClientWrites = [];
    } catch (e) {
      this.finishConn({ code: Status.unavailable, reason: (e as Error).message, remote: true });
    }
  }

  private queuedClientWrites: Uint8Array[] = [];

  private attachShared(raw: WebTransportBidiStreamLike, opener: boolean, initial?: Uint8Array): void {
    this.sharedOpened = true;
    const st = new WTStream(this, raw, HEADER_SHARED_LANE, opener, this.limit, initial);
    this.shared = st;
    st.start({
      message: (m) => {
        if (this.notified) return;
        if (this.h) this.h.message(m);
        else this.earlySharedMsgs.push(m);
      },
      error: (e) => {
        if (this.notified) return;
        if (this.h) this.h.error(e);
        else this.earlySharedErr ??= e;
      },
      close: (info) => {
        this.finishConn({ code: info.code, reason: info.reset ? 'shared lane reset' : 'shared lane closed', remote: info.remote });
      },
    });
  }

  send(msg: Uint8Array): void {
    if (this.sendClosed || this.notified) throw new ConnClosedError();
    if (!this.shared) {
      if (this.role === 'client') {
        this.queuedClientWrites.push(msg.slice());
        void this.ensureClientShared();
        return;
      }
      throw new ConnClosedError('webtransport: shared lane not opened yet');
    }
    this.shared.send(msg);
  }

  async openStream(): Promise<Stream> {
    if (this.sendClosed || this.notified) throw new ConnClosedError();
    await this.wt.ready;
    if (this.sendClosed || this.notified) throw new ConnClosedError();
    const raw = await this.wt.createBidirectionalStream();
    const st = new WTStream(this, raw, HEADER_LEASED, true, this.limit);
    this.trackedStreams.add(st);
    return st;
  }

  onStream(handler: (stream: Stream) => void): void {
    this.streamHandler = handler;
    const pending = this.pendingStreams;
    this.pendingStreams = [];
    for (const s of pending) handler(s);
  }

  async close(code: number, reason: string): Promise<void> {
    const truncated = truncateReason(reason, MAX_WEBTRANSPORT_REASON);
    const closeCode = code >= 0 && code <= 31 ? code : Status.internal;
    if (!this.sendClosed) {
      this.sendClosed = true;
      if (this.shared && code !== Status.protocol_error) {
        this.shared.closeWrite();
        let t: ReturnType<typeof setTimeout> | undefined;
        await Promise.race([
          this.shared.readFinished,
          this.wt.closed.catch(() => {}),
          new Promise<void>((r) => (t = setTimeout(r, this.lingerMs))),
        ]);
        if (t) clearTimeout(t);
      }
      try {
        this.wt.close({ closeCode, reason: truncated });
      } catch {
        // already closed
      }
    }
    this.finishConn({ code, reason: truncated, remote: false });
  }

  private finishConn(info: CloseInfo): void {
    if (this.notified) return;
    this.notified = true;
    this.sendClosed = true;
    if (this.h) this.h.close(info);
    else this.earlyClose = info;
  }

  private async watchClosed(): Promise<void> {
    try {
      const info = await this.wt.closed;
      const code = typeof info?.closeCode === 'number' && info.closeCode <= 31 ? info.closeCode : Status.unavailable;
      this.finishConn({ code, reason: info?.reason ?? '', remote: !this.sendClosed });
    } catch (e) {
      this.finishConn({ code: Status.unavailable, reason: (e as Error)?.message ?? 'connection closed', remote: !this.sendClosed });
    }
  }

  private async acceptLoop(): Promise<void> {
    try {
      await this.wt.ready;
      const reader = this.wt.incomingBidirectionalStreams.getReader();
      for (;;) {
        const { value, done } = await reader.read();
        if (done || this.notified) return;
        if (value) void this.classifyIncoming(value);
      }
    } catch {
      // session closed
    }
  }

  private async classifyIncoming(raw: WebTransportBidiStreamLike): Promise<void> {
    const reader = raw.readable.getReader();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      let firstChunk: Uint8Array | undefined;
      while (!firstChunk || firstChunk.length === 0) {
        const res = await Promise.race([
          reader.read(),
          new Promise<never>((_, rej) => {
            timer = setTimeout(() => rej(new Error('stream header timeout')), this.headerTimeoutMs);
          }),
        ]);
        if (timer) {
          clearTimeout(timer);
          timer = undefined;
        }
        if (res.done) {
          reader.releaseLock();
          void raw.writable.getWriter().abort(streamAbortReason(Status.protocol_error)).catch(() => {});
          return;
        }
        firstChunk = res.value;
      }
      const hdr = firstChunk[0];
      const rest = firstChunk.subarray(1);
      reader.releaseLock();
      const peerRole: Role = this.role === 'client' ? 'server' : 'client';
      const kind = classifyStreamHeader(hdr, peerRole, this.sharedOpened);
      if (kind === 'protocol_error' || kind === 'profile_reserved') {
        void this.close(Status.protocol_error, `invalid stream header 0x${hdr.toString(16)}`);
        return;
      }
      if (kind === 'shared_lane') {
        this.attachShared(raw, false, rest);
        return;
      }
      const st = new WTStream(this, raw, HEADER_LEASED, false, this.limit, rest);
      this.trackedStreams.add(st);
      if (this.streamHandler) this.streamHandler(st);
      else this.pendingStreams.push(st);
    } catch {
      if (timer) clearTimeout(timer);
      try {
        reader.releaseLock();
      } catch {
        // ignore
      }
      void raw.writable.getWriter().abort(streamAbortReason(Status.protocol_error)).catch(() => {});
    }
  }
}

/** Wraps an already-established WebTransport session as a Sparrow Conn. */
export function webTransportConn(wt: WebTransportLike, opts: WebTransportConnOptions = {}): Conn {
  return new WTConn(wt, opts);
}

/** Opens a WebTransport session to url, awaits ready + the shared lane, and returns its Conn. */
export async function connectWebTransport(url: string, opts: ConnectWebTransportOptions = {}): Promise<Conn> {
  const Ctor = opts.WebTransport ?? (globalThis as { WebTransport?: WebTransportConstructor }).WebTransport;
  if (!Ctor) throw new Error('webtransport: no WebTransport implementation; pass opts.WebTransport');
  if (opts.signal?.aborted) throw new Error('webtransport: aborted');

  const wtOpts: { serverCertificateHashes?: WebTransportHash[] } = {};
  if (opts.serverCertificateHashes?.length) {
    wtOpts.serverCertificateHashes = opts.serverCertificateHashes.map((value) => ({
      algorithm: 'sha-256',
      value,
    }));
  }

  const wt = new Ctor(url, wtOpts);
  const timeoutMs = opts.timeoutMs ?? 10_000;

  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;
  try {
    const sharedStream = await Promise.race([
      (async () => {
        await wt.ready;
        return wt.createBidirectionalStream();
      })(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('webtransport: open timed out')), timeoutMs);
        if (opts.signal) {
          onAbort = () => reject(new Error('webtransport: aborted'));
          opts.signal.addEventListener('abort', onAbort, { once: true });
        }
      }),
    ]);
    return new WTConn(wt, {
      role: 'client',
      lingerMs: opts.lingerMs,
      headerTimeoutMs: opts.headerTimeoutMs,
      sharedStream,
    });
  } catch (err) {
    try {
      wt.close({ closeCode: Status.unavailable, reason: 'connect failed' });
    } catch {
      // ignore
    }
    throw err;
  } finally {
    if (timer) clearTimeout(timer);
    if (onAbort && opts.signal) opts.signal.removeEventListener('abort', onAbort);
  }
}
