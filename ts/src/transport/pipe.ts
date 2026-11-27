// The pipe binding (spec 4.7): one ordered byte stream, such as a child
// process's standard input and output. There is a shared lane and nothing
// else; each message is preceded by its length as a QUIC varint, with no
// stream header. The side that speaks first with Hello is the client: a
// started process is the client, on its standard input and output. Closing
// the byte stream ends the session; status and reason travel only in GoAway.
// Standard error is not part of the protocol.
//
// Node only (node:child_process, node:stream).

import { spawn as nodeSpawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import type { Readable, Writable } from 'node:stream';
import { Status } from '../status.js';
import { ConnClosedError, type Conn, type ConnHandlers } from '../transport.js';
import { DEFAULTS, FrameDecoder, frame } from '../wire.js';

export interface PipeOptions {
  /** How long close waits, after finishing this side's direction, for the peer to finish its own (5.6); default 2 s. */
  lingerMs?: number;
  /** Destroy the readable side on close (default true). */
  destroyOnClose?: boolean;
  /** Called once when the connection has ended, either way. */
  onEnd?: () => void;
}

class PipeConn implements Conn {
  readonly binding = 'pipe';
  private h?: ConnHandlers;
  private fd = new FrameDecoder(DEFAULTS.maxMessageSize);
  private sendClosed = false;
  private notified = false;
  private readEnded = false;
  private failed = false;
  private readonly onReadEnd: Promise<void>;
  private markReadEnd!: () => void;

  constructor(
    private readonly r: Readable,
    private readonly w: Writable,
    private readonly opts: PipeOptions,
  ) {
    this.onReadEnd = new Promise((res) => (this.markReadEnd = res));
    w.on('error', () => this.finish(true, 'write failed'));
  }

  get closed(): boolean {
    return this.sendClosed || this.notified;
  }

  start(h: ConnHandlers): void {
    this.h = h;
    this.r.on('data', (chunk: Uint8Array) => {
      if (this.failed || this.notified) return;
      let msgs: Uint8Array[];
      try {
        msgs = this.fd.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength).slice());
      } catch (e) {
        this.failed = true;
        h.error(e as Error);
        return;
      }
      for (const m of msgs) {
        if (this.notified) return;
        h.message(m);
      }
    });
    const ended = () => {
      if (this.readEnded) return;
      this.readEnded = true;
      this.markReadEnd();
      this.finish(true, 'pipe closed by the peer');
    };
    this.r.on('end', ended);
    this.r.on('close', ended);
    this.r.on('error', ended);
  }

  setReadLimit(n: number): void {
    this.fd.maxMessageSize = n;
  }

  send(msg: Uint8Array): void {
    if (this.sendClosed || this.notified) throw new ConnClosedError();
    this.w.write(frame(msg));
  }

  private finish(remote: boolean, reason: string): void {
    if (this.notified) return;
    this.notified = true;
    this.opts.onEnd?.();
    this.h?.close({ code: Status.unavailable, reason, remote });
  }

  async close(code: number, reason: string): Promise<void> {
    if (!this.sendClosed) {
      this.sendClosed = true;
      // Finish this side's direction once what was written is flushed; a
      // peer that reads nothing cannot hold it past the linger.
      let t: ReturnType<typeof setTimeout> | undefined;
      await new Promise<void>((res) => {
        try {
          this.w.end(() => res());
        } catch {
          res();
        }
        t = setTimeout(res, this.opts.lingerMs ?? 2000);
      });
      clearTimeout(t);
      if (code !== Status.protocol_error && !this.readEnded) {
        let t: ReturnType<typeof setTimeout> | undefined;
        await Promise.race([this.onReadEnd, new Promise<void>((res) => (t = setTimeout(res, this.opts.lingerMs ?? 2000)))]);
        if (t) clearTimeout(t);
      }
      if (this.opts.destroyOnClose !== false) this.r.destroy();
    }
    if (!this.notified) {
      this.notified = true;
      this.opts.onEnd?.();
      this.h?.close({ code, reason, remote: false });
    }
  }
}

/** A pipe connection reading from r and writing to w (for example a child's stdout and stdin). */
export function pipeConn(r: Readable, w: Writable, opts: PipeOptions = {}): Conn {
  return new PipeConn(r, w, opts);
}

/**
 * The pipe connection on this process's standard input and output, for a
 * process whose parent speaks Sparrow to it: the started process is the
 * Sparrow client (4.7). Nothing else may write to standard output afterwards
 * (log to standard error).
 */
export function stdio(opts: PipeOptions = {}): Conn {
  return new PipeConn(process.stdin, process.stdout, opts);
}

export interface SpawnPipeOptions extends PipeOptions {
  /** How long the child may take to exit after the connection ended (its standard input is closed) before it is killed; default 5 s. */
  killAfterMs?: number;
}

/** How a spawned process ended. */
export interface ChildExit {
  code: number | null;
  signal: NodeJS.Signals | null;
}

/**
 * Starts a process with a pipe connection on its standard input and output.
 * The returned connection is the starting side's end: the Sparrow server
 * (4.7). Standard error is inherited unless opts.stdio says otherwise. Once
 * the connection has ended (closed, or the child closed its output or died),
 * a child that has not exited killAfterMs later is killed; exited resolves
 * with its exit code or signal.
 */
export function spawn(cmd: string, args: string[] = [], opts: SpawnOptions & SpawnPipeOptions = {}): { conn: Conn; child: ChildProcess; exited: Promise<ChildExit> } {
  const { lingerMs, destroyOnClose, onEnd, killAfterMs, ...spawnOpts } = opts;
  const child = nodeSpawn(cmd, args, { stdio: ['pipe', 'pipe', 'inherit'], ...spawnOpts });
  if (!child.stdout || !child.stdin) throw new Error('pipe: the child has no standard input or output pipe');
  let killTimer: ReturnType<typeof setTimeout> | undefined;
  const exited = new Promise<ChildExit>((res) => {
    child.once('exit', (code, signal) => {
      clearTimeout(killTimer);
      res({ code, signal });
    });
    child.once('error', () => {
      clearTimeout(killTimer);
      res({ code: child.exitCode, signal: child.signalCode });
    });
  });
  const reap = () => {
    onEnd?.();
    if (child.exitCode !== null || child.signalCode !== null) return;
    killTimer = setTimeout(() => child.kill('SIGKILL'), killAfterMs ?? 5000);
  };
  return { conn: new PipeConn(child.stdout, child.stdin, { lingerMs, destroyOnClose, onEnd: reap }), child, exited };
}
