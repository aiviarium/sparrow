// A fake clock for the session's protocol timers (SessionOptions.clock).
import type { Clock } from '../../src/session.js';

interface Pending {
  at: number;
  seq: number;
  f: () => void;
}

/** Time moves only when advance() is called; due timers run in order. */
export class FakeClock implements Clock {
  private t = 1_800_000_000_000;
  private seq = 0;
  private timers = new Map<number, Pending>();

  now(): number {
    return this.t;
  }

  setTimeout(f: () => void, ms: number): unknown {
    const id = ++this.seq;
    this.timers.set(id, { at: this.t + Math.max(0, ms), seq: id, f });
    return id;
  }

  clearTimeout(id: unknown): void {
    this.timers.delete(id as number);
  }

  /** Timers not yet run. */
  get pending(): number {
    return this.timers.size;
  }

  /**
   * Moves time forward by ms, running every timer that falls due on the way
   * (including ones those timers set), and lets the promises they settle run.
   */
  async advance(ms: number): Promise<void> {
    const end = this.t + ms;
    for (;;) {
      await flush();
      let next: Pending | undefined;
      for (const p of this.timers.values()) if (p.at <= end && (!next || p.at < next.at || (p.at === next.at && p.seq < next.seq))) next = p;
      if (!next) break;
      this.timers.delete(next.seq);
      this.t = Math.max(this.t, next.at);
      next.f();
    }
    this.t = end;
    await flush();
  }
}

/** Lets pending promise callbacks and I/O callbacks run. */
export async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) await new Promise<void>((r) => setImmediate(r));
}
