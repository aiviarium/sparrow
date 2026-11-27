// Interoperability with the Go reference implementation over the pipe
// binding. go/cmd/sparrow-interop is built once with `go build` (Go 1.24):
//
//  - TS client -> Go server: the Go program starts test/fixture/client-main.mjs
//    as the Sparrow client on its stdio and serves interop.test with
//    session.NewServer; the TS client runs the interop suite (every call
//    shape, errors with details, cancel, deadline, progress, every value
//    type, byte streams), the Go server calls the client's facet.
//  - Go client -> TS server: this test starts the Go program as the Sparrow
//    client (spawn) and serves interop.test with Session.accept; the Go
//    client runs the same suite, the TS server calls the Go client's facet.
//
// Set SPARROW_SKIP_GO=1 to skip when Go is not installed.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import * as lib from '../src/index.js';
import { Session, Status } from '../src/index.js';
import { spawn } from '../src/transport/pipe.js';
import { facets, serverHandlers } from './fixture/interop.mjs';
import { Writer, decode, encode, toHex } from '../src/cbor.js';
import { decodeMessage, encodeMessage } from '../src/wire.js';
import { T, canonicalSchema, decodeSchema, encodeSchema, validateSchema } from '../src/schema.js';
import { Codec } from '../src/value.js';
import { ITERS, SEED, inputs, rng, seedsOf } from './helpers/fuzz.js';

const goDir = fileURLToPath(new URL('../../go', import.meta.url));
const clientMain = fileURLToPath(new URL('./fixture/client-main.mjs', import.meta.url));
const skip = process.env.SPARROW_SKIP_GO === '1';
let bin = '';

beforeAll(() => {
  if (skip) return;
  bin = join(mkdtempSync(join(tmpdir(), 'sparrow-interop-')), 'sparrow-interop');
  execFileSync('go', ['build', '-o', bin, './cmd/sparrow-interop'], { cwd: goDir, stdio: 'inherit' });
}, 300_000);

describe.skipIf(skip)('interop with Go over the pipe binding', () => {
  it('TS client -> Go server (session.NewServer, the TS client is the started process)', () => {
    const r = spawnSync(bin, ['server', process.execPath, clientMain], { encoding: 'utf8', timeout: 120_000 });
    process.stderr.write(r.stderr);
    expect(r.stderr).toContain('[ts client] passed 18 checks');
    expect(r.stderr).toContain('[go server] called the client');
    expect(r.status).toBe(0);
  });

  it('Go client -> TS server (Session.accept, the Go client is the started process)', async () => {
    const f = facets(lib);
    const sh = serverHandlers(lib);
    let stderr = '';
    const { conn, child } = spawn(bin, ['client'], { stdio: ['pipe', 'pipe', 'pipe'] });
    child.stderr!.on('data', (d) => (stderr += d));
    const exit = new Promise<number | null>((res) => child.on('exit', (code) => res(code)));
    const srv = await Session.accept(conn, {
      schema: f.serverSchema,
      handlers: sh.handlers,
      authenticate: (h) => (h.auth?.credentials === 'interop' ? 'ext:go' : Promise.reject(new Error('bad credential'))),
    });
    expect(srv.principal).toBe('ext:go');
    expect(srv.peerSchema?.facets.map((x) => x.name)).toEqual(['interop.client']);
    // Calls from the TS server to the Go client's facet.
    expect(await srv.call('interop.client', 'greet', 'ts server')).toBe('hello, ts server');
    const items: unknown[] = [];
    for await (const v of srv.stream('interop.client', 'count', 3)) items.push(v);
    expect(items).toEqual([1, 2, 3]);
    // Wait for the Go client's suite.
    const deadline = Date.now() + 60_000;
    while (sh.state.lastLog !== 'suite passed') {
      if (Date.now() > deadline || child.exitCode !== null) throw new Error(`the Go client did not finish:\n${stderr}`);
      await new Promise((r) => setTimeout(r, 20));
    }
    srv.goAway(Status.going_away, 'interop done');
    const code = await exit;
    process.stderr.write(stderr);
    expect(stderr).toContain('[go client] passed 17 checks');
    expect(code).toBe(0);
    expect((await srv.closed).code).toBe(Status.going_away);
  });

  it('differential: Go and TS accept and reject the same inputs and agree on their re-encoding', () => {
    // Seeds from the vectors and their mutations; per kind, Go's answer
    // (cmd/sparrow-interop decode) and TS's must be the same line.
    const lines: string[] = [];
    const want: string[] = [];
    const add = (what: string, b: Uint8Array, ts: () => string) => {
      lines.push(`${what} ${toHex(b)}`);
      let r: string;
      try {
        r = ts();
      } catch (e) {
        // TS holds IDs, counts and lengths as numbers: an integer beyond 2^53 - 1 where the
        // message has a number is refused (SPEC-ISSUES Q6); Go takes any uint64.
        r = /\d+ is too large/.test((e as Error).message) ? 'err (beyond 2^53)' : 'err';
      }
      want.push(r);
    };
    const n = Math.max(500, ITERS);
    for (const b of inputs(seedsOf(), 11, n)) add('cbor', b, () => `ok ${toHex(encode(decode(b)))}`);
    for (const b of inputs(seedsOf(['framing.json', 'handshake.json', 'calls.json', 'credit.json']), 12, n)) add('message', b, () => `ok ${toHex(encodeMessage(decodeMessage(b)))}`);
    for (const b of inputs(seedsOf(['schema.json']), 13, Math.floor(n / 4))) {
      add('schema', b, () => {
        const s = decodeSchema(b);
        validateSchema(s);
        return `ok ${toHex(encodeSchema(canonicalSchema(s)))}`;
      });
    }
    const codec = new Codec({ id: 16, name: 'x', version: '1.0.0', types: [], services: [], sigils: [], implements: null, retired: [], annotations: {} });
    const r = rng(SEED ^ 14);
    const stamps: Uint8Array[] = [];
    for (let i = 0; i < n; i++) {
      const w = new Writer();
      w.tag(1);
      const k = r.n(4);
      if (k === 0) w.int(Math.floor((r.f() - 0.5) * 2 ** (r.n(45) + 1)));
      else if (k === 1) w.float((r.f() - 0.5) * 10 ** r.n(13));
      else if (k === 2) w.float(Math.round((r.f() - 0.5) * 2e12) / 1000 + (r.n(3) - 1) * 0.0005);
      else w.float([NaN, Infinity, -Infinity, -0, 5e-324, 8.64e12, 8.64e12 + 1, -8.64e12][r.n(8)]);
      stamps.push(w.finish());
    }
    for (const b of stamps) add('timestamp', b, () => `ok ${(codec.decode(T.timestamp, b) as Date).getTime()}`);
    const res = spawnSync(bin, ['decode'], { input: lines.join('\n') + '\n', encoding: 'utf8', maxBuffer: 256 << 20, timeout: 120_000 });
    expect(res.status, res.stderr).toBe(0);
    const got = res.stdout.trimEnd().split('\n');
    expect(got.length).toBe(lines.length);
    const diffs: string[] = [];
    // Known differences: a time outside Date's range (±8.64e15 ms), which Go keeps and TS refuses,
    // and integers beyond 2^53 - 1.
    const saturated = (g: string) => g.replace(/1b([0-9a-f]{16})/g, (x, h: string) => (BigInt(`0x${h}`) > 2n ** 53n - 1n ? '1b001fffffffffffff' : x));
    const outOfDate = (g: string) => g.startsWith('ok ') && Math.abs(Number(g.slice(3))) > 8.64e15;
    const known = (i: number) =>
      (want[i] === 'err' && lines[i].startsWith('timestamp') && outOfDate(got[i])) ||
      (want[i] === 'err (beyond 2^53)' && (got[i] === 'err' || got[i].startsWith('ok '))) ||
      // Counts beyond 2^53 - 1 (a Credit amount, retry_after_ms) saturate there in TS.
      (got[i].startsWith('ok ') && saturated(got[i]) === want[i]);
    for (let i = 0; i < lines.length; i++) if (got[i] !== want[i] && !known(i)) diffs.push(`${lines[i]}\n  go: ${got[i]}\n  ts: ${want[i]}`);
    expect(diffs.slice(0, 10).join('\n')).toBe('');
  });
});

