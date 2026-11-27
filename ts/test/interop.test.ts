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
});
