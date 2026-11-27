#!/usr/bin/env node
// A started process that speaks Sparrow on its standard input and output
// (the pipe binding, 4.7): it is the Sparrow client, publishes the
// interop.client facet and runs the interop check suite against its parent.
// Exit code 0 when every check passed. Diagnostics go to standard error.
import * as lib from '../../dist/index.js';
import { stdio } from '../../dist/transport/pipe.js';
import { clientHandlers, facets, runClientSuite } from './interop.mjs';

const log = (s) => process.stderr.write(`[ts client] ${s}\n`);
const f = facets(lib);
let session;
try {
  session = await lib.Session.connect(stdio(), {
    schema: f.clientSchema,
    handlers: clientHandlers(),
    auth: { scheme: 'bearer', credentials: 'interop' },
  });
  const done = await runClientSuite(session, lib, process.env.SPARROW_VERBOSE ? log : () => {});
  log(`passed ${done.length} checks: ${done.join(' ')}`);
  if (process.env.SPARROW_WAIT_FOR_SERVER) {
    // Tell the server the suite passed; it may still call this side's facet, then ends the session with GoAway.
    session.notify('interop.test', 'log', 'suite passed');
    const info = await session.closed;
    if (session.goAwayReceived?.status !== lib.Status.going_away) throw new Error(`want GoAway(going_away), got ${JSON.stringify(info)}`);
  } else await session.close(lib.Status.going_away, 'done');
  process.exitCode = 0;
} catch (e) {
  log(`FAILED: ${e?.stack ?? e}`);
  process.exitCode = 1;
  try {
    await session?.close(lib.Status.internal, 'client failed');
  } catch {}
}
