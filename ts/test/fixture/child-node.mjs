#!/usr/bin/env node
// A started process for the pipe fault tests: the Sparrow client on its
// standard input and output, publishing the facet "child" (block never
// answers; download sends n bytes). It prints "started" to standard error
// when a block call starts, and exits when the session ends.
import * as lib from '../../dist/index.js';
import { stdio } from '../../dist/transport/pipe.js';

const { FacetBuilder, T, byteStream, makeSchema } = lib;
const b = new FacetBuilder('child', '1.0.0', { id: 16 });
const svc = b.service('Child');
svc.method('block', T.unit, T.unit);
svc.method('download', T.uint, byteStream());
const session = await lib.Session.connect(stdio(), {
  schema: makeSchema('child', '1.0.0', [b.build()]),
  handlers: {
    child: {
      block: () => {
        process.stderr.write('started\n');
        return new Promise(() => {});
      },
      download: async (n, ctx) => {
        const chunk = new Uint8Array(16384).fill(7);
        for (let left = n; left > 0; left -= chunk.length) await ctx.sendBytes(0, chunk.subarray(0, Math.min(left, chunk.length)), left <= chunk.length);
      },
    },
  },
});
await session.closed;
process.exit(0);
