// A minimal Sparrow browser client for the end-to-end test: just
// enough CBOR (RFC 8949: unsigned and negative integers, byte and text
// strings, arrays, maps, tags, simple values) and protocol (Hello, Welcome,
// Ready, a unary call, SchemaAck, Pong) to prove the WebTransport and
// WebSocket bindings work from a real browser. Not a library.

const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });

// ---------------------------------------------------------------- CBOR
export class Bytes {
  constructor(u8) { this.u8 = u8; }
}
export class Tag {
  constructor(tag, value) { this.tag = tag; this.value = value; }
}

function head(out, major, n) {
  if (n < 24) out.push((major << 5) | n);
  else if (n < 0x100) out.push((major << 5) | 24, n);
  else if (n < 0x10000) out.push((major << 5) | 25, n >> 8, n & 0xff);
  else if (n < 0x100000000) out.push((major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  else {
    const b = BigInt(n);
    out.push((major << 5) | 27);
    for (let i = 7; i >= 0; i--) out.push(Number((b >> BigInt(8 * i)) & 0xffn));
  }
}

function encInto(out, v) {
  if (v === null || v === undefined) out.push(0xf6);
  else if (v === false) out.push(0xf4);
  else if (v === true) out.push(0xf5);
  else if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('floats are not used here');
    if (v >= 0) head(out, 0, v); else head(out, 1, -1 - v);
  } else if (typeof v === 'string') {
    const b = te.encode(v);
    head(out, 3, b.length);
    for (const x of b) out.push(x);
  } else if (v instanceof Uint8Array || v instanceof Bytes) {
    const b = v instanceof Bytes ? v.u8 : v;
    head(out, 2, b.length);
    for (const x of b) out.push(x);
  } else if (Array.isArray(v)) {
    head(out, 4, v.length);
    for (const x of v) encInto(out, x);
  } else if (v instanceof Tag) {
    head(out, 6, v.tag);
    encInto(out, v.value);
  } else if (v instanceof Map) {
    head(out, 5, v.size);
    for (const [k, x] of v) { encInto(out, k); encInto(out, x); }
  } else if (typeof v === 'object') {
    const ks = Object.keys(v);
    head(out, 5, ks.length);
    for (const k of ks) { encInto(out, k); encInto(out, v[k]); }
  } else throw new Error('cannot encode ' + typeof v);
}

export function encode(v) {
  const out = [];
  encInto(out, v);
  return new Uint8Array(out);
}

export function decode(u8) {
  let off = 0;
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  function arg(info) {
    if (info < 24) return info;
    if (info === 24) return u8[off++];
    if (info === 25) { const v = dv.getUint16(off); off += 2; return v; }
    if (info === 26) { const v = dv.getUint32(off); off += 4; return v; }
    if (info === 27) { const v = dv.getBigUint64(off); off += 8; return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v; }
    throw new Error('indefinite lengths are not allowed');
  }
  function item() {
    const b = u8[off++];
    const major = b >> 5, info = b & 31;
    switch (major) {
      case 0: return arg(info);
      case 1: { const n = arg(info); return typeof n === 'bigint' ? -1n - n : -1 - n; }
      case 2: { const n = arg(info); const v = u8.slice(off, off + n); off += n; return v; }
      case 3: { const n = arg(info); const v = td.decode(u8.subarray(off, off + n)); off += n; return v; }
      case 4: { const n = arg(info); const a = []; for (let i = 0; i < n; i++) a.push(item()); return a; }
      case 5: { const n = arg(info); const m = new Map(); for (let i = 0; i < n; i++) { const k = item(); m.set(k, item()); } return m; }
      case 6: { const t = arg(info); return new Tag(t, item()); }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        if (info === 25) { off += 2; return NaN; } // floats are not expected
        if (info === 26) { const v = dv.getFloat32(off); off += 4; return v; }
        if (info === 27) { const v = dv.getFloat64(off); off += 8; return v; }
        throw new Error('unsupported simple value ' + info);
    }
  }
  const v = item();
  if (off !== u8.length) throw new Error('trailing bytes');
  return v;
}

// ---------------------------------------------------------------- framing
export function varint(n) {
  if (n < 64) return [n];
  if (n < 16384) return [0x40 | (n >> 8), n & 0xff];
  if (n < 2 ** 30) return [0x80 | (n >>> 24), (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  throw new Error('message too large for this client');
}

// A WebTransport stream reader that yields whole length-prefixed messages.
class FrameReader {
  constructor(readable) { this.r = readable.getReader(); this.buf = new Uint8Array(0); }
  async need(n) {
    while (this.buf.length < n) {
      const { value, done } = await this.r.read();
      if (done) throw new Error('stream ended');
      const b = new Uint8Array(this.buf.length + value.length);
      b.set(this.buf); b.set(value, this.buf.length);
      this.buf = b;
    }
  }
  take(n) { const v = this.buf.slice(0, n); this.buf = this.buf.slice(n); return v; }
  async next() {
    await this.need(1);
    const len = 1 << (this.buf[0] >> 6);
    await this.need(len);
    const h = this.take(len);
    let n = h[0] & 0x3f;
    for (let i = 1; i < len; i++) n = n * 256 + h[i];
    await this.need(n);
    return this.take(n);
  }
}

// ---------------------------------------------------------------- lanes
async function wtLane(url, certHash) {
  const opts = certHash ? { serverCertificateHashes: [{ algorithm: 'sha-256', value: certHash }] } : {};
  const wt = new WebTransport(url, opts);
  await wt.ready;
  const st = await wt.createBidirectionalStream();
  const w = st.writable.getWriter();
  const rd = new FrameReader(st.readable);
  let first = true;
  return {
    async send(msg) {
      const b = encode(msg);
      const pre = first ? [0x00] : [];
      first = false;
      await w.write(new Uint8Array([...pre, ...varint(b.length), ...b]));
    },
    async recv() { return decode(await rd.next()); },
    close() { try { wt.close({ closeCode: 0, reason: 'done' }); } catch (e) { /* closed */ } },
  };
}

async function wsLane(url) {
  const ws = new WebSocket(url, 'sparrow.v1');
  ws.binaryType = 'arraybuffer';
  const queue = [];
  const waiters = [];
  let closed = null;
  ws.onmessage = (e) => {
    const m = decode(new Uint8Array(e.data));
    if (waiters.length) waiters.shift().resolve(m); else queue.push(m);
  };
  ws.onclose = (e) => {
    closed = new Error(`websocket closed ${e.code} ${e.reason}`);
    while (waiters.length) waiters.shift().reject(closed);
  };
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = () => reject(new Error('websocket failed')); });
  if (ws.protocol !== 'sparrow.v1') throw new Error('subprotocol not agreed: ' + ws.protocol);
  return {
    async send(msg) { ws.send(encode(msg)); },
    recv() {
      if (queue.length) return Promise.resolve(queue.shift());
      if (closed) return Promise.reject(closed);
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },
    close() { ws.close(1000, 'done'); },
  };
}

// ---------------------------------------------------------------- session
const get = (m, k) => (m instanceof Map ? m.get(k) : m[k]);

// session runs Hello / Welcome / Ready with a ticket and one unary call to
// facet `facetName`, method `methodName`, and returns what happened.
export async function session({ binding, url, certHash, ticket, facetName, methodName, input }) {
  const lane = binding === 'webtransport' ? await wtLane(url, certHash) : await wsLane(url);
  const log = [];
  try {
    await lane.send([0, [1], {}, ['bearer', ticket], null, null, {}, false]);
    const welcome = await lane.recv();
    if (welcome[0] !== 1) throw new Error('expected Welcome, got kind ' + welcome[0] + ': ' + JSON.stringify(welcome));
    log.push('Welcome');
    const offer = welcome[5];
    if (offer[0] !== 2) throw new Error('expected a full schema offer, got ' + offer[0]);
    const hash = offer[1];
    const sc = offer[2];
    const facet = sc[3].find((f) => f[1] === facetName);
    if (!facet) throw new Error('facet ' + facetName + ' not in the schema');
    let methodId = null;
    for (const svc of facet[4]) for (const m of svc[2]) if (m[1] === methodName) methodId = m[0];
    if (methodId === null) throw new Error('method ' + methodName + ' not found');
    await lane.send([2, hash]);
    log.push('Ready');
    await lane.send([16, 2, facet[0], methodId, {}, input]);
    for (;;) {
      const m = await lane.recv();
      switch (m[0]) {
        case 3: await lane.send([4, m[1]]); log.push('SchemaAck'); break;       // SchemaUpdate
        case 7: await lane.send([8, m[1]]); break;                             // Ping
        case 6: case 24: case 22: break;                                       // AuthStatus, Credit, Headers
        case 17: if (m[1] === 2) { log.push('Response'); return { ok: true, output: m[2], log, facetId: facet[0], methodId }; } break;
        case 20: return { ok: false, error: `Error ${m[2]}: ${m[3]}`, log };
        case 9: return { ok: false, error: `GoAway ${m[1]}: ${m[2]}`, log };
        default: log.push('kind ' + m[0]);
      }
    }
  } finally {
    lane.close();
  }
}

// connect posts /sparrow/connect (Web Profile 9.1) with a bearer login.
export async function connect(base, token) {
  const r = await fetch(base + '/sparrow/connect', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
    body: JSON.stringify({ client: { name: 'browser-e2e', version: '1.0.0', hostApi: '3.2.0' } }),
  });
  if (!r.ok) throw new Error('/connect: HTTP ' + r.status + ' ' + (await r.text()));
  return r.json();
}

export function b64urlToBytes(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}
