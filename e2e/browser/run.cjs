// Runs client.html in headless Chromium against a running sparrow-hub
// with the Web Profile on, and prints the result as JSON on stdout.
//
//   node run.cjs <web base, e.g. https://127.0.0.1:4434> <bearer token>
//
// The page is served by a small HTTP server on 127.0.0.1 (a secure
// context, and in the same local address space as the hub, so Chromium's
// local-network-access checks allow the connections); /sparrow/connect is
// a cross-origin request the hub answers with CORS. The hub's self-signed
// certificate is accepted for fetch and WebSocket with ignoreHTTPSErrors;
// WebTransport pins it with serverCertificateHashes, which needs an ECDSA
// certificate valid for at most 14 days.
const { chromium } = require('playwright');
const fs = require('fs');
const http = require('http');
const path = require('path');

function servePage() {
  const srv = http.createServer((req, res) => {
    const f = { '/client.html': 'text/html', '/sparrow-mini.js': 'text/javascript' }[req.url];
    if (!f) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'Content-Type': f });
    res.end(fs.readFileSync(path.join(__dirname, req.url.slice(1))));
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(srv)));
}

async function main() {
  const [base, token] = process.argv.slice(2);
  if (!base || !token) {
    console.error('usage: node run.cjs <web base> <token>');
    process.exit(2);
  }
  const browser = await chromium.launch();
  const result = { browser: browser.version() };
  try {
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    const logs = [];
    page.on('console', (m) => logs.push(`${m.type()}: ${m.text()}`));
    page.on('pageerror', (e) => logs.push(`pageerror: ${e}`));
    const srv = await servePage();
    await page.goto(`http://127.0.0.1:${srv.address().port}/client.html`);
    await page.waitForFunction(() => document.getElementById('out').textContent === 'ready');
    Object.assign(result, await page.evaluate((p) => window.runE2E(p), { base, token, input: 'hello from the browser' }));
    srv.close();
    result.console = logs;
  } catch (e) {
    result.error = String(e && e.stack || e);
  } finally {
    await browser.close();
  }
  process.stdout.write(JSON.stringify(result) + '\n');
}

main();
