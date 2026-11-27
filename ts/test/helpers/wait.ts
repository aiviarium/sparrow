// Polling helpers: wait for a condition instead of sleeping for a fixed time.

/** Resolves once cond() is true; rejects after timeoutMs. Polls every few milliseconds. */
export async function eventually(cond: () => boolean, msg = 'condition', timeoutMs = 5000): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${msg}`);
    await new Promise((r) => setTimeout(r, 2));
  }
}

/** Fails if cond() becomes true within ms (for things that must not happen). */
export async function never(cond: () => boolean, msg: string, ms = 50): Promise<void> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) throw new Error(`unexpected: ${msg}`);
    await new Promise((r) => setTimeout(r, 2));
  }
  if (cond()) throw new Error(`unexpected: ${msg}`);
}
