// Copies compiled @aiviarium/sparrow and @aiviarium/sparrow-client ESM bundles
// into frontend/dist/vendor/ so Wails embeds the immutable empty hull cleanly.
import { cpSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');
const vendor = join(here, 'dist', 'vendor');

const tsDist = join(root, 'ts', 'dist');
const clientDist = join(root, 'client', 'dist');
if (!existsSync(tsDist) || !existsSync(clientDist)) {
  console.error('Build ts/ and client/ first (npm run build in ts/ and client/).');
  process.exit(1);
}

mkdirSync(vendor, { recursive: true });
cpSync(tsDist, join(vendor, 'sparrow'), { recursive: true });
cpSync(clientDist, join(vendor, 'sparrow-client'), { recursive: true });
console.log('Bundled @aiviarium/sparrow and @aiviarium/sparrow-client into desktop/frontend/dist/vendor/');
