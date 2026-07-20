'use strict';

/**
 * prepublishOnly: bundle the release engine into the package.
 *
 * Publishing without a fresh binary must fail loudly, not ship a stale or
 * missing engine.
 */

const { copyFileSync, statSync } = require('node:fs');
const { join } = require('node:path');

const source = join(__dirname, '..', 'target', 'release', 'radiochron.exe');
const target = join(__dirname, 'radiochron.exe');

let size;
try {
  size = statSync(source).size;
} catch {
  console.error('prepare: no release binary. Run `cargo build --release` first.');
  process.exit(1);
}

copyFileSync(source, target);
console.log(`prepare: bundled radiochron.exe (${Math.round(size / 1024)} KB)`);
