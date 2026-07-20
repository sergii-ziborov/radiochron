#!/usr/bin/env node
'use strict';

/**
 * RadioChron MCP server launcher.
 *
 * The engine is a prebuilt native binary shipped inside this package, so the
 * one-liner works with nothing but Node:
 *
 *   claude mcp add radiochron -- npx -y radiochron
 *
 * stdio is inherited: the MCP client talks JSON-RPC straight to the engine,
 * this launcher just finds and starts it.
 */

const { spawnSync } = require('node:child_process');
const { join } = require('node:path');
const { existsSync } = require('node:fs');

if (process.platform !== 'win32') {
  process.stderr.write(
    [
      'radiochron: the collector engine is Windows-only today.',
      'Linux (nl80211) and macOS (CoreWLAN) collectors are on the roadmap:',
      'https://radiochron.com/#roadmap',
      ''
    ].join('\n')
  );
  process.exit(1);
}

const exe = join(__dirname, 'radiochron.exe');
if (!existsSync(exe)) {
  process.stderr.write('radiochron: bundled engine missing — broken install, try reinstalling.\n');
  process.exit(1);
}

const result = spawnSync(exe, process.argv.slice(2), { stdio: 'inherit' });
process.exit(result.status === null ? 1 : result.status);
