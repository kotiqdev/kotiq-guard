// Tests for the deterministic pipeline (mirrors tests/test_isolated_scanning.py AC-1/AC-2).

import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import {
  addMatcher,
  installFetchMock,
  mockNpmRegistry,
  mockPackumentStatus,
  restoreFetchMock,
} from '../../../test/helpers/fetch-mock';
import { makeTarball } from '../../../test/helpers/tarball';
import { PackageManifest } from '../models/contracts';
import { analyzePackage } from './pipeline';

const REPO_ROOT = resolve(__dirname, '../..');
const SAFE_MANIFEST = JSON.parse(
  readFileSync(join(REPO_ROOT, 'evals/golden/safe/minimal.json'), 'utf8'),
) as PackageManifest;

const CARD_KEYS = new Set([
  'verdict',
  'risk_score',
  'recommended_action',
  'summary',
  'top_findings',
  'reputation',
]);

function mockOsintAllEmpty(): void {
  addMatcher((url) => {
    if (url.startsWith('https://api.osv.dev')) {
      return () => new Response(JSON.stringify({ vulns: [] }), { status: 200 });
    }
    if (url.startsWith('https://api.deps.dev')) {
      return () => new Response('', { status: 404 });
    }
    return null;
  });
}

beforeEach(() => installFetchMock());
afterEach(() => restoreFetchMock());

test('AC-1: analyzePackage returns a VerdictCard dict', async () => {
  const minimalPkgJson = JSON.stringify({
    name: SAFE_MANIFEST.name,
    version: SAFE_MANIFEST.version,
  });
  const blob = await makeTarball({ 'package.json': minimalPkgJson });
  mockNpmRegistry({
    name: SAFE_MANIFEST.name ?? 'minimal-pkg',
    version: SAFE_MANIFEST.version ?? '1.0.0',
    blob,
  });
  mockOsintAllEmpty();

  const card = await analyzePackage(SAFE_MANIFEST.name ?? 'minimal-pkg');
  for (const k of CARD_KEYS) expect(card).toHaveProperty(k);
  expect(['SAFE', 'SUSPICIOUS', 'MALICIOUS', 'NEEDS_REVIEW']).toContain(card.verdict);
});

test('AC-2: not-found + no OSINT signal ⇒ NEEDS_REVIEW / BLOCK', async () => {
  mockPackumentStatus('ghost-pkg', 404);
  mockOsintAllEmpty();
  const card = await analyzePackage('ghost-pkg');
  expect(card.verdict).toBe('NEEDS_REVIEW');
  expect(card.recommended_action).toBe('BLOCK');
});

test('AC-2: not-found but OSV has a HIGH advisory ⇒ SUSPICIOUS (not collapsed to NEEDS_REVIEW)', async () => {
  mockPackumentStatus('event-stream', 404);
  addMatcher((url) => {
    if (url === 'https://api.osv.dev/v1/query') {
      return () =>
        new Response(
          JSON.stringify({
            vulns: [
              {
                id: 'GHSA-mh6f-8j2x-4483',
                aliases: [],
                summary: 'malware advisory',
                severity: [{ type: 'CVSS_V3', score: 'HIGH' }],
                references: [{ url: 'https://github.com/advisories/GHSA-mh6f-8j2x-4483' }],
              },
            ],
          }),
          { status: 200 },
        );
    }
    if (url.startsWith('https://api.deps.dev')) {
      return () => new Response('', { status: 404 });
    }
    return null;
  });

  const card = await analyzePackage('event-stream', '3.3.6');
  expect(card.verdict).toBe('SUSPICIOUS');
  expect(card.reputation.length).toBeGreaterThan(0);
});
