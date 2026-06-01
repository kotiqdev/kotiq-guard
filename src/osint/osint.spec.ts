// Tests for the OSINT reputation lookups (mirrors tests/test_mcp_integration.py).
//
// Network is mocked — these tests never hit OSV.dev or deps.dev.

import { Severity } from '../models/enums';
import { aggregateFindings } from '../reporter/reporter';
import {
  addMatcher,
  installFetchMock,
  restoreFetchMock,
} from '../../test/helpers/fetch-mock';
import { checkDepsDev, checkOsv, checkTyposquat } from './osint';

const OSV_LODASH_RESPONSE = {
  vulns: [
    {
      id: 'GHSA-p6mc-m468-83gw',
      aliases: ['CVE-2020-8203'],
      summary: 'Prototype Pollution in lodash',
      severity: [{ type: 'CVSS_V3', score: 'HIGH' }],
      references: [
        { url: 'https://github.com/advisories/GHSA-p6mc-m468-83gw' },
        { url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-8203' },
      ],
    },
  ],
};

function mockOsv(payload: unknown, status = 200): void {
  addMatcher((url) => {
    if (url === 'https://api.osv.dev/v1/query') {
      return () =>
        new Response(JSON.stringify(payload), {
          status,
          headers: { 'Content-Type': 'application/json' },
        });
    }
    return null;
  });
}

function mockOsvNetworkError(): void {
  addMatcher((url) => {
    if (url === 'https://api.osv.dev/v1/query') {
      return () => {
        throw new TypeError('offline');
      };
    }
    return null;
  });
}

function mockDepsDev(payload: unknown, status = 200): void {
  addMatcher((url) => {
    if (url.startsWith('https://api.deps.dev/v3alpha/systems/npm/packages/')) {
      return () =>
        new Response(JSON.stringify(payload), {
          status,
          headers: { 'Content-Type': 'application/json' },
        });
    }
    return null;
  });
}

function mockDepsDevNetworkError(): void {
  addMatcher((url) => {
    if (url.startsWith('https://api.deps.dev/v3alpha/systems/npm/packages/')) {
      return () => {
        throw new TypeError('offline');
      };
    }
    return null;
  });
}

beforeEach(() => installFetchMock());
afterEach(() => restoreFetchMock());

// --- AC-2: OSV.dev -----------------------------------------------------------------------------

test('AC-2: OSV returns findings for a CVE package', async () => {
  mockOsv(OSV_LODASH_RESPONSE);
  const findings = await checkOsv('lodash', '4.17.20');

  expect(findings.length).toBeGreaterThan(0);
  const f = findings[0];
  expect(f.source).toBe('osv');
  expect(f.summary).toBeTruthy();
  expect(f.references.length).toBeGreaterThan(0);
  expect(
    f.references.some((r) => r.includes('GHSA-p6mc-m468-83gw') || r.includes('CVE-2020-8203')),
  ).toBe(true);
});

test('AC-2: HIGH CVSS maps to Severity.HIGH', async () => {
  mockOsv(OSV_LODASH_RESPONSE);
  const findings = await checkOsv('lodash', '4.17.20');
  expect(findings[0].severity).toBe(Severity.HIGH);
});

test('AC-2: clean package returns []', async () => {
  mockOsv({ vulns: [] });
  expect(await checkOsv('left-pad', '1.3.0')).toEqual([]);
});

test('AC-2: network error returns []', async () => {
  mockOsvNetworkError();
  expect(await checkOsv('lodash')).toEqual([]);
});

// --- AC-3: deps.dev ----------------------------------------------------------------------------

test('AC-3: deps.dev flags a non-default version', async () => {
  mockDepsDev({
    versionKey: { system: 'NPM', name: 'some-pkg', version: '0.0.1' },
    isDefault: false,
    advisories: [],
  });
  const findings = await checkDepsDev('some-pkg', '0.0.1');
  expect(findings.length).toBeGreaterThan(0);
  const f = findings[0];
  expect(f.source).toBe('depsdev');
  const rank: Record<string, number> = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
  expect(rank[f.severity]).toBeGreaterThanOrEqual(rank.MEDIUM);
});

test('AC-3: deps.dev flags an attached advisory at HIGH', async () => {
  mockDepsDev({
    versionKey: { system: 'NPM', name: 'vuln-pkg', version: '1.0.0' },
    isDefault: true,
    advisories: [{ advisoryKey: { id: 'GHSA-xxxx-yyyy-zzzz' } }],
  });
  const findings = await checkDepsDev('vuln-pkg', '1.0.0');
  const adv = findings.filter((f) => f.summary.includes('Advisory'));
  expect(adv.length).toBeGreaterThan(0);
  expect(adv[0].severity).toBe(Severity.HIGH);
});

test('AC-3: healthy package returns []', async () => {
  mockDepsDev({
    versionKey: { system: 'NPM', name: 'left-pad', version: '1.3.0' },
    isDefault: true,
    advisories: [],
  });
  expect(await checkDepsDev('left-pad', '1.3.0')).toEqual([]);
});

test('AC-3: network error returns []', async () => {
  mockDepsDevNetworkError();
  expect(await checkDepsDev('some-pkg')).toEqual([]);
});

// --- AC-4: typosquat ---------------------------------------------------------------------------

test('AC-4: "lodas" is flagged as a typosquat of "lodash"', () => {
  const findings = checkTyposquat('lodas');
  expect(findings.length).toBeGreaterThan(0);
  const f = findings[0];
  expect(f.source).toBe('typosquat');
  expect(f.severity).toBe(Severity.HIGH);
  expect(f.summary).toContain('lodash');
});

test('AC-4: exact match is not flagged', () => {
  expect(checkTyposquat('lodash')).toEqual([]);
});

test('AC-4: unrelated name is not flagged', () => {
  expect(checkTyposquat('zzz-totally-unique-zzz123')).toEqual([]);
});

test('AC-4: "expres" is flagged against "express"', () => {
  const findings = checkTyposquat('expres');
  expect(findings.length).toBeGreaterThan(0);
  expect(findings[0].source).toBe('typosquat');
  expect(findings[0].summary).toContain('express');
});

// --- AC-5: end-to-end VerdictCard with reputation findings --------------------------------------

test('AC-5: OSV HIGH propagates to SUSPICIOUS / QUARANTINE VerdictCard', async () => {
  mockOsv(OSV_LODASH_RESPONSE);
  const reputation = await checkOsv('lodash', '4.17.20');
  expect(reputation.length).toBeGreaterThan(0);

  const card = aggregateFindings([], reputation);
  expect(card.verdict).toBe('SUSPICIOUS');
  expect(card.recommended_action).toBe('QUARANTINE');
  expect(card.reputation.length).toBeGreaterThanOrEqual(1);
  expect(card.risk_score).toBeGreaterThan(0);
});

test('AC-5: CRITICAL OSV maps to MALICIOUS / BLOCK', async () => {
  mockOsv({
    vulns: [
      {
        id: 'GHSA-crit-0001',
        aliases: ['CVE-2023-9999'],
        summary: 'Critical RCE in demo-pkg',
        severity: [{ type: 'CVSS_V3', score: 'CRITICAL' }],
        references: [{ url: 'https://github.com/advisories/GHSA-crit-0001' }],
      },
    ],
  });
  const reputation = await checkOsv('demo-pkg', '1.0.0');
  const card = aggregateFindings([], reputation);
  expect(card.verdict).toBe('MALICIOUS');
  expect(card.recommended_action).toBe('BLOCK');
});
