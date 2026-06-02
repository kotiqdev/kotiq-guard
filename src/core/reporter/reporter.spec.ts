// AC-4 from the Python multi-agent-split spec — deterministic verdict/action mapping.

import { Severity } from '../models/enums';
import { aggregateFindings } from './reporter';

function finding(severity: Severity, category = 'crypto_theft') {
  return {
    category,
    severity,
    title: `${category} ${severity} test`,
    file: null,
    line: null,
    snippet: null,
    explanation: 'synthetic',
    confidence: 1.0,
  };
}

test('AC-4: any CRITICAL ⇒ MALICIOUS / BLOCK', () => {
  const card = aggregateFindings([finding(Severity.CRITICAL)], []);
  expect(card.verdict).toBe('MALICIOUS');
  expect(card.recommended_action).toBe('BLOCK');
});

test('AC-4: ≥1 HIGH (no CRITICAL) ⇒ SUSPICIOUS / QUARANTINE', () => {
  const card = aggregateFindings([finding(Severity.HIGH)], []);
  expect(card.verdict).toBe('SUSPICIOUS');
  expect(card.recommended_action).toBe('QUARANTINE');
});

test('AC-4: ≥1 MEDIUM ⇒ SUSPICIOUS / ALLOW_WITH_WARNING', () => {
  const card = aggregateFindings([finding(Severity.MEDIUM)], []);
  expect(card.verdict).toBe('SUSPICIOUS');
  expect(card.recommended_action).toBe('ALLOW_WITH_WARNING');
});

test('AC-4: only INFO/LOW ⇒ SAFE / ALLOW', () => {
  const card = aggregateFindings([finding(Severity.LOW), finding(Severity.INFO)], []);
  expect(card.verdict).toBe('SAFE');
  expect(card.recommended_action).toBe('ALLOW');
});

test('AC-4: no findings ⇒ SAFE / ALLOW with risk_score 0', () => {
  const card = aggregateFindings([], []);
  expect(card.verdict).toBe('SAFE');
  expect(card.recommended_action).toBe('ALLOW');
  expect(card.risk_score).toBe(0);
});

test('AC-4: risk_score clamped to 100', () => {
  const inputs = Array.from({ length: 5 }, () => finding(Severity.CRITICAL));
  expect(aggregateFindings(inputs, []).risk_score).toBe(100);
});

test('AC-4: risk_score is monotonic in severity', () => {
  const low = aggregateFindings([finding(Severity.LOW)], []).risk_score;
  const medium = aggregateFindings([finding(Severity.MEDIUM)], []).risk_score;
  const high = aggregateFindings([finding(Severity.HIGH)], []).risk_score;
  const crit = aggregateFindings([finding(Severity.CRITICAL)], []).risk_score;
  expect(low).toBeLessThan(medium);
  expect(medium).toBeLessThan(high);
  expect(high).toBeLessThan(crit);
});

test('AC-4: top_findings sorted desc and capped at 5', () => {
  const inputs = [
    finding(Severity.LOW),
    finding(Severity.CRITICAL),
    finding(Severity.MEDIUM),
    finding(Severity.HIGH),
    finding(Severity.LOW),
    finding(Severity.INFO),
    finding(Severity.HIGH),
  ];
  const card = aggregateFindings(inputs, []);
  const severities = card.top_findings.map((f) => f.severity);
  expect(severities.length).toBe(5);
  const rank: Record<string, number> = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
  for (let i = 0; i < 4; i++) {
    expect(rank[severities[i]]).toBeGreaterThanOrEqual(rank[severities[i + 1]]);
  }
  expect(severities[0]).toBe('CRITICAL');
});
