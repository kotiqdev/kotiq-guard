// AC-4 from the Python isolated-scanning spec — scan CLI prints VerdictCard JSON and exits 2 on
// MALICIOUS.
//
// The CLI delegates to `analyzePackage`. We mock that module to keep the test deterministic and
// offline.

jest.mock('../pipeline/pipeline', () => ({
  analyzePackage: jest.fn(),
}));

const { analyzePackage } = require('../pipeline/pipeline') as {
  analyzePackage: jest.Mock;
};

import { main, splitSpec } from './scan';

afterEach(() => {
  analyzePackage.mockReset();
});

const CARD_KEYS = ['verdict', 'risk_score', 'recommended_action', 'summary', 'top_findings', 'reputation'];

function safeCard() {
  return {
    verdict: 'SAFE',
    risk_score: 0,
    recommended_action: 'ALLOW',
    summary: '',
    top_findings: [],
    reputation: [],
  };
}

test('AC-4: CLI prints valid VerdictCard JSON and exits 0 for non-malicious verdicts', async () => {
  analyzePackage.mockResolvedValue(safeCard());
  const out: string[] = [];
  const spy = jest.spyOn(process.stdout, 'write').mockImplementation((chunk: any) => {
    out.push(String(chunk));
    return true;
  });

  const code = await main(['lodash']);
  spy.mockRestore();

  const parsed = JSON.parse(out.join(''));
  for (const k of CARD_KEYS) expect(parsed).toHaveProperty(k);
  expect(code).toBe(0);
});

test('AC-4: CLI exits with code 2 on MALICIOUS', async () => {
  analyzePackage.mockResolvedValue({
    verdict: 'MALICIOUS',
    risk_score: 95,
    recommended_action: 'BLOCK',
    summary: 'curl|bash',
    top_findings: [],
    reputation: [],
  });
  const spy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  const code = await main(['evil-pkg@1.0.0']);
  spy.mockRestore();
  expect(code).toBe(2);
});

test('AC-4: name@version split handles scoped packages', () => {
  expect(splitSpec('lodash')).toEqual({ name: 'lodash', version: null });
  expect(splitSpec('event-stream@3.3.6')).toEqual({ name: 'event-stream', version: '3.3.6' });
  expect(splitSpec('@scope/pkg@1.2.3')).toEqual({ name: '@scope/pkg', version: '1.2.3' });
});
