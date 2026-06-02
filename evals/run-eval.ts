// Eval runner for the Kotiq golden set.
//
// Offline — no LLM, no network, no subprocess. Calls the deterministic tool stack directly:
//     analyzeManifest → aggregateFindings → compare against eval_set.json expected verdicts.
//
// Usage:
//     npm run eval [-- <eval_set_path>]

import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { PackageManifest } from '../src/core/models/contracts';
import { aggregateFindings } from '../src/core/reporter/reporter';
import { analyzeManifest } from '../src/core/static-analysis/static-analysis';

const REPO_ROOT = resolve(__dirname, '..');
const DEFAULT_EVAL_SET = join(REPO_ROOT, 'evals', 'eval_set.json');
const REPORT_PATH = join(REPO_ROOT, 'evals', 'eval_report.json');

const CAUGHT = new Set(['MALICIOUS', 'SUSPICIOUS']);

export interface EvalEntry {
  fixture_path: string;
  expected_verdict: string;
  expected_action: string;
  notes?: string;
}

export interface EvalFailure {
  fixture: string;
  expected_verdict: string;
  actual_verdict: string;
  expected_action: string;
  actual_action: string;
  notes: string;
}

export interface EvalReport {
  total: number;
  passed: number;
  failed: number;
  recall_malicious: number;
  accuracy: number;
  failures: EvalFailure[];
}

export function runEval(evalSetPath: string = DEFAULT_EVAL_SET): EvalReport {
  const entries: EvalEntry[] = JSON.parse(readFileSync(evalSetPath, 'utf8'));

  const total = entries.length;
  let passed = 0;
  let maliciousTotal = 0;
  let maliciousCaught = 0;
  const failures: EvalFailure[] = [];

  for (const entry of entries) {
    const fixture = JSON.parse(
      readFileSync(join(REPO_ROOT, entry.fixture_path), 'utf8'),
    ) as PackageManifest;
    const riskFindings = analyzeManifest(fixture);
    const card = aggregateFindings(riskFindings, []);

    const actualVerdict = card.verdict;
    const expectedVerdict = entry.expected_verdict;
    const expectedAction = entry.expected_action;

    if (CAUGHT.has(expectedVerdict)) {
      maliciousTotal++;
      if (CAUGHT.has(actualVerdict)) maliciousCaught++;
    }

    const verdictMatch = actualVerdict === expectedVerdict;
    const actionMatch = card.recommended_action === expectedAction;
    if (verdictMatch && actionMatch) {
      passed++;
    } else {
      failures.push({
        fixture: entry.fixture_path,
        expected_verdict: expectedVerdict,
        actual_verdict: actualVerdict,
        expected_action: expectedAction,
        actual_action: card.recommended_action,
        notes: entry.notes ?? '',
      });
    }
  }

  const recall = maliciousTotal ? maliciousCaught / maliciousTotal : 1.0;
  const accuracy = total ? passed / total : 1.0;

  const report: EvalReport = {
    total,
    passed,
    failed: total - passed,
    recall_malicious: recall,
    accuracy,
    failures,
  };

  writeFileSync(REPORT_PATH, `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

function printReport(report: EvalReport): void {
  const w = '─'.repeat(50);
  process.stdout.write(`\n${w}\n`);
  process.stdout.write(`  Kotiq eval — ${report.passed}/${report.total} passed\n`);
  process.stdout.write(`  Recall (malicious): ${(report.recall_malicious * 100).toFixed(1)}%\n`);
  process.stdout.write(`  Accuracy:           ${(report.accuracy * 100).toFixed(1)}%\n`);
  if (report.failures.length > 0) {
    process.stdout.write(`\n  Failures (${report.failures.length}):\n`);
    for (const f of report.failures) {
      process.stdout.write(`    FAIL ${f.fixture}\n`);
      process.stdout.write(
        `         expected ${f.expected_verdict}/${f.expected_action}  got ${f.actual_verdict}/${f.actual_action}\n`,
      );
    }
  }
  process.stdout.write(`${w}\n\n`);
}

if (require.main === module) {
  const path = process.argv[2] ?? DEFAULT_EVAL_SET;
  const report = runEval(path);
  printReport(report);
  process.exit(report.recall_malicious >= 1.0 ? 0 : 1);
}
