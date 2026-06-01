// Tests for the eval harness (mirrors tests/test_eval_harness.py). One test per AC.

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { EvalEntry, runEval } from '../evals/run-eval';
import { PackageManifest } from '../src/models/contracts';
import { aggregateFindings } from '../src/reporter/reporter';
import { analyzeManifest } from '../src/static-analysis/static-analysis';
import { scan } from '../src/static-analysis/web3-signatures';

const REPO = resolve(__dirname, '..');
const SAFE_DIR = join(REPO, 'evals', 'golden', 'safe');
const MAL_DIR = join(REPO, 'evals', 'golden', 'malicious');
const EVAL_SET = join(REPO, 'evals', 'eval_set.json');
const REPORT = join(REPO, 'evals', 'eval_report.json');
const RUNNER = join(REPO, 'evals', 'run-eval.ts');

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

function listJson(dir: string): string[] {
  return readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => join(dir, f));
}

// --- AC-1: safe fixtures all produce SAFE/ALLOW ------------------------------------------------

test('AC-1: all 6 safe fixtures produce verdict=SAFE / recommended_action=ALLOW', () => {
  const safeFiles = listJson(SAFE_DIR);
  expect(safeFiles.length).toBe(6);
  for (const fpath of safeFiles) {
    const fixture = readJson<PackageManifest>(fpath);
    expect(fixture.found).toBe(true);
    expect(fixture.install_hooks).toEqual({});
    const risk = analyzeManifest(fixture);
    const card = aggregateFindings(risk, []);
    expect(card.verdict).toBe('SAFE');
    expect(card.recommended_action).toBe('ALLOW');
  }
});

// --- AC-2: malicious fixtures all carry at least one §6 signature -------------------------------

test('AC-2: all 6 malicious fixtures carry at least one §6 signature', () => {
  const malFiles = listJson(MAL_DIR);
  expect(malFiles.length).toBe(6);
  for (const fpath of malFiles) {
    const fixture = readJson<PackageManifest>(fpath);
    const texts: string[] = [];
    for (const cmd of Object.values(fixture.install_hooks ?? {})) texts.push(cmd);
    for (const src of fixture.hook_sources ?? []) texts.push(src.content ?? '');
    const hits = texts.flatMap((t) => scan(t));
    expect(hits.length).toBeGreaterThan(0);
  }
});

// --- AC-3: eval_set.json has all 12 entries with required fields --------------------------------

test('AC-3: eval_set.json has 12 entries with required fields', () => {
  const entries = readJson<EvalEntry[]>(EVAL_SET);
  expect(entries.length).toBe(12);
  for (const entry of entries) {
    for (const key of ['fixture_path', 'expected_verdict', 'expected_action', 'notes']) {
      expect(entry).toHaveProperty(key);
    }
    expect(existsSync(join(REPO, entry.fixture_path))).toBe(true);
  }
});

// --- AC-4 / AC-5: recall + accuracy --------------------------------------------------------------

test('AC-4: recall on the malicious set is 100%', () => {
  const report = runEval();
  expect(report.recall_malicious).toBe(1.0);
});

test('AC-5: overall accuracy ≥ 11/12', () => {
  const report = runEval();
  expect(report.accuracy).toBeGreaterThanOrEqual(11 / 12);
});

// --- AC-6: runner is offline ---------------------------------------------------------------------

test('AC-6: run-eval.ts has no network/LLM/subprocess imports', () => {
  const src = readFileSync(RUNNER, 'utf8');
  const code = src
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .join('\n');
  for (const forbidden of [
    "from 'http'",
    "from 'https'",
    "from 'undici'",
    "from 'node-fetch'",
    "from 'child_process'",
    "from 'node:child_process'",
    "from '@google/genai'",
    "from 'openai'",
    'fetch(',
  ]) {
    expect(code).not.toContain(forbidden);
  }
});

// --- AC-7: no real credentials in fixtures -------------------------------------------------------

test('AC-7: no fixture contains real credentials', () => {
  const all = [...listJson(SAFE_DIR), ...listJson(MAL_DIR)];
  const pemPrivkey = /-----BEGIN\s+\S+\s+PRIVATE KEY-----/;
  const realPrivkeyHex = /\b(?!0{64})[0-9a-fA-F]{64}\b/g;
  for (const fpath of all) {
    const text = readFileSync(fpath, 'utf8');
    expect(pemPrivkey.test(text)).toBe(false);
    let m: RegExpExecArray | null;
    realPrivkeyHex.lastIndex = 0;
    while ((m = realPrivkeyHex.exec(text)) !== null) {
      const val = m[0];
      if (val === '0'.repeat(64)) continue;
      const window = text.slice(Math.max(0, m.index - 20), m.index + val.length + 20);
      expect(window).toContain('evil');
    }
  }
});

// --- AC-8: report file written with expected keys ------------------------------------------------

test('AC-8: runEval writes a complete report file', () => {
  runEval();
  expect(existsSync(REPORT)).toBe(true);
  const report = readJson<Record<string, unknown>>(REPORT);
  for (const key of ['total', 'passed', 'failed', 'recall_malicious', 'accuracy', 'failures']) {
    expect(report).toHaveProperty(key);
  }
  expect(report.total).toBe(12);
  expect(Array.isArray(report.failures)).toBe(true);
});
