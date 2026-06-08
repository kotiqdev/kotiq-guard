// OSINT reputation checks for npm packages.
//
// Three passive, read-only lookups that feed the OSINT agent:
//
// 1. checkOsv       — OSV.dev CVE/advisory database (POST /v1/query)
// 2. checkDepsDev   — deps.dev version metadata (deprecated flag, advisories)
// 3. checkTyposquat — Levenshtein-distance check vs bundled top-npm list (no network)
//
// All three return ReputationFinding[] and never throw — any exception yields an empty list so the
// pipeline keeps running.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { HTTP_TIMEOUT_MS } from '../config/configuration';
import { ReputationFinding, ReputationFindingSchema } from '../models/contracts';
import { Severity } from '../models/enums';

// ---------------------------------------------------------------------------
// Bundled typosquat reference list
// ---------------------------------------------------------------------------
// The list ships alongside the compiled JS via nest-cli's `assets` rule
// (`osint/data/*.txt` is copied to `dist/osint/data/`).
const TOP_NPM_FILE = join(__dirname, 'data', 'top1000_npm.txt');

let topNpmCache: string[] | null = null;

function loadTopNpm(): string[] {
  if (topNpmCache !== null) return topNpmCache;
  const raw = readFileSync(TOP_NPM_FILE, 'utf8');
  topNpmCache = raw
    .split('\n')
    .map((ln) => ln.trim())
    .filter((ln) => ln.length > 0 && !ln.startsWith('#'));
  return topNpmCache;
}

// ---------------------------------------------------------------------------
// Levenshtein distance (Wagner-Fischer, no external deps)
// ---------------------------------------------------------------------------
function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) dp[j] = j;
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? prev : 1 + Math.min(prev, dp[j], dp[j - 1]);
      prev = tmp;
    }
  }
  return dp[n];
}

// ---------------------------------------------------------------------------
// HTTP helper with hard timeout
// ---------------------------------------------------------------------------
async function fetchWithTimeout(url: string, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// OSV.dev severity mapping
// ---------------------------------------------------------------------------
function osvSeverity(vuln: Record<string, any>): Severity {
  const sevList: any[] = vuln.severity ?? [];
  for (const s of sevList) {
    const score = String(s?.score ?? '').toUpperCase();
    if (score.includes('CRITICAL')) return Severity.CRITICAL;
    if (score.includes('HIGH')) return Severity.HIGH;
    if (score.includes('MODERATE') || score.includes('MEDIUM')) return Severity.MEDIUM;
    if (score.includes('LOW')) return Severity.LOW;
  }
  const aliases: string[] = vuln.aliases ?? [];
  const ids: string[] = [vuln.id ?? '', ...aliases];
  if (ids.some((i) => i.startsWith('CVE-') || i.startsWith('GHSA-'))) return Severity.HIGH;
  return Severity.MEDIUM;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function checkOsv(name: string, version: string | null = null): Promise<ReputationFinding[]> {
  try {
    const payload: Record<string, any> = { package: { name, ecosystem: 'npm' } };
    if (version) payload.version = version;
    const resp = await fetchWithTimeout('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (resp.status !== 200) return [];
    const data = (await resp.json()) as Record<string, any>;
    const vulns: any[] = data.vulns ?? [];
    const findings: ReputationFinding[] = [];
    for (const v of vulns) {
      const vid: string = v.id ?? 'unknown';
      const aliases: string[] = v.aliases ?? [];
      const refs: string[] =
        (v.references ?? [])
          .map((r: any) => r?.url ?? '')
          .filter((u: string) => u.length > 0) || [];
      const refList = refs.length > 0 ? refs : [vid];
      const summary: string = v.summary ?? v.details ?? vid;
      findings.push(
        ReputationFindingSchema.parse({
          source: 'osv',
          severity: osvSeverity(v),
          summary: `[${vid}] ${summary}`,
          references: [vid, ...aliases, ...refList].slice(0, 10),
        }),
      );
    }
    return findings;
  } catch {
    return [];
  }
}

export async function checkDepsDev(name: string, version: string | null = null): Promise<ReputationFinding[]> {
  try {
    const ver = version ?? 'latest';
    const url = `https://api.deps.dev/v3alpha/systems/npm/packages/${encodeURIComponent(name)}/versions/${encodeURIComponent(ver)}`;
    const resp = await fetchWithTimeout(url);
    if (resp.status !== 200) return [];
    const data = (await resp.json()) as Record<string, any>;
    const findings: ReputationFinding[] = [];

    const isDefault = data.isDefault ?? true;
    if (!isDefault) {
      findings.push(
        ReputationFindingSchema.parse({
          source: 'depsdev',
          severity: Severity.MEDIUM,
          summary: `${name}@${ver} is not the default/recommended version (deps.dev)`,
          references: [`https://deps.dev/npm/${name}/${ver}`],
        }),
      );
    }

    const advisories: any[] = data.advisories ?? [];
    for (const adv of advisories) {
      const advId: string = adv?.advisoryKey?.id ?? 'unknown';
      findings.push(
        ReputationFindingSchema.parse({
          source: 'depsdev',
          severity: Severity.HIGH,
          summary: `Advisory ${advId} linked to ${name}@${ver} (deps.dev)`,
          references: [`https://deps.dev/advisory/${advId}`],
        }),
      );
    }

    return findings;
  } catch {
    return [];
  }
}

// Last-week npm download count for a package, or null if unknown. Used to tell a genuine typosquat
// (an obscure look-alike) from a legitimately popular package that merely resembles a shorter name
// (e.g. msw ~ ms, preact ~ react). Scoped packages aren't supported by this endpoint → null.
export async function npmWeeklyDownloads(name: string): Promise<number | null> {
  try {
    const resp = await fetchWithTimeout(
      `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`,
    );
    if (resp.status !== 200) return null;
    const data = (await resp.json()) as { downloads?: number };
    return typeof data.downloads === 'number' ? data.downloads : null;
  } catch {
    return null;
  }
}

export function checkTyposquat(name: string): ReputationFinding[] {
  try {
    const top = loadTopNpm();
    if (top.includes(name)) return [];
    const matches = top.filter((pkg) => levenshtein(name, pkg) === 1);
    if (matches.length === 0) return [];
    let closest = matches[0];
    let best = levenshtein(name, closest);
    for (const pkg of matches) {
      const d = levenshtein(name, pkg);
      if (d < best) {
        best = d;
        closest = pkg;
      }
    }
    return [
      ReputationFindingSchema.parse({
        source: 'typosquat',
        severity: Severity.HIGH,
        summary:
          `'${name}' is 1 edit away from popular package '${closest}' — ` +
          'possible typosquatting attack',
        references: [`https://www.npmjs.com/package/${closest}`],
      }),
    ];
  } catch {
    return [];
  }
}
