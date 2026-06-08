// Deterministic analysis pipeline — single source of truth.
//
//     unpackNpm → analyzeManifest + [checkOsv, checkDepsDev, checkTyposquat] → aggregateFindings
//
// No LLM is involved. Both the `kotiq-check` MCP server and the one-shot CLI delegate here so the
// pipeline body lives in exactly one place.
//
// Safety: passive read-only. Never executes install scripts or package code, never writes the
// package to disk, never spawns a subprocess.

import { HookSource, VerdictCard } from '../models/contracts';
import { checkDepsDev, checkOsv, checkTyposquat, npmWeeklyDownloads } from '../osint/osint';
import { aggregateFindings } from '../reporter/reporter';
import { analyzeManifest } from '../static-analysis/static-analysis';
import { unpackNpm } from '../unpack/unpack';

// Deterministic verdict + the raw install-hook context, so a downstream agent can reason about
// WHAT the hooks actually do (beyond the signature scan). `hookSources` is the source of any local
// script the hook runs, if it was shipped in the tarball.
// A candidate this widely downloaded is an established package, not an obscure typosquat look-alike.
const POPULAR_WEEKLY_DOWNLOADS = 10_000;

export type ScanResult = {
  card: VerdictCard;
  installHooks: Record<string, string>; // hookName → command string
  hookSources: HookSource[]; // { path, content }
};

export async function analyzeWithContext(name: string, version: string | null = null): Promise<ScanResult> {
  const manifest = await unpackNpm(name, version);
  const found = Boolean(manifest.found);

  // Static analysis needs the tarball; OSINT does not — run it regardless so a yanked malicious
  // version (event-stream@3.3.6, ua-parser-js@0.7.29) still surfaces its OSV advisory.
  const riskFindings = found ? analyzeManifest(manifest) : [];

  // Use the resolved version (the one that will actually be installed) so OSV/deps.dev only report
  // advisories that affect THAT version — like npm audit, not "every advisory the package ever had".
  const resolvedVersion = found && manifest.version ? manifest.version : version;
  // Edit-distance typosquatting flags a name 1 edit from a popular one — but legit popular packages
  // also resemble shorter names (msw~ms, preact~react). Only fetch the candidate's own downloads
  // when a typosquat actually fired, then suppress it if the candidate is itself well-established.
  const typosquatRaw = checkTyposquat(name);
  const [osv, depsdev, weeklyDownloads] = await Promise.all([
    checkOsv(name, resolvedVersion),
    checkDepsDev(name, resolvedVersion),
    typosquatRaw.length > 0 ? npmWeeklyDownloads(name) : Promise.resolve(null),
  ]);
  const isEstablished = weeklyDownloads != null && weeklyDownloads >= POPULAR_WEEKLY_DOWNLOADS;
  const typosquat = isEstablished ? [] : typosquatRaw;
  const reputationFindings = [...osv, ...depsdev, ...typosquat];

  const installHooks = manifest.install_hooks ?? {};
  const hookSources = manifest.hook_sources ?? [];

  // Not found and no external signal at all → we cannot vouch for it: NEEDS_REVIEW / BLOCK.
  let card: VerdictCard;
  if (!found && reputationFindings.length === 0) {
    card = {
      verdict: 'NEEDS_REVIEW' as VerdictCard['verdict'],
      risk_score: 50,
      recommended_action: 'BLOCK' as VerdictCard['recommended_action'],
      summary: `Package '${name}' could not be fetched and has no OSINT signal.`,
      top_findings: [],
      reputation: [],
      scanned_version: resolvedVersion ?? null,
    };
  } else {
    card = { ...aggregateFindings(riskFindings, reputationFindings), scanned_version: resolvedVersion ?? null };
  }

  return { card, installHooks, hookSources };
}

// Backwards-compatible helper: just the VerdictCard (CLI, MCP, deterministic callers).
export async function analyzePackage(name: string, version: string | null = null): Promise<VerdictCard> {
  return (await analyzeWithContext(name, version)).card;
}
