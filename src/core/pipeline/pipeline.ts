// Deterministic analysis pipeline — single source of truth.
//
//     unpackNpm → analyzeManifest + [checkOsv, checkDepsDev, checkTyposquat] → aggregateFindings
//
// No LLM is involved. Both the `kotiq-check` MCP server and the one-shot CLI delegate here so the
// pipeline body lives in exactly one place.
//
// Safety: passive read-only. Never executes install scripts or package code, never writes the
// package to disk, never spawns a subprocess.

import { unpackNpm } from '../unpack/unpack';
import { VerdictCard } from '../models/contracts';
import { checkDepsDev, checkOsv, checkTyposquat } from '../osint/osint';
import { aggregateFindings } from '../reporter/reporter';
import { analyzeManifest } from '../static-analysis/static-analysis';

export async function analyzePackage(name: string, version: string | null = null): Promise<VerdictCard> {
  const manifest = await unpackNpm(name, version);
  const found = Boolean(manifest.found);

  // Static analysis needs the tarball; OSINT does not — run it regardless so a yanked malicious
  // version (event-stream@3.3.6, ua-parser-js@0.7.29) still surfaces its OSV advisory.
  const riskFindings = found ? analyzeManifest(manifest) : [];

  // Use the resolved version (the one that will actually be installed) so OSV/deps.dev only report
  // advisories that affect THAT version — like npm audit, not "every advisory the package ever had".
  // Keep the caller's explicit version for yanked-but-known-bad pins (event-stream@3.3.6).
  const resolvedVersion = found && manifest.version ? manifest.version : version;
  const [osv, depsdev, typosquat] = await Promise.all([
    checkOsv(name, resolvedVersion),
    checkDepsDev(name, resolvedVersion),
    Promise.resolve(checkTyposquat(name)),
  ]);
  const reputationFindings = [...osv, ...depsdev, ...typosquat];

  // Not found and no external signal at all → we cannot vouch for it: NEEDS_REVIEW / BLOCK.
  if (!found && reputationFindings.length === 0) {
    return {
      verdict: 'NEEDS_REVIEW' as VerdictCard['verdict'],
      risk_score: 50,
      recommended_action: 'BLOCK' as VerdictCard['recommended_action'],
      summary: `Package '${name}' could not be fetched and has no OSINT signal.`,
      top_findings: [],
      reputation: [],
      scanned_version: resolvedVersion ?? null,
    };
  }

  return { ...aggregateFindings(riskFindings, reputationFindings), scanned_version: resolvedVersion ?? null };
}
