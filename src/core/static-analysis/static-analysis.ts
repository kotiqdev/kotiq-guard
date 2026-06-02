// Static analysis over an PackageManifest → RiskFinding[].
//
// Consumes the manifest produced by `ingestNpm` and emits findings for:
//
// - Each declared install hook (preinstall/install/postinstall/prepare) — every hook is at least
//   an `install_hook` MEDIUM finding (they run automatically before the user touches the code); if
//   any §6 signature fires inside the hook *command* itself the hook finding inherits the
//   signature's severity.
// - Each §6 signature hit found inside hook_sources — emitted as a `crypto_theft` finding with the
//   source file path, line number, and snippet.
// - Each notable_files entry — emitted as a `sensitive_file` LOW finding.
//
// Pure / passive: no I/O, no subprocess, no eval.

import { PackageManifest, RiskFinding, RiskFindingSchema } from '../models/contracts';
import { Severity } from '../models/enums';
import { SignatureHit, scan } from './web3-signatures';

const SEVERITY_ORDER: readonly Severity[] = [
  Severity.INFO,
  Severity.LOW,
  Severity.MEDIUM,
  Severity.HIGH,
  Severity.CRITICAL,
];

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

function hitToFinding(hit: SignatureHit, file: string | null): RiskFinding {
  return RiskFindingSchema.parse({
    category: hit.category,
    severity: hit.severity,
    title: hit.label,
    file,
    line: hit.line,
    snippet: hit.snippet,
    explanation: `Pattern '${hit.name}' (Plan.md §6) matched in ${file ?? 'the install-hook command'} at line ${hit.line}.`,
  });
}

export function analyzeManifest(manifest: PackageManifest | Record<string, unknown> | null | undefined): RiskFinding[] {
  if (!manifest || !(manifest as PackageManifest).found) return [];
  const m = manifest as PackageManifest;
  const findings: RiskFinding[] = [];

  // 1) Declared install hooks. Even a benign hook is a flag because it runs automatically.
  for (const [hookName, command] of Object.entries(m.install_hooks ?? {})) {
    const cmdHits = scan(command ?? '');
    let baseSeverity: Severity = Severity.MEDIUM;
    for (const hit of cmdHits) baseSeverity = maxSeverity(baseSeverity, hit.severity);
    findings.push(
      RiskFindingSchema.parse({
        category: 'install_hook',
        severity: baseSeverity,
        title: `${hookName} script declared in package.json`,
        file: 'package.json',
        line: null,
        snippet: command,
        explanation:
          `npm will run \`${command}\` automatically on install (${hookName}). ` +
          'Contagious-Interview / Lazarus malware hides its payload here.',
      }),
    );
    for (const hit of cmdHits) findings.push(hitToFinding(hit, 'package.json'));
  }

  // 2) Hook source files — the actual second-stage code. This is where §6 detection earns its
  //    keep: the hook command may just be `node scripts/install.js` (innocuous-looking) while the
  //    script reads ~/.config/solana and POSTs to evil.example.
  for (const entry of m.hook_sources ?? []) {
    const path = entry.path;
    const content = entry.content ?? '';
    for (const hit of scan(content)) findings.push(hitToFinding(hit, path));
  }

  // 3) Sensitive files shipping inside the tarball (.env, wallet.dat, …). LOW because the file
  //    being there doesn't *do* anything on its own, but it's a smell worth surfacing.
  for (const path of m.notable_files ?? []) {
    findings.push(
      RiskFindingSchema.parse({
        category: 'sensitive_file',
        severity: Severity.LOW,
        title: `Sensitive file in package: ${path}`,
        file: path,
        line: null,
        snippet: null,
        explanation:
          `The package ships \`${path}\`. Credential-shaped files have no reason to be ` +
          'distributed via npm; check whether secrets were committed by mistake.',
      }),
    );
  }

  return findings;
}
