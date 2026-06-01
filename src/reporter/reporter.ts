// Aggregate analysis findings into a final VerdictCard.
//
// Deterministic core. The LLM-driven ReporterAgent calls this; the function does the actual
// verdict/action selection so the answer is reproducible across model versions.
//
//     severities seen           verdict       recommended_action
//     ────────────────────────────────────────────────────────────
//     any CRITICAL              MALICIOUS     BLOCK
//     ≥1 HIGH (no CRITICAL)     SUSPICIOUS    QUARANTINE
//     ≥1 MEDIUM                 SUSPICIOUS    ALLOW_WITH_WARNING
//     everything else           SAFE          ALLOW
//
// Reputation findings count toward the mapping too — a HIGH-severity OSV advisory is just as
// relevant as a HIGH-severity static finding. Risk score is a clamped sum of severity weights.

import {
  ReputationFinding,
  ReputationFindingSchema,
  RiskFinding,
  RiskFindingSchema,
  VerdictCard,
  VerdictCardSchema,
} from '../models/contracts';
import { Action, Severity, Verdict } from '../models/enums';

// Weights for risk_score; chosen so a single CRITICAL alone is enough to dominate (90/100), and a
// single HIGH (50) is below the BLOCK floor but well above SAFE.
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  [Severity.INFO]: 1,
  [Severity.LOW]: 5,
  [Severity.MEDIUM]: 20,
  [Severity.HIGH]: 50,
  [Severity.CRITICAL]: 90,
};

// Sort order for top_findings (highest severity first).
const SEVERITY_RANK: Record<Severity, number> = {
  [Severity.CRITICAL]: 5,
  [Severity.HIGH]: 4,
  [Severity.MEDIUM]: 3,
  [Severity.LOW]: 2,
  [Severity.INFO]: 1,
};

const TOP_FINDINGS_CAP = 5;

function coerceRisk(items: unknown[]): RiskFinding[] {
  return (items ?? []).map((f) => RiskFindingSchema.parse(f));
}

function coerceRep(items: unknown[]): ReputationFinding[] {
  return (items ?? []).map((r) => ReputationFindingSchema.parse(r));
}

function pickVerdictAndAction(severities: Severity[]): { verdict: Verdict; action: Action } {
  if (severities.includes(Severity.CRITICAL)) return { verdict: Verdict.MALICIOUS, action: Action.BLOCK };
  if (severities.includes(Severity.HIGH)) return { verdict: Verdict.SUSPICIOUS, action: Action.QUARANTINE };
  if (severities.includes(Severity.MEDIUM)) return { verdict: Verdict.SUSPICIOUS, action: Action.ALLOW_WITH_WARNING };
  return { verdict: Verdict.SAFE, action: Action.ALLOW };
}

function riskScore(severities: Severity[]): number {
  const total = severities.reduce((sum, s) => sum + SEVERITY_WEIGHTS[s], 0);
  return Math.min(100, total);
}

function summarize(verdict: Verdict, risk: RiskFinding[], rep: ReputationFinding[]): string {
  const bySev = new Map<Severity, number>();
  for (const f of risk) bySev.set(f.severity, (bySev.get(f.severity) ?? 0) + 1);
  const parts: string[] = [];
  for (const sev of [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]) {
    const count = bySev.get(sev);
    if (count) parts.push(`${count} ${sev}`);
  }
  const findingsStr = parts.length > 0 ? parts.join(', ') : 'no static findings';
  const repStr = rep.length > 0 ? `; ${rep.length} OSINT signal${rep.length !== 1 ? 's' : ''}` : '';
  const top = risk.length > 0 ? risk[0].title : null;
  const topStr = top ? ` — top: ${top}` : '';
  return `${verdict}: ${findingsStr}${repStr}${topStr}`;
}

export function aggregateFindings(
  riskFindings: unknown[],
  reputationFindings: unknown[],
): VerdictCard {
  const risk = coerceRisk(riskFindings);
  const rep = coerceRep(reputationFindings);

  const severities: Severity[] = [...risk.map((f) => f.severity), ...rep.map((r) => r.severity)];
  const { verdict, action } = pickVerdictAndAction(severities);
  const score = riskScore(severities);

  const ranked = [...risk].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  const top = ranked.slice(0, TOP_FINDINGS_CAP);
  const summary = summarize(verdict, ranked, rep);

  return VerdictCardSchema.parse({
    verdict,
    risk_score: score,
    recommended_action: action,
    summary,
    top_findings: top,
    reputation: rep,
  });
}
