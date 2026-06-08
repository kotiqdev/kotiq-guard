// Shared severity → verdict mapping for the repo scanner (dependency scan + self-scan).

import { Severity, Verdict } from '../models/enums';

export const SEV_RANK: Record<Severity, number> = {
    [Severity.INFO]: 0,
    [Severity.LOW]: 1,
    [Severity.MEDIUM]: 2,
    [Severity.HIGH]: 3,
    [Severity.CRITICAL]: 4,
};

export const VERDICT_RANK: Record<Verdict, number> = {
    [Verdict.SAFE]: 0,
    [Verdict.NEEDS_REVIEW]: 1,
    [Verdict.SUSPICIOUS]: 2,
    [Verdict.MALICIOUS]: 3,
};

export function verdictForSeverity(rank: number): Verdict {
    if (rank >= SEV_RANK[Severity.CRITICAL]) return Verdict.MALICIOUS;
    if (rank >= SEV_RANK[Severity.HIGH]) return Verdict.SUSPICIOUS;
    if (rank >= SEV_RANK[Severity.MEDIUM]) return Verdict.NEEDS_REVIEW;
    return Verdict.SAFE;
}

export function maxSeverityRank(sevs: Severity[]): number {
    return sevs.reduce((m, s) => Math.max(m, SEV_RANK[s]), 0);
}

export function worseVerdict(a: Verdict, b: Verdict): Verdict {
    return VERDICT_RANK[a] >= VERDICT_RANK[b] ? a : b;
}
