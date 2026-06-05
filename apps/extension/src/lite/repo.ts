// Repo-scan result types. The scan LOGIC now lives on the backend (src/core/repo/repo-scan.ts) so
// the detection is centrally controlled/updatable and authoritative — the extension just calls /repo.

import type { Severity } from './signatures';

export type Verdict = 'SAFE' | 'NEEDS_REVIEW' | 'SUSPICIOUS' | 'MALICIOUS';

export interface DepFinding {
    name: string;
    version: string;
    hooks: Record<string, string>;
    findings: { label: string; severity: Severity; snippet: string }[];
    verdict: Verdict;
}

export interface RepoResult {
    found: boolean;
    repo: string;
    totalDeps: number;
    scanned: number;
    withHooks: number;
    flagged: DepFinding[];
    worst: Verdict;
    error?: string;
}
