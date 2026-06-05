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

export type SelfFindingKind =
    | 'install_hook'
    | 'vscode_task'
    | 'vscode_settings'
    | 'idea_runconfig'
    | 'source'
    | 'env_secret';

export interface RepoSelfFinding {
    kind: SelfFindingKind;
    file: string;
    label: string;
    severity: Severity;
    detail?: string;
}

export interface RepoSelfResult {
    findings: RepoSelfFinding[];
    worst: Verdict;
    filesScanned: number;
    // Plain-language, developer-facing "what this repo does" bullets.
    what: string[];
    // Heads-up notes on code that does NOT auto-run (informational; never drives the verdict).
    fyi?: RepoSelfFinding[];
}

export interface RepoResult {
    found: boolean;
    repo: string;
    totalDeps: number;
    scanned: number;
    withHooks: number;
    flagged: DepFinding[];
    // The repo's OWN files (tasks.json folderOpen, install hooks, source, .env). Null on error.
    self: RepoSelfResult | null;
    worst: Verdict;
    error?: string;
}
