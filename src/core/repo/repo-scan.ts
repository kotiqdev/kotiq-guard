// Server-side GitHub repo dependency scan. Reads a repo's package.json from GitHub, then for each
// direct dependency fetches its install-hook COMMANDS from the npm registry and scans them with the
// SAME core signatures Pro uses. Authoritative + centrally updatable (vs running in the extension).
//
// Passive: HTTP GETs only, no execution. MVP scans direct deps; transitive (lockfile) is future work.

import { HTTP_TIMEOUT_MS, NPM_REGISTRY } from '../config/configuration';
import { Severity, Verdict } from '../models/enums';
import { scan } from '../static-analysis/web3-signatures';

const RAW = 'https://raw.githubusercontent.com';
const RUN_HOOKS = ['preinstall', 'install', 'postinstall'] as const;
const MAX_DEPS = 200;
const CONCURRENCY = 10;

const SEV_RANK: Record<Severity, number> = {
    [Severity.INFO]: 0,
    [Severity.LOW]: 1,
    [Severity.MEDIUM]: 2,
    [Severity.HIGH]: 3,
    [Severity.CRITICAL]: 4,
};
const VERDICT_RANK: Record<Verdict, number> = {
    [Verdict.SAFE]: 0,
    [Verdict.NEEDS_REVIEW]: 1,
    [Verdict.SUSPICIOUS]: 2,
    [Verdict.MALICIOUS]: 3,
};

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

function encodeName(name: string): string {
    if (name.startsWith('@')) {
        const slash = name.indexOf('/');
        if (slash > 0) return `@${encodeURIComponent(name.slice(1, slash))}%2F${encodeURIComponent(name.slice(slash + 1))}`;
    }
    return encodeURIComponent(name);
}

async function getJson(url: string): Promise<unknown> {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
    try {
        const res = await fetch(url, { headers: { Accept: 'application/json' }, signal: ctrl.signal });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } finally {
        clearTimeout(t);
    }
}

function verdictFor(sev: number): Verdict {
    if (sev >= SEV_RANK[Severity.CRITICAL]) return Verdict.MALICIOUS;
    if (sev >= SEV_RANK[Severity.HIGH]) return Verdict.SUSPICIOUS;
    if (sev >= SEV_RANK[Severity.MEDIUM]) return Verdict.NEEDS_REVIEW;
    return Verdict.SAFE;
}

async function scanDep(name: string): Promise<DepFinding | null> {
    let manifest: { version?: string; scripts?: Record<string, string> };
    try {
        manifest = (await getJson(`${NPM_REGISTRY}/${encodeName(name)}/latest`)) as typeof manifest;
    } catch {
        return null;
    }
    const scripts = manifest.scripts ?? {};
    const hooks: Record<string, string> = {};
    for (const h of RUN_HOOKS) if (typeof scripts[h] === 'string') hooks[h] = scripts[h];
    if (!Object.keys(hooks).length) return null;

    const findings: DepFinding['findings'] = [];
    for (const cmd of Object.values(hooks)) {
        for (const hit of scan(cmd)) findings.push({ label: hit.label, severity: hit.severity, snippet: hit.snippet });
    }
    const maxSev = findings.reduce((m, f) => Math.max(m, SEV_RANK[f.severity]), 0);
    return { name, version: manifest.version ?? 'latest', hooks, findings, verdict: verdictFor(maxSev) };
}

async function pool<T, R>(items: T[], n: number, fn: (t: T) => Promise<R>): Promise<R[]> {
    const out: R[] = new Array(items.length);
    let i = 0;
    const worker = async (): Promise<void> => {
        while (i < items.length) {
            const idx = i++;
            out[idx] = await fn(items[idx]);
        }
    };
    await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
    return out;
}

export async function repoScan(owner: string, repo: string): Promise<RepoResult> {
    const id = `${owner}/${repo}`;
    const empty = (error?: string): RepoResult => ({
        found: false,
        repo: id,
        totalDeps: 0,
        scanned: 0,
        withHooks: 0,
        flagged: [],
        worst: Verdict.SAFE,
        error,
    });

    let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
    try {
        pkg = (await getJson(`${RAW}/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/HEAD/package.json`)) as typeof pkg;
    } catch (e) {
        return empty((e as Error).message === 'HTTP 404' ? 'no package.json (not a Node project?)' : (e as Error).message);
    }

    const allNames = [...new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})])];
    const names = allNames.slice(0, MAX_DEPS);
    const results = (await pool(names, CONCURRENCY, scanDep)).filter((r): r is DepFinding => r !== null);

    const flagged = results
        .filter((r) => r.verdict !== Verdict.SAFE)
        .sort((a, b) => VERDICT_RANK[b.verdict] - VERDICT_RANK[a.verdict]);
    const worst = flagged[0]?.verdict ?? Verdict.SAFE;

    return { found: true, repo: id, totalDeps: allNames.length, scanned: names.length, withHooks: results.length, flagged, worst };
}
