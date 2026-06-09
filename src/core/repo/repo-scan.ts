// Server-side GitHub repo scan. Two passes, both passive (HTTP GET only, no execution):
//
//   1. DEPENDENCY scan — for each direct dependency, fetch its install-hook commands from the npm
//      registry and run them through the core signatures (the same ones Pro uses).
//   2. SELF scan — read the repo's OWN files (package.json hooks, .vscode/tasks.json, settings,
//      source, .env) and flag the Contagious-Interview / BeaverTail lure behaviours. This catches
//      malware that lives in the repo itself, not in its dependencies — a dep-only scan misses it.
//
// An optional GITHUB_TOKEN lifts the 60/hr rate limit and unlocks private repos; without it we read
// public content from raw.githubusercontent.com (no rate limit).

import { env } from '../../env';
import { HTTP_TIMEOUT_MS, NPM_REGISTRY } from '../config/configuration';
import { Severity, Verdict } from '../models/enums';
import { scan } from '../static-analysis/web3-signatures';
import { selfScan, type RepoFiles, type RepoSelfResult } from './self-scan';
import { maxSeverityRank, verdictForSeverity, VERDICT_RANK, worseVerdict } from './verdict';

const RAW = 'https://raw.githubusercontent.com';
const GH_API = 'https://api.github.com';
const RUN_HOOKS = ['preinstall', 'install', 'postinstall'] as const;
const MAX_DEPS = 200;
const CONCURRENCY = 10;
const MAX_FILE_BYTES = 256 * 1024;

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
    self: RepoSelfResult | null;
    worst: Verdict;
    error?: string;
}

function ghHeaders(json = false): Record<string, string> {
    const h: Record<string, string> = { 'User-Agent': 'kotiq-guard' };
    if (json) h.Accept = 'application/vnd.github+json';
    if (env.githubToken) h.Authorization = `Bearer ${env.githubToken}`;
    return h;
}

function encodeName(name: string): string {
    if (name.startsWith('@')) {
        const slash = name.indexOf('/');
        if (slash > 0) return `@${encodeURIComponent(name.slice(1, slash))}%2F${encodeURIComponent(name.slice(slash + 1))}`;
    }
    return encodeURIComponent(name);
}

// GitHub owner/repo path segments: word chars, dot, hyphen only. Validated before use in API paths so
// only well-formed identifiers reach the request URL.
const REPO_SEGMENT_RE = /^[\w.-]+$/;
function validRepoRef(owner: string, repo: string): boolean {
    return REPO_SEGMENT_RE.test(owner) && REPO_SEGMENT_RE.test(repo);
}

async function getJson(url: string, headers?: Record<string, string>): Promise<unknown> {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
    try {
        const res = await fetch(url, { headers: headers ?? { Accept: 'application/json' }, signal: ctrl.signal });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } finally {
        clearTimeout(t);
    }
}

async function getText(url: string, headers?: Record<string, string>): Promise<string | null> {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), HTTP_TIMEOUT_MS);
    try {
        const res = await fetch(url, { headers, signal: ctrl.signal });
        if (!res.ok || !res.body) return null;
        // Stream with a byte cap rather than buffering the whole body, so a large response stays
        // bounded in memory before we slice it (mirrors the tarball download path).
        const reader = res.body.getReader();
        const chunks: Buffer[] = [];
        let total = 0;
        for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            if (!value) continue;
            chunks.push(Buffer.from(value));
            total += value.byteLength;
            if (total >= MAX_FILE_BYTES) {
                try { await reader.cancel(); } catch { /* ignore */ }
                break;
            }
        }
        return Buffer.concat(chunks).slice(0, MAX_FILE_BYTES).toString('utf8');
    } catch {
        return null;
    } finally {
        clearTimeout(t);
    }
}

// --- dependency scan ----------------------------------------------------------------------------
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
    return {
        name,
        version: manifest.version ?? 'latest',
        hooks,
        findings,
        verdict: verdictForSeverity(maxSeverityRank(findings.map((f) => f.severity))),
    };
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

// --- GitHub file access (for the self-scan) -----------------------------------------------------
async function getRepoMeta(owner: string, repo: string): Promise<{ defaultBranch: string } | null> {
    try {
        const meta = (await getJson(`${GH_API}/repos/${owner}/${repo}`, ghHeaders(true))) as { default_branch?: string };
        return { defaultBranch: meta.default_branch ?? 'HEAD' };
    } catch {
        return null;
    }
}

async function getTree(owner: string, repo: string, branch: string): Promise<string[]> {
    try {
        const tree = (await getJson(
            `${GH_API}/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
            ghHeaders(true),
        )) as { tree?: { path: string; type: string }[] };
        return (tree.tree ?? []).filter((n) => n.type === 'blob').map((n) => n.path);
    } catch {
        return [];
    }
}

function makeReader(owner: string, repo: string, branch: string): (path: string) => Promise<string | null> {
    return async (path: string) => {
        // With a token we use the contents API (works for private repos); otherwise raw (no rate limit).
        if (env.githubToken) {
            try {
                const data = (await getJson(
                    `${GH_API}/repos/${owner}/${repo}/contents/${path.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(branch)}`,
                    ghHeaders(true),
                )) as { content?: string; encoding?: string };
                if (data.encoding === 'base64' && data.content) {
                    const text = Buffer.from(data.content, 'base64').toString('utf8');
                    return text.length > MAX_FILE_BYTES ? text.slice(0, MAX_FILE_BYTES) : text;
                }
            } catch {
                /* fall through to raw */
            }
        }
        return getText(`${RAW}/${owner}/${repo}/${branch}/${path}`, ghHeaders());
    };
}

// Open a repo for reading: resolve the default branch, list files, return a passive file reader.
// Used by the Pro AI pass to read the LIVE source the analyst needs.
export async function openRepo(owner: string, repo: string): Promise<RepoFiles> {
    if (!validRepoRef(owner, repo)) return { paths: [], read: async () => null };
    const meta = await getRepoMeta(owner, repo);
    const branch = meta?.defaultBranch ?? 'HEAD';
    const read = makeReader(owner, repo, branch);
    const paths = await getTree(owner, repo, branch);
    return { paths: paths.length ? paths : ['package.json'], read };
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
        self: null,
        worst: Verdict.SAFE,
        error,
    });

    if (!validRepoRef(owner, repo)) return empty('invalid repo identifier');

    const meta = await getRepoMeta(owner, repo);
    const branch = meta?.defaultBranch ?? 'HEAD';
    const read = makeReader(owner, repo, branch);

    // package.json drives the dependency scan; absence ⇒ not a Node project.
    const pkgText = await read('package.json');
    if (pkgText == null) return empty('no package.json (not a Node project?)');
    let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
    try {
        pkg = JSON.parse(pkgText);
    } catch {
        return empty('package.json is not valid JSON');
    }

    // 1. Dependency scan.
    const allNames = [...new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})])];
    const names = allNames.slice(0, MAX_DEPS);
    const depResults = (await pool(names, CONCURRENCY, scanDep)).filter((r): r is DepFinding => r !== null);
    const flagged = depResults
        .filter((r) => r.verdict !== Verdict.SAFE)
        .sort((a, b) => VERDICT_RANK[b.verdict] - VERDICT_RANK[a.verdict]);

    // 2. Self scan (the repo's own files).
    const paths = await getTree(owner, repo, branch);
    const files: RepoFiles = { paths: paths.length ? paths : ['package.json'], read };
    const self = await selfScan(files);

    const worst = worseVerdict(flagged[0]?.verdict ?? Verdict.SAFE, self.worst);

    return {
        found: true,
        repo: id,
        totalDeps: allNames.length,
        scanned: names.length,
        withHooks: depResults.length,
        flagged,
        self,
        worst,
    };
}
