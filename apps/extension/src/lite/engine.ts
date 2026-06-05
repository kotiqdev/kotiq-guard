// Lite engine — runs in the browser (background worker). Fetches a package's install-hook COMMANDS
// from the npm registry packument (no tarball, no OSINT) and scans them with the signatures.
// Lighter than Pro (which reads the actual script source + known CVEs), but the same hard floor:
// a CRITICAL signature → MALICIOUS regardless of tier.

import { type Severity, scan } from './signatures';

const REGISTRY = 'https://registry.npmjs.org';
const RUN_HOOKS = ['preinstall', 'install', 'postinstall'] as const; // run on a dependency install
const ALL_HOOKS = ['preinstall', 'install', 'postinstall', 'prepare'] as const;

export type Verdict = 'SAFE' | 'NEEDS_REVIEW' | 'SUSPICIOUS' | 'MALICIOUS';

export interface LiteFinding {
    hook: string;
    label: string;
    severity: Severity;
    snippet: string;
}
export interface LiteResult {
    found: boolean;
    verdict: Verdict;
    version: string | null;
    hooks: Record<string, string>;
    findings: LiteFinding[];
    note: string;
    error?: string;
}

const SEV_RANK: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export function splitSpec(spec: string): { name: string; version: string | null } {
    const t = spec.trim();
    const at = t.lastIndexOf('@');
    if (at > 0) return { name: t.slice(0, at), version: t.slice(at + 1) };
    return { name: t, version: null };
}

function encodeName(name: string): string {
    if (name.startsWith('@')) {
        const slash = name.indexOf('/');
        if (slash > 0) return `@${encodeURIComponent(name.slice(1, slash))}%2F${encodeURIComponent(name.slice(slash + 1))}`;
    }
    return encodeURIComponent(name);
}

function fail(msg: string): LiteResult {
    return { found: false, verdict: 'NEEDS_REVIEW', version: null, hooks: {}, findings: [], note: '', error: msg };
}

function buildNote(hooks: Record<string, string>, runHooks: string[], findings: LiteFinding[]): string {
    if (findings.length) {
        return `⚠ Found in install commands: ${findings.map((f) => f.label).join('; ')}.`;
    }
    if (runHooks.length) {
        return `Runs install hook(s): ${runHooks.join(', ')}. Commands look clean. Lite checks commands only — Pro reads the actual script source + known CVEs.`;
    }
    if (hooks.prepare) {
        return `Only a "prepare" hook — it doesn't run when installed as a dependency.`;
    }
    return 'No install hooks. Nothing runs on install.';
}

export async function liteScan(spec: string): Promise<LiteResult> {
    const { name, version } = splitSpec(spec);

    let doc: Record<string, unknown>;
    try {
        const res = await fetch(`${REGISTRY}/${encodeName(name)}`, { headers: { Accept: 'application/json' } });
        if (res.status === 404) return fail('package not found in the npm registry');
        if (!res.ok) return fail(`registry returned HTTP ${res.status}`);
        doc = (await res.json()) as Record<string, unknown>;
    } catch (e) {
        return fail((e as Error).message);
    }

    const distTags = (doc['dist-tags'] ?? {}) as Record<string, string>;
    const versions = (doc.versions ?? {}) as Record<string, { scripts?: Record<string, string> }>;
    const resolved = version ?? distTags.latest;
    const ver = resolved ? versions[resolved] : undefined;
    if (!ver) return fail(`version ${version ?? 'latest'} not found`);

    const scripts = ver.scripts ?? {};
    const hooks: Record<string, string> = {};
    for (const h of ALL_HOOKS) if (typeof scripts[h] === 'string') hooks[h] = scripts[h];

    // Scan only hooks that actually run on a dependency install (skip prepare).
    const findings: LiteFinding[] = [];
    for (const h of RUN_HOOKS) {
        const cmd = hooks[h];
        if (!cmd) continue;
        for (const hit of scan(cmd)) findings.push({ hook: h, label: hit.label, severity: hit.severity, snippet: hit.snippet });
    }

    const maxSev = findings.reduce((m, f) => Math.max(m, SEV_RANK[f.severity]), 0);
    const runHooks = RUN_HOOKS.filter((h) => hooks[h]);

    let verdict: Verdict = 'SAFE';
    if (maxSev >= SEV_RANK.CRITICAL) verdict = 'MALICIOUS';
    else if (maxSev >= SEV_RANK.HIGH) verdict = 'SUSPICIOUS';
    else if (maxSev >= SEV_RANK.MEDIUM) verdict = 'NEEDS_REVIEW';

    return { found: true, verdict, version: resolved ?? null, hooks, findings, note: buildNote(hooks, runHooks, findings) };
}
