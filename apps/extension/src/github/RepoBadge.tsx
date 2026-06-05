import { useEffect, useState } from 'react';

import { REQUIRE_AUTH } from '../config';
import type { RepoResult } from '../lite/repo';
import { loadSession, type Session } from '../session';

const COLORS: Record<string, string> = {
    SAFE: '#1a7f37',
    NEEDS_REVIEW: '#6e7781',
    SUSPICIOUS: '#bf8700',
    MALICIOUS: '#cf222e',
};

// First path segments on github.com that are NOT a user/org repo root.
const RESERVED = new Set([
    'features', 'marketplace', 'settings', 'orgs', 'notifications', 'explore', 'topics', 'sponsors',
    'about', 'pricing', 'login', 'signup', 'new', 'search', 'codespaces', 'apps', 'collections',
    'events', 'pulls', 'issues', 'dashboard', 'account', 'organizations',
]);

function repoFromUrl(): { owner: string; repo: string } | null {
    const seg = location.pathname.split('/').filter(Boolean);
    if (seg.length < 2) return null;
    const [owner, repo] = seg;
    if (RESERVED.has(owner.toLowerCase())) return null;
    return { owner, repo };
}

const shell = { position: 'fixed', top: 12, right: 12, zIndex: 99999, font: '13px system-ui, sans-serif' } as const;
const pill = (bg: string, cursor = 'pointer') =>
    ({ padding: '8px 12px', borderRadius: 8, color: '#fff', fontWeight: 600, background: bg, cursor, boxShadow: '0 2px 8px rgba(0,0,0,.2)' }) as const;

export function RepoBadge() {
    const [target] = useState(repoFromUrl());
    const [session, setSession] = useState<Session | null | undefined>(undefined);
    const [authBusy, setAuthBusy] = useState(false);
    const [result, setResult] = useState<RepoResult | null>(null);
    const [open, setOpen] = useState(false);

    useEffect(() => {
        void loadSession().then((s) => setSession(s));
    }, []);

    useEffect(() => {
        if (!target || session === undefined) return;
        if (REQUIRE_AUTH && !session) return; // need sign-in first
        void chrome.runtime
            .sendMessage({ type: 'repoScan', owner: target.owner, repo: target.repo })
            .then((r: { status?: number; result?: RepoResult }) => {
                if (r?.status === 401) return setSession(null);
                setResult(r?.result ?? null);
            })
            .catch(() => setResult(null));
    }, [target, session]);

    async function doSignIn() {
        setAuthBusy(true);
        try {
            const resp = (await chrome.runtime.sendMessage({ type: 'signIn' })) as { ok: boolean; session?: Session };
            if (resp.ok && resp.session) setSession(resp.session);
        } finally {
            setAuthBusy(false);
        }
    }

    if (!target) return null;

    if (REQUIRE_AUTH && session === null) {
        return (
            <div style={shell}>
                <div
                    onClick={authBusy ? undefined : doSignIn}
                    title="Sign in with Google to scan this repo's dependencies"
                    style={{ ...pill('#6e7781', authBusy ? 'default' : 'pointer'), opacity: authBusy ? 0.7 : 1 }}
                >
                    🔒 Kotiq · {authBusy ? 'Signing in…' : 'Sign in to scan deps'}
                </div>
            </div>
        );
    }

    if (!result || !result.found) return null; // not a Node repo → show nothing

    const color = COLORS[result.worst] ?? '#6e7781';
    const panel = { padding: '10px 12px', borderBottom: '1px solid #eaeef2' } as const;

    return (
        <div style={shell}>
            <div onClick={() => setOpen((o) => !o)} style={pill(color)}>
                🐱 Kotiq: {result.worst}
                <span style={{ marginLeft: 6, fontWeight: 400, opacity: 0.85 }}>· {result.withHooks} hook deps</span>
            </div>

            {open && (
                <div style={{ marginTop: 6, width: 360, background: '#fff', color: '#24292f', border: '1px solid #d0d7de', borderRadius: 8, boxShadow: '0 4px 16px rgba(0,0,0,.18)', overflow: 'hidden' }}>
                    <div style={{ ...panel, color: '#57606a' }}>
                        <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.4px', color: '#8a929b', marginBottom: 4 }}>
                            Dependency scan · {result.repo}
                        </div>
                        <b>{result.totalDeps}</b> dependencies · <b>{result.withHooks}</b> run install hooks
                        {result.scanned < result.totalDeps && <> · scanned {result.scanned}</>}
                    </div>

                    {result.flagged.length ? (
                        <div style={panel}>
                            <div style={{ color: COLORS.SUSPICIOUS, fontWeight: 600, marginBottom: 6 }}>⚠ Risky dependencies</div>
                            {result.flagged.slice(0, 8).map((d) => (
                                <div key={d.name} style={{ marginBottom: 6 }}>
                                    <span style={{ fontWeight: 600, color: COLORS[d.verdict] }}>{d.verdict}</span>{' '}
                                    <code>{d.name}@{d.version}</code>
                                    <div style={{ fontSize: 12, color: '#57606a', marginTop: 1 }}>{d.findings.map((f) => f.label).join('; ')}</div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div style={{ ...panel, color: '#1a7f37' }}>No dependency runs a risky install hook.</div>
                    )}

                    <div style={{ padding: '10px 12px', color: '#8a929b', fontSize: 11 }}>
                        Scanned on Kotiq's server — install-hook commands of direct deps. Pro adds source + known CVEs.
                    </div>
                </div>
            )}
        </div>
    );
}
