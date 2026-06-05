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

const SEV_COLOR: Record<string, string> = {
    INFO: '#6e7781',
    LOW: '#6e7781',
    MEDIUM: '#bf8700',
    HIGH: '#bc4c00',
    CRITICAL: '#cf222e',
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
    const [scanning, setScanning] = useState(false);
    const [open, setOpen] = useState(false);
    const [ai, setAi] = useState<{ loading: boolean; text?: string; error?: string; pro?: boolean } | null>(null);

    useEffect(() => {
        void loadSession().then((s) => setSession(s));
    }, []);

    useEffect(() => {
        if (!target || session === undefined) return;
        if (REQUIRE_AUTH && !session) return; // need sign-in first
        setScanning(true);
        void chrome.runtime
            .sendMessage({ type: 'repoScan', owner: target.owner, repo: target.repo })
            .then((r: { status?: number; result?: RepoResult }) => {
                if (r?.status === 401) return setSession(null);
                setResult(r?.result ?? null);
            })
            .catch(() => setResult(null))
            .finally(() => setScanning(false));
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

    async function runExplain() {
        if (!target) return;
        setAi({ loading: true });
        try {
            const r = (await chrome.runtime.sendMessage({ type: 'repoExplain', owner: target.owner, repo: target.repo })) as {
                ok?: boolean;
                status?: number;
                result?: { explanation?: string };
                error?: string;
            };
            if (r?.status === 403) return setAi({ loading: false, pro: true });
            if (r?.ok && r.result?.explanation) return setAi({ loading: false, text: r.result.explanation });
            setAi({ loading: false, error: r?.error ?? 'AI explanation unavailable — is the model running?' });
        } catch (e) {
            setAi({ loading: false, error: (e as Error).message });
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

    // Signed-in users see Kotiq working while GitHub is being analyzed (it can take a few seconds).
    if (scanning && !result) {
        return (
            <div style={shell}>
                <style>{'@keyframes kotiqPulse{0%,100%{opacity:.5}50%{opacity:1}}'}</style>
                <div style={{ ...pill('#6e7781', 'default'), animation: 'kotiqPulse 1.2s ease-in-out infinite' }}>
                    🐱 Kotiq · scanning repo…
                </div>
            </div>
        );
    }

    if (!result || !result.found) return null; // not a Node repo → show nothing

    const color = COLORS[result.worst] ?? '#6e7781';
    const panel = { padding: '10px 12px', borderBottom: '1px solid #eaeef2' } as const;
    const selfFindings = result.self?.findings ?? [];
    const what = result.self?.what ?? [];
    const subtitle = selfFindings.length
        ? `· ${selfFindings.length} repo risk${selfFindings.length > 1 ? 's' : ''}`
        : `· ${result.withHooks} hook deps`;

    return (
        <div style={shell}>
            <div onClick={() => setOpen((o) => !o)} style={pill(color)}>
                🐱 Kotiq: {result.worst}
                <span style={{ marginLeft: 6, fontWeight: 400, opacity: 0.85 }}>{subtitle}</span>
            </div>

            {open && (
                <div style={{ marginTop: 6, width: 360, maxHeight: '70vh', overflowY: 'auto', background: '#fff', color: '#24292f', border: '1px solid #d0d7de', borderRadius: 8, boxShadow: '0 4px 16px rgba(0,0,0,.18)' }}>
                    {result.worst !== 'SAFE' && (
                        <div style={panel}>
                            {!ai && (
                                <button
                                    onClick={runExplain}
                                    style={{ width: '100%', padding: '9px 12px', border: '1px solid #d0d7de', borderRadius: 8, background: '#f6f8fa', color: '#24292f', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}
                                >
                                    ✨ Explain with AI
                                    <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.4px', color: '#fff', background: '#1a7f37', borderRadius: 999, padding: '1px 6px' }}>PRO</span>
                                </button>
                            )}
                            {ai?.loading && <div style={{ fontSize: 12, color: '#57606a' }}>Analyzing with Kotiq's agents (analyst ⇄ critic)…</div>}
                            {ai?.text && (
                                <>
                                    <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.4px', color: '#8a929b', marginBottom: 6 }}>✨ AI analysis</div>
                                    <div style={{ fontSize: 12.5, lineHeight: 1.45, whiteSpace: 'pre-wrap' }}>{ai.text}</div>
                                    <div style={{ fontSize: 10.5, color: '#8a929b', marginTop: 6 }}>AI summary, grounded in the findings below — double-check critical actions.</div>
                                </>
                            )}
                            {ai?.pro && (
                                <div style={{ fontSize: 12, color: '#57606a' }}>
                                    AI analysis is a Pro feature.{' '}
                                    <a href="https://kotiq.dev" target="_blank" rel="noreferrer" style={{ color: '#0969da' }}>Request Pro access</a>.
                                </div>
                            )}
                            {ai?.error && <div style={{ fontSize: 12, color: '#bc4c00' }}>{ai.error}</div>}
                        </div>
                    )}
                    {what.length > 0 && (
                        <div style={{ ...panel, background: '#fff8f8' }}>
                            <div style={{ color: COLORS.MALICIOUS, fontWeight: 700, marginBottom: 6 }}>⚠ What this repo does</div>
                            {what.map((w, i) => (
                                <div key={i} style={{ fontSize: 12, color: '#3d2222', marginBottom: 5, lineHeight: 1.35 }}>• {w}</div>
                            ))}
                        </div>
                    )}

                    {selfFindings.length > 0 && (
                        <div style={panel}>
                            <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.4px', color: '#8a929b', marginBottom: 6 }}>
                                Repo files
                            </div>
                            {selfFindings.map((f, i) => (
                                <div key={i} style={{ marginBottom: 7 }}>
                                    <span style={{ fontWeight: 700, color: SEV_COLOR[f.severity] ?? '#6e7781', fontSize: 11 }}>{f.severity}</span>{' '}
                                    <code style={{ fontSize: 11, color: '#57606a' }}>{f.file}</code>
                                    <div style={{ fontSize: 12, color: '#24292f', marginTop: 1 }}>{f.label}</div>
                                    {f.detail && <div style={{ fontSize: 11, color: '#8a929b', marginTop: 1, fontFamily: 'ui-monospace, monospace', wordBreak: 'break-all' }}>{f.detail}</div>}
                                </div>
                            ))}
                        </div>
                    )}

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
                        Scanned on Kotiq's server, passively — the repo's own scripts, .vscode tasks, source &amp; .env, plus each dependency's install hooks. Nothing is executed.
                    </div>
                </div>
            )}
        </div>
    );
}
