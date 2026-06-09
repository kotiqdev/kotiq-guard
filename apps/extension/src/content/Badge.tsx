import { useEffect, useState } from 'react';

import { REQUIRE_AUTH } from '../config';
import type { LiteResult } from '../lite/engine';
import { loadSession, SESSION_KEY, type Session } from '../session';
import { AiBlock } from '../ui/AiBlock';
import { ConsentGate, useAcked } from '../ui/consent';
import { Dock } from '../ui/Dock';
import { SignInBadge } from '../ui/SignInBadge';
import { Spinner } from '../ui/primitives';
import { badgePill, dropdownPanel, panel, pillName, sectionLabel, SEV_COLOR, VERDICT_COLOR } from '../ui/theme';

type ScanResult = {
    verdict: string;
    effective_verdict?: string;
    summary?: string;
    explanation?: string;
    scanned_version?: string | null;
    scripts?: { hooks?: Record<string, string>; readable?: string[] };
    security?: { level?: string; note?: string };
    // Deterministic reasons behind the verdict (surfaced so the user sees WHY without the AI).
    top_findings?: { severity?: string; title?: string; explanation?: string; file?: string | null }[];
    reputation?: { source?: string; severity?: string; summary?: string }[];
};

// The exact version the user is viewing — ONLY from the /v/<version> URL. We deliberately do NOT read
// npm's embedded page JSON: on SPA navigation it lags one package behind, which made us scan a
// non-existent spec like express@<prev-pkg-version>. No /v/ in the URL → null → scan latest, and show
// the version the backend actually resolved (data.scanned_version).
function versionFromPage(): string | null {
    const u = location.pathname.match(/\/v\/([^/]+)/);
    return u ? decodeURIComponent(u[1]) : null;
}

// /package/<name> or /package/@scope/name, with the page's version appended when we can find it.
function packageSpecFromPage(): string | null {
    const m = location.pathname.match(/^\/package\/((?:@[^/]+\/)?[^/]+)/);
    if (!m) return null;
    const name = decodeURIComponent(m[1]);
    const version = versionFromPage();
    return version ? `${name}@${version}` : name;
}

// Just the package name for display (drop a trailing @version; a scoped name keeps its @scope/).
function pkgNameFromSpec(spec: string | null): string {
    if (!spec) return '';
    const at = spec.lastIndexOf('@');
    return at > 0 ? spec.slice(0, at) : spec;
}

// Reply shape from the background worker for scan/explain.
type ScanReply = { ok?: boolean; status?: number; data?: ScanResult | null; aborted?: boolean; error?: string };

// Shown for a valid Google user who isn't allow-listed (Pro). Runs the LIGHT engine in the browser
// (install-hook commands from the registry + signatures). Deterministic only — AI is a Pro feature.
function LiteBadge({ pkg, pageVersion }: { pkg: string; pageVersion: string | null }) {
    const [open, setOpen] = useState(false);
    const [result, setResult] = useState<LiteResult | null>(null);

    useEffect(() => {
        void chrome.runtime
            .sendMessage({ type: 'liteScan', pkg })
            .then((r: { result?: LiteResult }) => setResult(r?.result ?? null))
            .catch(() => setResult(null));
    }, [pkg]);

    const color = (result && VERDICT_COLOR[result.verdict]) || '#9aa0a6';
    const version = pageVersion ?? result?.version ?? null;

    return (
        <Dock status={{ busy: !result, color: result ? color : undefined }}>
            <div onClick={() => setOpen((o) => !o)} style={badgePill(color)}>
                <span style={pillName}>{pkgNameFromSpec(pkg)}</span>: {result?.verdict ?? '…'}
                {version && <span style={{ marginLeft: 6, fontWeight: 400, opacity: 0.85 }}>· {version}</span>}
                <span style={{ marginLeft: 6, fontSize: 10, fontWeight: 700, letterSpacing: 0.5, background: 'rgba(255,255,255,.25)', borderRadius: 999, padding: '1px 6px' }}>
                    LITE
                </span>
            </div>
            {open && result && (
                <div style={{ ...dropdownPanel, width: 320, overflow: 'hidden' }}>
                    <div style={{ ...panel, color: '#57606a' }}>
                        <div style={sectionLabel}>What Kotiq checked</div>
                        {result.note}
                    </div>
                    <div style={{ padding: '10px 12px', color: '#8a929b', fontSize: 11 }}>
                        Pro runs the full cloud analysis — multi-agent Gemini reads the script source + a known-CVE check.
                        Request access from the Kotiq toolbar icon.
                    </div>
                </div>
            )}
        </Dock>
    );
}

export function Badge() {
    const [pkg, setPkg] = useState(packageSpecFromPage());
    const [pageVersion, setPageVersion] = useState(versionFromPage());
    const [data, setData] = useState<ScanResult | null>(null); // fast deterministic scan
    const [full, setFull] = useState<ScanResult | null>(null); // after "Explain" (LLM agents)
    const [loading, setLoading] = useState(false);
    const [open, setOpen] = useState(false);
    const [showVersionInfo, setShowVersionInfo] = useState(false);
    // undefined = still reading storage · null = signed out · Session = signed in
    const [session, setSession] = useState<Session | null | undefined>(undefined);
    const [authBusy, setAuthBusy] = useState(false);
    const [authError, setAuthError] = useState<string | null>(null);
    const [lite, setLite] = useState(false); // true when the backend says we're not allow-listed (403)
    const acked = useAcked(); // first-run consent gate (must accept before any scan)

    useEffect(() => {
        void loadSession().then((s) => setSession(s));
    }, []);

    // Live-update when the popup or background signs in/out (storage changes in another context).
    useEffect(() => {
        const onChange = (changes: Record<string, chrome.storage.StorageChange>, area: string): void => {
            if (area !== 'local' || !(SESSION_KEY in changes)) return;
            void loadSession().then((s) => {
                setData(null);
                setFull(null);
                setLite(false);
                setSession(s ?? null);
            });
        };
        chrome.storage.onChanged.addListener(onChange);
        return () => chrome.storage.onChanged.removeListener(onChange);
    }, []);

    // npm is a SPA — going to another package changes the URL via history (no full reload), so the
    // content script never re-reads. Poll the URL; on a package change hide the stale verdict and
    // re-scan. A short settle delay lets the SPA render the new package's data before we read it.
    useEffect(() => {
        let lastHref = location.href;
        let settle: ReturnType<typeof setTimeout>;
        const id = setInterval(() => {
            if (location.href === lastHref) return;
            lastHref = location.href;
            setData(null);
            setFull(null);
            setLite(false);
            setOpen(false);
            clearTimeout(settle);
            settle = setTimeout(() => {
                setPkg(packageSpecFromPage());
                setPageVersion(versionFromPage());
            }, 500);
        }, 600);
        return () => {
            clearInterval(id);
            clearTimeout(settle);
        };
    }, []);

    useEffect(() => {
        if (acked !== true || !pkg || session === undefined) return; // consent + session first
        if (REQUIRE_AUTH && !session) return; // not signed in → never touch the cloud
        let cancelled = false; // a newer scan / navigation supersedes this one
        // Go through the background worker: content scripts can't reach localhost (Chrome blocks
        // public-page → loopback). The background context (host_permissions) can.
        void chrome.runtime
            .sendMessage({ type: 'scan', pkg, from: location.href })
            .then((r: ScanReply) => {
                if (cancelled) return;
                if (r?.status === 401) return setSession(null); // token rejected → sign-in badge
                if (r?.status === 403) return setLite(true); // valid user, not allow-listed → Lite
                if (r?.ok && r.data) setData(r.data);
                else setData({ verdict: 'error' });
            })
            .catch(() => {
                if (!cancelled) setData({ verdict: 'error' });
            });
        return () => {
            cancelled = true;
        };
    }, [acked, pkg, session]);

    // Ask the background worker to run the Google sign-in flow (content scripts can't do it).
    async function doSignIn() {
        setAuthBusy(true);
        setAuthError(null);
        console.info('[kotiq] sign-in requested → asking background to start Google flow');
        try {
            const resp = (await chrome.runtime.sendMessage({ type: 'signIn' })) as
                | { ok: true; session: Session }
                | { ok: false; error: string };
            if (resp.ok) {
                console.info('[kotiq] signed in as', resp.session.email);
                setSession(resp.session);
            } else {
                console.warn('[kotiq] sign-in failed:', resp.error);
                setAuthError(resp.error);
            }
        } catch (e) {
            console.warn('[kotiq] sign-in error:', (e as Error).message);
            setAuthError((e as Error).message);
        } finally {
            setAuthBusy(false);
        }
    }

    if (!pkg) return null;
    if (acked === undefined) return null; // waiting on the consent flag
    if (!acked) return <ConsentGate />; // must acknowledge before scanning
    if (REQUIRE_AUTH && session === null) {
        return (
            <SignInBadge
                onSignIn={doSignIn}
                busy={authBusy}
                error={authError}
                label="Sign in with Google"
                title="Sign in with Google (the only sign-in method) to scan this package"
            />
        );
    }
    if (lite) return <LiteBadge pkg={pkg} pageVersion={pageVersion} />;
    if (!data) {
        // Immediate feedback while the scan runs (otherwise the badge would silently appear late).
        return (
            <Dock status={{ busy: true }}>
                <div style={{ ...badgePill('#6e7781', 'default'), display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Spinner size={13} color="#ffffff" />
                    <span style={pillName}>{pkgNameFromSpec(pkg)}</span> · scanning…
                </div>
            </Dock>
        );
    }

    // Badge reflects the effective verdict (security can escalate it once we've run the agents).
    const shown = full?.effective_verdict ?? data.verdict;
    const color = VERDICT_COLOR[shown] ?? '#6e7781';
    const pkgName = pkgNameFromSpec(pkg);

    const version = pageVersion ?? data.scanned_version ?? null;
    const isFallback = !pageVersion && !!data.scanned_version;

    const scripts = (full ?? data).scripts;
    const hookNames = scripts?.hooks ? Object.keys(scripts.hooks) : [];
    const readable = scripts?.readable ?? [];
    const sec = full?.security;
    const findings = (full ?? data).top_findings ?? [];
    const reputation = (full ?? data).reputation ?? [];

    async function explain() {
        setLoading(true);
        try {
            const r = (await chrome.runtime.sendMessage({ type: 'explain', pkg, from: location.href })) as ScanReply;
            if (r.aborted) return; // user cancelled
            if (r.ok && r.data) setFull(r.data);
            else setFull({ verdict: data!.verdict, explanation: 'Could not reach the server.' });
        } finally {
            setLoading(false);
        }
    }

    function cancel() {
        void chrome.runtime.sendMessage({ type: 'cancel' });
        setLoading(false);
    }

    return (
        <Dock status={{ busy: loading, color }}>
            <div onClick={() => setOpen((o) => !o)} title={data.summary} style={badgePill(color)}>
                <span style={pillName}>{pkgName}</span>: {shown}
                {version && (
                    <span style={{ marginLeft: 6, fontWeight: 400, opacity: isFallback ? 0.55 : 0.85 }}>
                        · {version}
                        {isFallback && (
                            <span
                                onClick={(e) => {
                                    e.stopPropagation();
                                    setShowVersionInfo((s) => !s);
                                }}
                                title="Version resolved by Kotiq, not read from the page"
                                style={{ marginLeft: 4, cursor: 'help' }}
                            >
                                ⓘ
                            </span>
                        )}
                    </span>
                )}
            </div>

            {showVersionInfo && isFallback && (
                <div
                    style={{
                        marginTop: 6,
                        width: 340,
                        background: '#fff',
                        color: '#57606a',
                        border: '1px solid #d0d7de',
                        borderRadius: 8,
                        boxShadow: '0 4px 16px rgba(0,0,0,.18)',
                        padding: '10px 12px',
                        lineHeight: 1.45,
                    }}
                >
                    Couldn't read the version from this page — showing <b>{version}</b>, the version Kotiq's engine
                    resolved and scanned.
                </div>
            )}

            {open && (
                <div style={{ ...dropdownPanel, width: 340, overflow: 'hidden' }}>
                    {/* AI explanation — at the TOP, matching the repo badge */}
                    <div style={panel}>
                        <AiBlock
                            busy={loading}
                            text={full?.explanation}
                            agentsLabel="security ⇄ critic"
                            disclaimer="AI summary — double-check critical installs."
                            onExplain={explain}
                            onCancel={cancel}
                        />
                    </div>

                    {/* Why this verdict — deterministic findings + OSINT signals (shown without the AI) */}
                    {(findings.length > 0 || reputation.length > 0) && (
                        <div style={{ ...panel, color: '#57606a' }}>
                            <div style={sectionLabel}>Why this verdict</div>
                            {findings.map((f, i) => (
                                <div key={`f${i}`} style={{ marginTop: i ? 6 : 0 }}>
                                    <span style={{ color: SEV_COLOR[f.severity ?? ''] ?? '#6e7781', fontWeight: 700, fontSize: 11 }}>
                                        {(f.severity ?? '').toUpperCase()}
                                    </span>{' '}
                                    {f.title}
                                    {f.explanation && <div style={{ fontSize: 12, color: '#8a929b', marginTop: 1 }}>{f.explanation}</div>}
                                </div>
                            ))}
                            {reputation.map((r, i) => (
                                <div key={`r${i}`} style={{ marginTop: findings.length || i ? 6 : 0 }}>
                                    <span style={{ color: SEV_COLOR[r.severity ?? ''] ?? '#6e7781', fontWeight: 700, fontSize: 11 }}>
                                        {(r.severity ?? '').toUpperCase()}
                                    </span>{' '}
                                    {r.summary}
                                    {r.source && <span style={{ fontSize: 11, color: '#8a929b' }}> · {r.source}</span>}
                                </div>
                            ))}
                        </div>
                    )}

                    {/* What Kotiq checked (from the instant deterministic scan) */}
                    <div style={{ ...panel, color: '#57606a' }}>
                        <div style={sectionLabel}>What Kotiq checked</div>
                        {hookNames.length ? (
                            <>
                                <b>Install hooks:</b> {hookNames.join(', ')}
                                <div style={{ fontSize: 12, marginTop: 2 }}>
                                    {readable.length
                                        ? `script source read: ${readable.join(', ')}`
                                        : 'script source not shipped — Kotiq could not read it'}
                                </div>
                            </>
                        ) : (
                            'No install hooks declared.'
                        )}
                    </div>

                    {/* Security agent escalation (after Explain) */}
                    {sec?.level && sec.level !== 'ok' && (
                        <div style={{ ...panel, color: VERDICT_COLOR.SUSPICIOUS, fontWeight: 600 }}>
                            ⚠ Security review: {sec.level.toUpperCase()}
                            <div style={{ fontWeight: 400, fontSize: 12, marginTop: 2 }}>{sec.note}</div>
                        </div>
                    )}
                </div>
            )}
        </Dock>
    );
}
