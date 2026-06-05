import { useEffect, useState } from 'react';

import { REQUIRE_AUTH } from '../config';
import type { LiteResult } from '../lite/engine';
import type { NanoStatus } from '../lite/nano';
import { loadSession, SESSION_KEY, type Session } from '../session';

const COLORS: Record<string, string> = {
    SAFE: '#1a7f37',
    SUSPICIOUS: '#bf8700',
    MALICIOUS: '#cf222e',
    NEEDS_REVIEW: '#6e7781',
};

// Matrix-style "Explain with AI" button: dark grey, glowing green text; brighter on hover, flashes on click.
const BTN_CSS = `
.kotiq-explain {
  width: 100%; padding: 8px 14px; border: 1px solid #00ff41; border-radius: 6px;
  background: #2a2a2a; color: #00ff41;
  font: 700 13px ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: .3px;
  text-shadow: 0 0 6px rgba(0,255,65,.45); cursor: pointer;
  transition: background .15s, box-shadow .15s, text-shadow .15s, color .15s, transform .05s;
}
.kotiq-explain:hover {
  background: #333; border-color: #5bff86; color: #5bff86;
  text-shadow: 0 0 10px rgba(0,255,65,.9); box-shadow: 0 0 12px rgba(0,255,65,.35);
}
.kotiq-explain:active { transform: scale(.98); background: #00ff41; color: #08240f; text-shadow: none; }
.kotiq-explain:disabled { cursor: default; opacity: .6; box-shadow: none; text-shadow: none; }
.kotiq-explain.loading { border-color: #ff5f56; color: #ff7b73; text-shadow: 0 0 6px rgba(255,95,86,.5); }
.kotiq-explain.loading:hover { background: #3a2a2a; box-shadow: 0 0 12px rgba(255,95,86,.4); }
`;

type ScanResult = {
    verdict: string;
    effective_verdict?: string;
    summary?: string;
    explanation?: string;
    scanned_version?: string | null;
    scripts?: { hooks?: Record<string, string>; readable?: string[] };
    security?: { level?: string; note?: string };
};

// The exact version the user is viewing: from the /v/<version> URL, else npm's embedded page data.
function versionFromPage(): string | null {
    const u = location.pathname.match(/\/v\/([^/]+)/);
    if (u) return decodeURIComponent(u[1]);
    for (const s of Array.from(document.querySelectorAll('script'))) {
        const m = (s.textContent ?? '').match(/"packageVersion":\{[\s\S]*?"version":"([^"]+)"/);
        if (m) return m[1];
    }
    return null;
}

// /package/<name> or /package/@scope/name, with the page's version appended when we can find it.
function packageSpecFromPage(): string | null {
    const m = location.pathname.match(/^\/package\/((?:@[^/]+\/)?[^/]+)/);
    if (!m) return null;
    const name = decodeURIComponent(m[1]);
    const version = versionFromPage();
    return version ? `${name}@${version}` : name;
}

// Reply shape from the background worker for scan/explain.
type ScanReply = { ok?: boolean; status?: number; data?: ScanResult | null; aborted?: boolean; error?: string };

// Shown when auth is required but the user isn't signed in. Clicking starts Google sign-in via the
// background worker. We never call the scan cloud here — only auth.
function SignInBadge({ onSignIn, busy, error }: { onSignIn: () => void; busy: boolean; error: string | null }) {
    return (
        <div style={{ position: 'fixed', top: 12, right: 12, zIndex: 99999, font: '13px system-ui, sans-serif' }}>
            <div
                onClick={busy ? undefined : onSignIn}
                title="Sign in with Google to scan this package"
                style={{
                    padding: '8px 12px',
                    borderRadius: 8,
                    color: '#fff',
                    fontWeight: 600,
                    background: '#6e7781',
                    boxShadow: '0 2px 8px rgba(0,0,0,.2)',
                    cursor: busy ? 'default' : 'pointer',
                    opacity: busy ? 0.7 : 1,
                }}
            >
                🔒 Kotiq · {busy ? 'Signing in…' : 'Sign in to scan'}
            </div>
            {error && (
                <div
                    style={{
                        marginTop: 6,
                        width: 280,
                        background: '#fff',
                        color: '#cf222e',
                        border: '1px solid #d0d7de',
                        borderRadius: 8,
                        boxShadow: '0 4px 16px rgba(0,0,0,.18)',
                        padding: '8px 10px',
                        lineHeight: 1.4,
                    }}
                >
                    {error}
                </div>
            )}
        </div>
    );
}

// Shown for a valid Google user who isn't allow-listed (Pro). Runs the LIGHT engine in the browser
// (install-hook commands from the registry + signatures) and offers an on-device Gemini Nano
// explanation — only when Nano is available. Same deterministic floor as Pro; lighter analysis.
function LiteBadge({ pkg, pageVersion }: { pkg: string; pageVersion: string | null }) {
    const [open, setOpen] = useState(false);
    const [result, setResult] = useState<LiteResult | null>(null);
    const [nano, setNano] = useState<NanoStatus | null>(null);
    const [explaining, setExplaining] = useState(false);
    const [explanation, setExplanation] = useState<string | null>(null);
    const [downloadPct, setDownloadPct] = useState<number | null>(null);

    // Model-download progress arrives via storage (background → here).
    useEffect(() => {
        const onChange = (changes: Record<string, chrome.storage.StorageChange>, area: string): void => {
            if (area !== 'local' || !('nanoProgress' in changes)) return;
            const v = changes.nanoProgress.newValue;
            setDownloadPct(typeof v === 'number' ? v : null);
        };
        chrome.storage.onChanged.addListener(onChange);
        return () => chrome.storage.onChanged.removeListener(onChange);
    }, []);

    useEffect(() => {
        void chrome.runtime
            .sendMessage({ type: 'liteScan', pkg })
            .then((r: { result?: LiteResult }) => setResult(r?.result ?? null))
            .catch(() => setResult(null));
        void chrome.runtime
            .sendMessage({ type: 'nanoStatus' })
            .then((r: { status?: NanoStatus }) => setNano(r?.status ?? 'unavailable'))
            .catch(() => setNano('unavailable'));
    }, [pkg]);

    const color = (result && COLORS[result.verdict]) || '#9aa0a6';
    const version = pageVersion ?? result?.version ?? null;
    const nanoOk = nano === 'available' || nano === 'downloadable' || nano === 'downloading';

    async function explain() {
        if (!result) return;
        setExplaining(true);
        try {
            const r = (await chrome.runtime.sendMessage({ type: 'liteExplain', result })) as { text?: string | null };
            setExplanation(r?.text ?? 'On-device AI could not produce an explanation.');
        } finally {
            setExplaining(false);
        }
    }

    return (
        <div style={{ position: 'fixed', top: 12, right: 12, zIndex: 99999, font: '13px system-ui, sans-serif' }}>
            <style>{BTN_CSS}</style>
            <div
                onClick={() => setOpen((o) => !o)}
                style={{ padding: '8px 12px', borderRadius: 8, color: '#fff', fontWeight: 600, background: color, cursor: 'pointer', boxShadow: '0 2px 8px rgba(0,0,0,.2)' }}
            >
                🐱 Kotiq: {result?.verdict ?? '…'}
                {version && <span style={{ marginLeft: 6, fontWeight: 400, opacity: 0.85 }}>· {version}</span>}
                <span style={{ marginLeft: 6, fontSize: 10, fontWeight: 700, letterSpacing: 0.5, background: 'rgba(255,255,255,.25)', borderRadius: 999, padding: '1px 6px' }}>
                    LITE
                </span>
                {downloadPct != null && <span style={{ marginLeft: 6, fontWeight: 400, opacity: 0.9 }}>· ⏳ {downloadPct}%</span>}
            </div>
            {open && result && (
                <div style={{ marginTop: 6, width: 320, background: '#fff', color: '#24292f', border: '1px solid #d0d7de', borderRadius: 8, boxShadow: '0 4px 16px rgba(0,0,0,.18)', overflow: 'hidden' }}>
                    <div style={{ padding: '10px 12px', borderBottom: '1px solid #eaeef2', color: '#57606a' }}>
                        <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '.4px', color: '#8a929b', marginBottom: 4 }}>What Kotiq checked</div>
                        {result.note}
                    </div>
                    <div style={{ padding: '10px 12px' }}>
                        {nanoOk ? (
                            <>
                                <button type="button" className="kotiq-explain" disabled={explaining} onClick={explain}>
                                    {explaining
                                        ? downloadPct != null
                                            ? `⏳ Downloading model… ${downloadPct}%`
                                            : '⏳ Thinking on-device…'
                                        : '⚡ Explain on-device'}
                                </button>
                                <div style={{ marginTop: 6, color: '#8a929b', fontSize: 11 }}>
                                    Runs Gemini Nano in your browser — private, nothing leaves your device. First use
                                    downloads the model once.
                                </div>
                                {explanation && (
                                    <>
                                        <div style={{ marginTop: 10, color: '#57606a', lineHeight: 1.45, whiteSpace: 'pre-wrap' }}>
                                            {explanation}
                                        </div>
                                        <div style={{ marginTop: 8, color: '#8a929b', fontSize: 11, fontStyle: 'italic' }}>
                                            On-device AI — a quick read, can be wrong. The verdict is from deterministic checks.
                                        </div>
                                    </>
                                )}
                            </>
                        ) : (
                            <div style={{ color: '#8a929b', fontSize: 12 }}>
                                On-device AI isn't available on this device — the verdict above still stands.
                            </div>
                        )}
                        <div style={{ marginTop: 10, color: '#8a929b', fontSize: 11 }}>
                            Pro runs the full cloud analysis — multi-agent Gemini + a known-CVE check. Request access from
                            the Kotiq toolbar icon.
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export function Badge() {
    const [pkg] = useState(packageSpecFromPage());
    const [pageVersion] = useState(versionFromPage());
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

    useEffect(() => {
        if (!pkg || session === undefined) return; // wait until we know the session
        if (REQUIRE_AUTH && !session) return; // not signed in → never touch the cloud
        // Go through the background worker: content scripts can't reach localhost (Chrome blocks
        // public-page → loopback). The background context (host_permissions) can.
        void chrome.runtime
            .sendMessage({ type: 'scan', pkg, from: location.href })
            .then((r: ScanReply) => {
                if (r?.status === 401) return setSession(null); // token rejected → sign-in badge
                if (r?.status === 403) return setLite(true); // valid user, not allow-listed → Lite
                if (r?.ok && r.data) setData(r.data);
                else setData({ verdict: 'error' });
            })
            .catch(() => setData({ verdict: 'error' }));
    }, [pkg, session]);

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
    if (REQUIRE_AUTH && session === null) {
        return <SignInBadge onSignIn={doSignIn} busy={authBusy} error={authError} />;
    }
    if (lite) return <LiteBadge pkg={pkg} pageVersion={pageVersion} />;
    if (!data) return null;

    // Badge reflects the effective verdict (security can escalate it once we've run the agents).
    const shown = full?.effective_verdict ?? data.verdict;
    const color = COLORS[shown] ?? '#6e7781';

    const version = pageVersion ?? data.scanned_version ?? null;
    const isFallback = !pageVersion && !!data.scanned_version;

    const scripts = (full ?? data).scripts;
    const hookNames = scripts?.hooks ? Object.keys(scripts.hooks) : [];
    const readable = scripts?.readable ?? [];
    const sec = full?.security;

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

    const panel = { padding: '10px 12px', borderBottom: '1px solid #eaeef2' } as const;

    return (
        <div style={{ position: 'fixed', top: 12, right: 12, zIndex: 99999, font: '13px system-ui, sans-serif' }}>
            <style>{BTN_CSS}</style>
            <div
                onClick={() => setOpen((o) => !o)}
                title={data.summary}
                style={{
                    padding: '8px 12px',
                    borderRadius: 8,
                    color: '#fff',
                    fontWeight: 600,
                    background: color,
                    cursor: 'pointer',
                    boxShadow: '0 2px 8px rgba(0,0,0,.2)',
                }}
            >
                🐱 Kotiq: {shown}
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
                <div
                    style={{
                        marginTop: 6,
                        width: 340,
                        background: '#fff',
                        color: '#24292f',
                        border: '1px solid #d0d7de',
                        borderRadius: 8,
                        boxShadow: '0 4px 16px rgba(0,0,0,.18)',
                        overflow: 'hidden',
                    }}
                >
                    {/* What Kotiq checked (from the instant deterministic scan) */}
                    <div style={{ ...panel, color: '#57606a' }}>
                        <div
                            style={{
                                fontSize: 11,
                                textTransform: 'uppercase',
                                letterSpacing: '.4px',
                                color: '#8a929b',
                                marginBottom: 4,
                            }}
                        >
                            What Kotiq checked
                        </div>
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
                        <div style={{ ...panel, color: COLORS.SUSPICIOUS, fontWeight: 600 }}>
                            ⚠ Security review: {sec.level.toUpperCase()}
                            <div style={{ fontWeight: 400, fontSize: 12, marginTop: 2 }}>{sec.note}</div>
                        </div>
                    )}

                    {/* AI explanation */}
                    <div style={{ padding: '10px 12px' }}>
                        <button
                            type="button"
                            className={`kotiq-explain${loading ? ' loading' : ''}`}
                            onClick={loading ? cancel : explain}
                        >
                            {loading ? '✕ Cancel — Thinking…' : full ? '🤖 Re-explain with AI' : '🤖 Explain with AI'}
                        </button>
                        {full?.explanation && (
                            <>
                                <div style={{ marginTop: 10, color: '#57606a', lineHeight: 1.45, whiteSpace: 'pre-wrap' }}>
                                    {full.explanation}
                                </div>
                                <div style={{ marginTop: 8, color: '#8a929b', fontSize: 11, fontStyle: 'italic' }}>
                                    AI summary — double-check critical installs.
                                </div>
                            </>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
