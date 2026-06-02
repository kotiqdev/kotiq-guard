import { useEffect, useState } from 'react';

const SERVER = 'http://localhost:8080';

const COLORS: Record<string, string> = {
    SAFE: '#1a7f37',
    SUSPICIOUS: '#bf8700',
    MALICIOUS: '#cf222e',
    NEEDS_REVIEW: '#6e7781',
};

type Verdict = {
    verdict: string;
    summary?: string;
    explanation?: string;
    scanned_version?: string | null;
};

// The exact version the user is viewing: from the /v/<version> URL, else npm's embedded page data.
function versionFromPage(): string | null {
    const u = location.pathname.match(/\/v\/([^/]+)/);
    if (u) return decodeURIComponent(u[1]);
    // npm embeds page data as `window.__context__` in a <script> tag; a content script can't read
    // the page's JS, but it CAN read the script tag's text from the DOM.
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

const from = encodeURIComponent(location.href);

export function Badge() {
    const [pkg] = useState(packageSpecFromPage());
    const [pageVersion] = useState(versionFromPage());
    const [data, setData] = useState<Verdict | null>(null);
    const [open, setOpen] = useState(false);
    const [explanation, setExplanation] = useState('');
    const [showVersionInfo, setShowVersionInfo] = useState(false);

    useEffect(() => {
        if (!pkg) return;
        // Fast path: deterministic verdict only (no LLM).
        fetch(`${SERVER}/scan?pkg=${encodeURIComponent(pkg)}&explain=false&from=${from}`)
            .then((r) => r.json())
            .then(setData)
            .catch(() => setData({ verdict: 'error' }));
    }, [pkg]);

    if (!pkg || !data) return null;
    const color = COLORS[data.verdict] ?? '#6e7781';

    // Prefer the version read off the page; otherwise fall back to whatever the engine resolved.
    const version = pageVersion ?? data.scanned_version ?? null;
    const isFallback = !pageVersion && !!data.scanned_version;

    async function explain() {
        setExplanation('Thinking…');
        try {
            const full: Verdict = await fetch(
                `${SERVER}/scan?pkg=${encodeURIComponent(pkg!)}&from=${from}`,
            ).then((r) => r.json());
            setExplanation(full.explanation || full.summary || '(no explanation)');
        } catch {
            setExplanation('Could not reach the server.');
        }
    }

    return (
        <div style={{ position: 'fixed', top: 12, right: 12, zIndex: 99999, font: '13px system-ui, sans-serif' }}>
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
                🐱 Kotiq: {data.verdict}
                {version && (
                    <span style={{ marginLeft: 6, fontWeight: 400, opacity: isFallback ? 0.55 : 0.85 }}>
                        · {version}
                        {isFallback && (
                            <span
                                onClick={(e) => {
                                    e.stopPropagation();
                                    setShowVersionInfo((v) => !v);
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
                        width: 320,
                        background: '#fff',
                        color: '#57606a',
                        border: '1px solid #d0d7de',
                        borderRadius: 8,
                        boxShadow: '0 4px 16px rgba(0,0,0,.18)',
                        padding: '10px 12px',
                        lineHeight: 1.45,
                    }}
                >
                    Couldn't read the version from this page — showing <b>{version}</b>, the version Kotiq's
                    engine resolved and scanned.
                </div>
            )}

            {open && (
                <div
                    style={{
                        marginTop: 6,
                        width: 320,
                        background: '#fff',
                        color: '#24292f',
                        border: '1px solid #d0d7de',
                        borderRadius: 8,
                        boxShadow: '0 4px 16px rgba(0,0,0,.18)',
                        overflow: 'hidden',
                    }}
                >
                    <div
                        onClick={explain}
                        style={{ padding: '10px 12px', cursor: 'pointer', borderBottom: '1px solid #eaeef2' }}
                    >
                        🤖 Explain with AI
                    </div>
                    <div style={{ padding: '10px 12px', color: '#57606a', lineHeight: 1.45, whiteSpace: 'pre-wrap' }}>
                        {explanation || 'Pick an action above, or click the badge to close.'}
                    </div>
                </div>
            )}
        </div>
    );
}
