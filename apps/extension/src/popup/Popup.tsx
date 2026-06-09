import { useEffect, useState, type CSSProperties } from 'react';

import { ackConsent, useAcked } from '../ui/consent';
import { fetchRole, loadSession, signIn, signOut, type Role, type Session } from './auth';

// The popup is a tiny state machine. One of these is shown at a time.
type View =
    | { kind: 'loading' }
    | { kind: 'signedOut' }
    | { kind: 'signedIn'; session: Session; role: Role | 'checking'; note?: string }
    | { kind: 'error'; message: string };

const C = {
    bg: '#0d0d0d',
    fg: '#e6e6e6',
    dim: '#8a8a8a',
    green: '#00ff41', // PRO
    grey: '#9aa0a6', // LITE
    border: '#2a2a2a',
};

export function Popup() {
    const [view, setView] = useState<View>({ kind: 'loading' });
    const [about, setAbout] = useState(false);
    const acked = useAcked(); // shared first-run consent flag (boolean | undefined)

    // On open: restore a cached session, then resolve the tier from the backend.
    useEffect(() => {
        void (async () => {
            const session = await loadSession();
            if (!session) return setView({ kind: 'signedOut' });
            setView({ kind: 'signedIn', session, role: 'checking' });
            try {
                const role = await fetchRole(session.idToken);
                setView({ kind: 'signedIn', session, role });
            } catch {
                setView({ kind: 'signedIn', session, role: 'checking', note: "Couldn't verify access — backend offline?" });
            }
        })();
    }, []);

    async function handleSignIn() {
        setView({ kind: 'loading' });
        try {
            const session = await signIn();
            setView({ kind: 'signedIn', session, role: 'checking' });
            try {
                const role = await fetchRole(session.idToken);
                setView({ kind: 'signedIn', session, role });
            } catch {
                setView({ kind: 'signedIn', session, role: 'checking', note: "Couldn't verify access yet." });
            }
        } catch (e) {
            setView({ kind: 'error', message: (e as Error).message });
        }
    }

    async function handleSignOut() {
        await signOut();
        setView({ kind: 'signedOut' });
    }

    return (
        <div style={S.shell}>
            <div style={S.header}>
                <img
                    src={chrome.runtime.getURL('icons/icon-48.png')}
                    alt=""
                    width={22}
                    height={22}
                    style={{ display: 'block' }}
                />
                <strong>Kotiq Guard</strong>
                <span
                    style={{
                        marginLeft: 'auto',
                        fontSize: 10,
                        fontWeight: 700,
                        letterSpacing: 0.5,
                        color: C.grey,
                        border: `1px solid ${C.border}`,
                        borderRadius: 999,
                        padding: '1px 7px',
                    }}
                >
                    BETA
                </span>
            </div>
            {acked === undefined ? (
                <div style={S.body}>
                    <p style={{ color: C.dim }}>…</p>
                </div>
            ) : !acked ? (
                <Consent onAccept={ackConsent} />
            ) : (
                <>
                    <div style={S.body}>{renderBody(view, handleSignIn, handleSignOut)}</div>
                    {about && <About />}
                    <div style={S.footer}>
                        <span>Beta — early build. Know before you install.</span>
                        <button style={S.aboutToggle} onClick={() => setAbout((a) => !a)}>
                            About {about ? '▴' : '▾'}
                        </button>
                    </div>
                </>
            )}
        </div>
    );
}

// First-run notice: sets expectations honestly (a signal, not a guarantee) + the sandbox advice.
function Consent({ onAccept }: { onAccept: () => void }) {
    return (
        <div style={S.body}>
            <p style={{ margin: '0 0 10px', color: C.fg, fontSize: 13, lineHeight: 1.5 }}>
                Kotiq checks a GitHub repo or npm package for risky install hooks and known issues
                <strong> before</strong> you open or install it — an extra safety signal, right on the page.
            </p>
            <p style={{ margin: '0 0 10px', color: C.dim, fontSize: 12, lineHeight: 1.45 }}>
                Currently focused on the <strong>Node.js ecosystem</strong> — npm packages and Node repos
                on GitHub. More may follow.
            </p>
            <div style={S.notice}>
                <p style={{ margin: '0 0 6px' }}>
                    ⚠️ <strong>It's a signal, not a guarantee.</strong> Attackers keep evolving — a “safe”
                    result can still miss something brand-new.
                </p>
                <p style={{ margin: 0 }}>
                    For anything untrusted or suspicious, open or install it in an{' '}
                    <strong>isolated environment (a VM, container or sandbox)</strong> — not on your main
                    machine. You stay responsible for what you run.
                </p>
            </div>
            <p style={{ margin: '10px 0 12px', color: C.dim, fontSize: 11, lineHeight: 1.45 }}>
                Next you'll sign in with Google (the only sign-in method) — email/profile; Kotiq sends the
                package/repo you check to its backend. See the{' '}
                <a href="https://kotiq.dev/privacy" target="_blank" rel="noreferrer" style={{ color: C.grey }}>
                    privacy policy
                </a>
                .
            </p>
            <button style={S.primary} onClick={onAccept}>
                Got it — I understand
            </button>
        </div>
    );
}

function About() {
    return (
        <div style={S.about}>
            <p style={{ margin: '0 0 8px' }}>
                <strong style={{ color: C.fg }}>Kotiq Guard</strong> tells you whether a GitHub repo or npm
                package is safe to <em>open</em> or <em>install</em> — before you run it.
            </p>
            <p style={{ margin: '0 0 8px' }}>
                It inspects the project <strong>passively</strong> — its scripts, editor tasks, source and
                dependencies — and never executes any code. Pro adds AI analysis of the code that actually
                runs on install or open.
            </p>
            <p style={{ margin: 0, color: C.dim }}>
                Beta — early build, results may be imperfect. Feedback:{' '}
                <a href="https://kotiq.dev" target="_blank" rel="noreferrer" style={{ color: C.grey }}>
                    kotiq.dev
                </a>
            </p>
        </div>
    );
}

function renderBody(view: View, onSignIn: () => void, onSignOut: () => void) {
    switch (view.kind) {
        case 'loading':
            return <p style={{ color: C.dim }}>…</p>;

        case 'signedOut':
            return (
                <>
                    <p style={{ color: C.dim, margin: '0 0 12px' }}>Sign in to scan npm packages.</p>
                    <button style={S.primary} onClick={onSignIn}>
                        Sign in with Google
                    </button>
                </>
            );

        case 'error':
            return (
                <>
                    <p style={{ color: '#ff5c5c', margin: '0 0 12px' }}>{view.message}</p>
                    <button style={S.primary} onClick={onSignIn}>
                        Try again
                    </button>
                </>
            );

        case 'signedIn': {
            const isPro = view.role === 'pro';
            const chip = view.role === 'checking' ? null : <Chip pro={isPro} />;
            return (
                <>
                    <div style={S.row}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                            {view.session.picture && (
                                <img
                                    src={view.session.picture}
                                    alt=""
                                    width={28}
                                    height={28}
                                    style={{ borderRadius: '50%', flexShrink: 0 }}
                                />
                            )}
                            <div style={{ minWidth: 0 }}>
                                <div style={{ color: C.fg, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {view.session.name || view.session.email || 'signed in'}
                                </div>
                                {view.session.name && <div style={{ color: C.dim, fontSize: 11 }}>{view.session.email}</div>}
                            </div>
                        </div>
                        {chip}
                    </div>
                    <p style={{ color: C.dim, margin: '8px 0 14px', fontSize: 12 }}>
                        {view.role === 'checking' && (view.note ?? 'Checking your access…')}
                        {view.role === 'pro' && 'Full cloud scan — Gemini on Vertex AI.'}
                        {view.role === 'lite' && 'Free deterministic scan. Pro adds AI source analysis + CVE.'}
                    </p>
                    {view.role === 'lite' && (
                        <button style={S.ghost} onClick={() => window.open('https://kotiq.dev', '_blank')}>
                            Request Pro access
                        </button>
                    )}
                    <button style={S.link} onClick={onSignOut}>
                        Sign out
                    </button>
                </>
            );
        }
    }
}

function Chip({ pro }: { pro: boolean }) {
    return (
        <span
            style={{
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: 0.5,
                padding: '2px 8px',
                borderRadius: 999,
                color: pro ? '#001b06' : '#111',
                background: pro ? C.green : C.grey,
            }}
        >
            {pro ? 'PRO' : 'LITE'}
        </span>
    );
}

const S: Record<string, CSSProperties> = {
    shell: {
        width: 300,
        background: C.bg,
        color: C.fg,
        fontFamily: 'ui-sans-serif, system-ui, sans-serif',
        border: `1px solid ${C.border}`,
    },
    header: { display: 'flex', alignItems: 'center', gap: 8, padding: '12px 14px', borderBottom: `1px solid ${C.border}` },
    body: { padding: 16, minHeight: 96 },
    footer: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 8,
        padding: '8px 14px',
        borderTop: `1px solid ${C.border}`,
        color: C.dim,
        fontSize: 11,
    },
    aboutToggle: {
        background: 'none',
        border: 'none',
        color: C.grey,
        cursor: 'pointer',
        fontSize: 11,
        fontWeight: 600,
        padding: 0,
        flexShrink: 0,
    },
    about: {
        padding: '12px 14px',
        borderTop: `1px solid ${C.border}`,
        color: C.fg,
        fontSize: 12,
        lineHeight: 1.45,
    },
    notice: {
        background: '#1a1407',
        border: '1px solid #3a2e0a',
        borderRadius: 8,
        padding: '10px 12px',
        color: '#e8d9a8',
        fontSize: 12,
        lineHeight: 1.45,
    },
    row: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 },
    primary: {
        width: '100%',
        padding: '10px 12px',
        background: C.green,
        color: '#001b06',
        border: 'none',
        borderRadius: 8,
        fontWeight: 700,
        cursor: 'pointer',
    },
    ghost: {
        width: '100%',
        padding: '8px 12px',
        background: 'transparent',
        color: C.fg,
        border: `1px solid ${C.border}`,
        borderRadius: 8,
        cursor: 'pointer',
        marginBottom: 8,
    },
    link: { width: '100%', padding: 6, background: 'none', color: C.dim, border: 'none', cursor: 'pointer', fontSize: 12 },
};
