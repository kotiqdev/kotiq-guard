// Shown when auth is required but the user isn't signed in. Clicking starts Google sign-in via the
// background worker (content scripts can't run chrome.identity). Shared by the npm + GitHub badges.

import { Dock } from './Dock';
import { badgePill } from './theme';

export function SignInBadge({
    onSignIn,
    busy,
    label,
    title,
    error,
}: {
    onSignIn: () => void;
    busy: boolean;
    label: string;
    title: string;
    error?: string | null;
}) {
    return (
        <Dock status={{ busy }}>
            <div
                onClick={busy ? undefined : onSignIn}
                title={title}
                style={{ ...badgePill('#6e7781', busy ? 'default' : 'pointer'), opacity: busy ? 0.7 : 1 }}
            >
                🔒 Kotiq · {busy ? 'Signing in…' : label}
            </div>
            {error && (
                <div style={{ marginTop: 6, width: 280, background: '#fff', color: '#cf222e', border: '1px solid #d0d7de', borderRadius: 8, boxShadow: '0 4px 16px rgba(0,0,0,.18)', padding: '8px 10px', lineHeight: 1.4 }}>
                    {error}
                </div>
            )}
        </Dock>
    );
}
