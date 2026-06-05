import { useEffect, useState } from 'react';

import { REQUIRE_AUTH } from '../config';
import type { RepoResult } from '../lite/repo';
import { loadSession, type Session } from '../session';
import { SignInBadge } from '../ui/SignInBadge';
import { Spinner } from '../ui/primitives';
import { badgePill, badgeShell, dropdownPanel, VERDICT_COLOR } from '../ui/theme';
import { AiAnalysis } from './AiAnalysis';
import { RepoFindings } from './RepoFindings';

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

export function RepoBadge() {
    const [target] = useState(repoFromUrl());
    const [session, setSession] = useState<Session | null | undefined>(undefined);
    const [authBusy, setAuthBusy] = useState(false);
    const [result, setResult] = useState<RepoResult | null>(null);
    const [scanning, setScanning] = useState(false);
    const [open, setOpen] = useState(false);

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

    if (!target) return null;

    if (REQUIRE_AUTH && session === null) {
        return (
            <SignInBadge
                onSignIn={doSignIn}
                busy={authBusy}
                label="Sign in to scan deps"
                title="Sign in with Google to scan this repo's dependencies"
            />
        );
    }

    // Signed-in users see Kotiq working while GitHub is being analyzed (it can take a few seconds).
    if (scanning && !result) {
        return (
            <div style={badgeShell}>
                <div style={{ ...badgePill('#6e7781', 'default'), display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Spinner size={13} color="#ffffff" />
                    🐱 Kotiq · scanning repo…
                </div>
            </div>
        );
    }

    if (!result || !result.found) return null; // not a Node repo → show nothing

    const color = VERDICT_COLOR[result.worst] ?? '#6e7781';
    const selfCount = result.self?.findings.length ?? 0;
    const subtitle = selfCount
        ? `· ${selfCount} repo risk${selfCount > 1 ? 's' : ''}`
        : `· ${result.withHooks} hook deps`;

    return (
        <div style={badgeShell}>
            <div onClick={() => setOpen((o) => !o)} style={badgePill(color)}>
                🐱 Kotiq: {result.worst}
                <span style={{ marginLeft: 6, fontWeight: 400, opacity: 0.85 }}>{subtitle}</span>
            </div>

            {open && (
                <div style={{ ...dropdownPanel, width: 360, maxHeight: '70vh', overflowY: 'auto' }}>
                    {result.worst !== 'SAFE' && <AiAnalysis owner={target.owner} repo={target.repo} />}
                    <RepoFindings result={result} />
                </div>
            )}
        </div>
    );
}
