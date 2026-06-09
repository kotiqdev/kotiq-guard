import { useEffect, useState } from 'react';

import { REQUIRE_AUTH } from '../config';
import type { RepoResult } from '../lite/repo';
import { loadSession, SESSION_KEY, type Session } from '../session';
import { ConsentGate, useAcked } from '../ui/consent';
import { Dock } from '../ui/Dock';
import { SignInBadge } from '../ui/SignInBadge';
import { Spinner } from '../ui/primitives';
import { badgePill, dropdownPanel, pillName, VERDICT_COLOR } from '../ui/theme';
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
    const [target, setTarget] = useState(repoFromUrl());
    const [session, setSession] = useState<Session | null | undefined>(undefined);
    const [authBusy, setAuthBusy] = useState(false);
    const [result, setResult] = useState<RepoResult | null>(null);
    const [open, setOpen] = useState(false);
    const [scanning, setScanning] = useState(false);
    const [aiBusy, setAiBusy] = useState(false); // AI explain running → collapsed Dock shows a spinner
    const acked = useAcked(); // first-run consent gate (must accept before any scan)

    useEffect(() => {
        void loadSession().then((s) => setSession(s));
    }, []);

    // Live-sync sign-in/out from the popup or background (session written in another context).
    useEffect(() => {
        const onChange = (changes: Record<string, chrome.storage.StorageChange>, area: string): void => {
            if (area !== 'local' || !(SESSION_KEY in changes)) return;
            void loadSession().then((s) => {
                setResult(null); // re-scan under the new session
                setSession(s ?? null);
            });
        };
        chrome.storage.onChanged.addListener(onChange);
        return () => chrome.storage.onChanged.removeListener(onChange);
    }, []);

    // GitHub is a SPA (Turbo) — moving between repos changes the URL without a full reload. Poll the
    // URL and re-target only when the REPO actually changes (not on tab switches within one repo).
    useEffect(() => {
        let lastKey = target ? `${target.owner}/${target.repo}` : '';
        let lastHref = location.href;
        const id = setInterval(() => {
            if (location.href === lastHref) return;
            lastHref = location.href;
            const t = repoFromUrl();
            const key = t ? `${t.owner}/${t.repo}` : '';
            if (key === lastKey) return; // same repo (e.g. Issues→Pull requests) → keep the result
            lastKey = key;
            setResult(null);
            setOpen(false);
            setAiBusy(false);
            setTarget(t);
        }, 600);
        return () => clearInterval(id);
    }, []);

    useEffect(() => {
        if (acked !== true || !target || session === undefined) return; // consent + session first
        if (REQUIRE_AUTH && !session) return; // need sign-in first
        let cancelled = false; // a newer scan / navigation supersedes this one
        setScanning(true);
        void chrome.runtime
            .sendMessage({ type: 'repoScan', owner: target.owner, repo: target.repo })
            .then((r: { status?: number; result?: RepoResult }) => {
                if (cancelled) return;
                if (r?.status === 401) return setSession(null);
                setResult(r?.result ?? null);
            })
            .catch(() => {
                if (!cancelled) setResult(null);
            })
            .finally(() => {
                if (!cancelled) setScanning(false);
            });
        return () => {
            cancelled = true;
        };
    }, [acked, target, session]);

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
    if (acked === undefined) return null; // waiting on the consent flag
    if (!acked) return <ConsentGate />; // must acknowledge before scanning

    if (REQUIRE_AUTH && session === null) {
        return (
            <SignInBadge
                onSignIn={doSignIn}
                busy={authBusy}
                label="Sign in with Google"
                title="Sign in with Google (the only sign-in method) to scan this repo's dependencies"
            />
        );
    }

    // Immediate feedback while the (multi-second) repo scan runs.
    if (scanning && !result) {
        return (
            <Dock status={{ busy: true }}>
                <div style={{ ...badgePill('#6e7781', 'default'), display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Spinner size={13} color="#ffffff" />
                    <span style={pillName}>{target.repo}</span> · scanning…
                </div>
            </Dock>
        );
    }

    // Repos with no (root) Node manifest → nothing to assess yet (a proper verdict for nested
    // manifests comes with the recursive scan). Brief scanning→hidden here is acceptable.
    if (!result || !result.found) return null;

    const color = VERDICT_COLOR[result.worst] ?? '#6e7781';
    const selfCount = result.self?.findings.length ?? 0;
    const subtitle = selfCount
        ? `· ${selfCount} repo risk${selfCount > 1 ? 's' : ''}`
        : `· ${result.withHooks} hook deps`;

    return (
        <Dock status={{ busy: aiBusy, color }}>
            <div onClick={() => setOpen((o) => !o)} style={badgePill(color)}>
                <span style={pillName}>{target.repo}</span>: {result.worst}
                <span style={{ marginLeft: 6, fontWeight: 400, opacity: 0.85 }}>{subtitle}</span>
            </div>

            {open && (
                <div style={{ ...dropdownPanel, width: 360, maxHeight: '70vh', overflowY: 'auto' }}>
                    <AiAnalysis owner={target.owner} repo={target.repo} onBusy={setAiBusy} />
                    <RepoFindings result={result} />
                </div>
            )}
        </Dock>
    );
}
