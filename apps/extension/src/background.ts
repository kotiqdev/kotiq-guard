// Background service worker — the privileged context. Content scripts can't run chrome.identity AND
// can't reach localhost (Chrome blocks public-page → loopback). This worker owns BOTH: sign-in and
// every backend call (it attaches the token). The badge/popup just send it messages.

import { API_BASE } from './config';
import { liteScan } from './lite/engine';
import { signIn } from './popup/auth';
import { clearSession, loadSession } from './session';

type Msg =
    | { type: 'signIn' }
    | { type: 'signOut' }
    | { type: 'getSession' }
    | { type: 'scan'; pkg: string; from?: string }
    | { type: 'explain'; pkg: string; from?: string }
    | { type: 'cancel' }
    | { type: 'liteScan'; pkg: string }
    | { type: 'repoScan'; owner: string; repo: string }
    | { type: 'repoExplain'; owner: string; repo: string };

let explainAbort: AbortController | null = null;

async function callScan(pkg: string, from: string, explain: boolean, signal?: AbortSignal) {
    const session = await loadSession();
    const headers = session ? { Authorization: `Bearer ${session.idToken}` } : undefined;
    const url =
        `${API_BASE}/scan?pkg=${encodeURIComponent(pkg)}` +
        `${explain ? '' : '&explain=false'}&from=${encodeURIComponent(from)}`;
    const res = await fetch(url, { headers, signal });
    return { ok: res.ok, status: res.status, data: res.ok ? await res.json() : null };
}

chrome.runtime.onMessage.addListener((msg: Msg, _sender, sendResponse) => {
    (async () => {
        try {
            switch (msg.type) {
                case 'signIn': {
                    const session = await signIn(true);
                    console.info('[kotiq bg] ✓ sign-in complete:', session.email);
                    sendResponse({ ok: true, session });
                    break;
                }
                case 'signOut':
                    await clearSession();
                    sendResponse({ ok: true });
                    break;
                case 'getSession':
                    sendResponse({ ok: true, session: await loadSession() });
                    break;
                case 'scan':
                    sendResponse(await callScan(msg.pkg, msg.from ?? '', false));
                    break;
                case 'explain':
                    explainAbort = new AbortController();
                    try {
                        sendResponse(await callScan(msg.pkg, msg.from ?? '', true, explainAbort.signal));
                    } catch (e) {
                        sendResponse(
                            (e as Error).name === 'AbortError'
                                ? { aborted: true }
                                : { ok: false, error: (e as Error).message },
                        );
                    } finally {
                        explainAbort = null;
                    }
                    break;
                case 'cancel':
                    explainAbort?.abort();
                    sendResponse({ ok: true });
                    break;
                case 'liteScan':
                    sendResponse({ ok: true, result: await liteScan(msg.pkg) });
                    break;
                case 'repoScan': {
                    // The scan runs on the BACKEND now (authoritative logic); we just relay + attach the token.
                    const session = await loadSession();
                    const headers = session ? { Authorization: `Bearer ${session.idToken}` } : undefined;
                    const url = `${API_BASE}/repo?owner=${encodeURIComponent(msg.owner)}&repo=${encodeURIComponent(msg.repo)}`;
                    const res = await fetch(url, { headers });
                    sendResponse({ ok: res.ok, status: res.status, result: res.ok ? await res.json() : null });
                    break;
                }
                case 'repoExplain': {
                    // Pro: AI narrative over the repo findings (analyst ⇄ critic on the backend).
                    explainAbort = new AbortController();
                    try {
                        const session = await loadSession();
                        const headers = session ? { Authorization: `Bearer ${session.idToken}` } : undefined;
                        const url = `${API_BASE}/repo/explain?owner=${encodeURIComponent(msg.owner)}&repo=${encodeURIComponent(msg.repo)}`;
                        const res = await fetch(url, { headers, signal: explainAbort.signal });
                        sendResponse({ ok: res.ok, status: res.status, result: res.ok ? await res.json() : null });
                    } catch (e) {
                        sendResponse((e as Error).name === 'AbortError' ? { aborted: true } : { ok: false, error: (e as Error).message });
                    } finally {
                        explainAbort = null;
                    }
                    break;
                }
                default:
                    sendResponse({ ok: false, error: 'unknown message' });
            }
        } catch (e) {
            console.warn('[kotiq bg] ✕', (e as Error).message);
            sendResponse({ ok: false, error: (e as Error).message });
        }
    })();
    return true; // keep the channel open for the async sendResponse
});
