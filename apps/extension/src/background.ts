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
    | { type: 'repoExplain'; owner: string; repo: string }
    | { type: 'openPopup' };

let explainAbort: AbortController | null = null;
let explainRid: string | null = null; // id of the in-flight LLM request, for explicit server-side cancel

// One place to attach the signed-in user's token and call the backend. Returns the parsed JSON on
// success (null otherwise) + the HTTP status, so callers can branch on 401/403.
async function authedFetch(path: string, signal?: AbortSignal): Promise<{ ok: boolean; status: number; json: unknown | null }> {
    const session = await loadSession();
    const headers = session ? { Authorization: `Bearer ${session.idToken}` } : undefined;
    const res = await fetch(`${API_BASE}${path}`, { headers, signal });
    return { ok: res.ok, status: res.status, json: res.ok ? await res.json() : null };
}

async function callScan(pkg: string, from: string, explain: boolean, signal?: AbortSignal, rid?: string) {
    const path =
        `/scan?pkg=${encodeURIComponent(pkg)}${explain ? '' : '&explain=false'}` +
        `&from=${encodeURIComponent(from)}${rid ? `&rid=${rid}` : ''}`;
    const { ok, status, json } = await authedFetch(path, signal);
    return { ok, status, data: json };
}

// Tell the server to abort the in-flight LLM request explicitly (a fetch-abort alone doesn't always
// tear down the keep-alive socket, so the server may not notice the client went away).
function postCancel(): void {
    if (explainRid) void fetch(`${API_BASE}/cancel?rid=${explainRid}`, { method: 'POST' }).catch(() => {});
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
                    explainRid = crypto.randomUUID();
                    try {
                        sendResponse(await callScan(msg.pkg, msg.from ?? '', true, explainAbort.signal, explainRid));
                    } catch (e) {
                        sendResponse(
                            (e as Error).name === 'AbortError'
                                ? { aborted: true }
                                : { ok: false, error: (e as Error).message },
                        );
                    } finally {
                        explainAbort = null;
                        explainRid = null;
                    }
                    break;
                case 'cancel':
                    postCancel(); // explicit server-side abort
                    explainAbort?.abort(); // also drop our own pending fetch
                    sendResponse({ ok: true });
                    break;
                case 'liteScan':
                    sendResponse({ ok: true, result: await liteScan(msg.pkg) });
                    break;
                case 'repoScan': {
                    // The scan runs on the BACKEND (authoritative logic); we just relay + attach the token.
                    const r = await authedFetch(`/repo?owner=${encodeURIComponent(msg.owner)}&repo=${encodeURIComponent(msg.repo)}`);
                    sendResponse({ ok: r.ok, status: r.status, result: r.json });
                    break;
                }
                case 'repoExplain': {
                    // Pro: AI narrative over the repo findings (analyst ⇄ critic on the backend).
                    explainAbort = new AbortController();
                    explainRid = crypto.randomUUID();
                    try {
                        const r = await authedFetch(
                            `/repo/explain?owner=${encodeURIComponent(msg.owner)}&repo=${encodeURIComponent(msg.repo)}&rid=${explainRid}`,
                            explainAbort.signal,
                        );
                        sendResponse({ ok: r.ok, status: r.status, result: r.json });
                    } catch (e) {
                        sendResponse((e as Error).name === 'AbortError' ? { aborted: true } : { ok: false, error: (e as Error).message });
                    } finally {
                        explainAbort = null;
                        explainRid = null;
                    }
                    break;
                }
                case 'openPopup':
                    // Open the extension popup (where the user reads the notice + signs in). Content
                    // scripts can't do this; only this privileged context can. Not supported on every
                    // Chrome version → the badge also shows a "click the toolbar icon" fallback hint.
                    try {
                        await chrome.action.openPopup();
                        sendResponse({ ok: true });
                    } catch (e) {
                        sendResponse({ ok: false, error: (e as Error).message });
                    }
                    break;
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
