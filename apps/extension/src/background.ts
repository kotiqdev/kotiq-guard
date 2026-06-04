// Background service worker — the privileged context. Content scripts can't run chrome.identity AND
// can't reach localhost (Chrome blocks public-page → loopback). This worker owns BOTH: sign-in and
// every backend call (it attaches the token). The badge/popup just send it messages.

import { API_BASE } from './config';
import { type LiteResult, liteScan } from './lite/engine';
import { explainWithNano, nanoStatus } from './lite/nano';
import { signIn } from './popup/auth';
import { clearSession, loadSession } from './session';

type Msg =
    | { type: 'signIn' }
    | { type: 'signOut' }
    | { type: 'getSession' }
    | { type: 'scan'; pkg: string; from?: string }
    | { type: 'explain'; pkg: string; from?: string }
    | { type: 'cancel' }
    | { type: 'nanoStatus' }
    | { type: 'liteScan'; pkg: string }
    | { type: 'liteExplain'; result: LiteResult };

// Build a tight prompt for Gemini Nano from the Lite scan result (Nano is small → keep it short).
function litePrompts(r: LiteResult): { system: string; user: string } {
    const system =
        'You are a security assistant. In 2-3 short, plain sentences, explain whether this npm package ' +
        'looks safe to install, based ONLY on the data given. Do not invent details. No markdown.';
    const findings = r.findings.map((f) => f.label).join('; ') || 'none';
    const user = `Verdict: ${r.verdict}. Install hooks: ${JSON.stringify(r.hooks)}. ${r.note} Signature findings: ${findings}.`;
    return { system, user };
}

let explainAbort: AbortController | null = null;

// Log on-device AI availability at startup (handy while building the Lite tier).
void nanoStatus().then((s) => console.info('[kotiq bg] Gemini Nano:', s));

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
                case 'nanoStatus':
                    sendResponse({ status: await nanoStatus() });
                    break;
                case 'liteScan':
                    sendResponse({ ok: true, result: await liteScan(msg.pkg) });
                    break;
                case 'liteExplain': {
                    const { system, user } = litePrompts(msg.result);
                    sendResponse({ ok: true, text: await explainWithNano(system, user) });
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
