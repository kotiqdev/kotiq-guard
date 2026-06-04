// Background service worker. The privileged context that CAN run chrome.identity (the content
// script can't). The badge/popup send it messages; it performs sign-in and answers.

import { signIn } from './popup/auth'; // shared auth helper (folder name is organizational only)
import { clearSession, loadSession } from './session';

type Msg = { type: 'signIn' } | { type: 'signOut' } | { type: 'getSession' };

chrome.runtime.onMessage.addListener((msg: Msg, _sender, sendResponse) => {
    (async () => {
        console.info('[kotiq bg] message:', msg.type);
        try {
            if (msg.type === 'signIn') {
                const session = await signIn(true);
                console.info('[kotiq bg] ✓ sign-in complete:', session.email);
                sendResponse({ ok: true, session });
            } else if (msg.type === 'signOut') {
                await clearSession();
                console.info('[kotiq bg] signed out');
                sendResponse({ ok: true });
            } else if (msg.type === 'getSession') {
                sendResponse({ ok: true, session: await loadSession() });
            } else {
                sendResponse({ ok: false, error: 'unknown message' });
            }
        } catch (e) {
            console.warn('[kotiq bg] ✕ sign-in failed:', (e as Error).message);
            sendResponse({ ok: false, error: (e as Error).message });
        }
    })();
    return true; // keep the channel open for the async sendResponse
});
