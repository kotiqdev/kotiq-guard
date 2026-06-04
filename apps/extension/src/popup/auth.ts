// Auth for the popup. Flow: launchWebAuthFlow → Google → signed ID token (JWT) → cache it →
// send it as a Bearer to the backend. Session read/write lives in ../session (shared with content).

import { API_BASE, OAUTH_CLIENT_ID } from '../config';
import { decodeJwt, saveSession, clearSession, type Session } from '../session';

export type Role = 'pro' | 'lite';
export type { Session };
export { loadSession } from '../session';

// Open Google sign-in and cache the resulting ID token. interactive=false attempts a silent renew.
export async function signIn(interactive = true): Promise<Session> {
    if (!OAUTH_CLIENT_ID) throw new Error('OAuth client id is not configured yet (src/config.ts)');

    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.searchParams.set('client_id', OAUTH_CLIENT_ID);
    url.searchParams.set('response_type', 'id_token'); // OpenID Connect ID token (a JWT)
    url.searchParams.set('redirect_uri', chrome.identity.getRedirectURL()); // https://<id>.chromiumapp.org/
    url.searchParams.set('scope', 'openid email profile'); // profile → name + avatar
    url.searchParams.set('nonce', crypto.randomUUID()); // required for the id_token flow
    url.searchParams.set('prompt', 'select_account');

    console.info('[kotiq auth] → opening Google sign-in:', `${url.origin}${url.pathname}`, `(interactive=${interactive})`);
    const redirect = await chrome.identity.launchWebAuthFlow({ url: url.toString(), interactive });
    if (!redirect) throw new Error('sign-in was cancelled');
    console.info('[kotiq auth] ← redirect received from Google');

    const idToken = new URLSearchParams(new URL(redirect).hash.slice(1)).get('id_token');
    if (!idToken) throw new Error('no id_token in the response');

    const { email, exp, name, picture } = decodeJwt(idToken);
    const session: Session = { idToken, email: email ?? '', exp: exp ?? 0, name, picture };
    await saveSession(session);
    console.info('[kotiq auth] ✓ signed in as', session.email, '· token expires', new Date(session.exp * 1000).toLocaleString());
    return session;
}

export async function signOut(): Promise<void> {
    await clearSession();
}

// Ask the backend which tier this verified user is.
//   200 {role} → that role · 403 → lite (valid Google user, not allow-listed) · else → throw.
export async function fetchRole(idToken: string): Promise<Role> {
    const res = await fetch(`${API_BASE}/me`, { headers: { Authorization: `Bearer ${idToken}` } });
    if (res.status === 200) {
        const data = (await res.json()) as { role?: Role };
        return data.role === 'pro' ? 'pro' : 'lite';
    }
    if (res.status === 403) return 'lite';
    throw new Error(`access check failed (${res.status})`);
}
