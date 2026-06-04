// Session storage, shared by the popup (which writes it on sign-in) and the content script
// (which reads it to decide whether to call the cloud). Single source so they can't drift.

export interface Session {
    idToken: string;
    email: string;
    exp: number; // unix seconds
    name?: string; // display name (from the `profile` scope)
    picture?: string; // avatar URL (from the `profile` scope)
}

const KEY = 'kotiqSession';

// Read a JWT payload. NOT verification — the server checks the signature; we only read claims for UI.
export function decodeJwt(token: string): { email?: string; exp?: number; name?: string; picture?: string } {
    const payload = token.split('.')[1] ?? '';
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as {
        email?: string;
        exp?: number;
        name?: string;
        picture?: string;
    };
}

export async function loadSession(): Promise<Session | null> {
    const stored = await chrome.storage.local.get(KEY);
    const s = stored[KEY] as Session | undefined;
    if (!s) return null;
    if (s.exp * 1000 < Date.now()) return null; // expired
    return s;
}

export async function saveSession(s: Session): Promise<void> {
    await chrome.storage.local.set({ [KEY]: s });
}

export async function clearSession(): Promise<void> {
    await chrome.storage.local.remove(KEY);
}
