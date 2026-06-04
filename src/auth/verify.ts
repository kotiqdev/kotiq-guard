// Verifies a Google ID token: checks the signature against Google's public keys, the expiry,
// the issuer, and that `aud` matches our OAuth client id. Returns the trusted claims we care about.
// google-auth-library caches Google's signing keys, so this is fast after the first call.

import { OAuth2Client } from 'google-auth-library';

import type { VerifiedIdentity } from './access';

const client = new OAuth2Client();

// Throws if the token is missing/expired/forged or `aud` != audience. On success the payload is
// trustworthy: Google signed it, so `email_verified` and `hd` cannot be tampered with by the client.
export async function verifyIdToken(idToken: string, audience: string): Promise<VerifiedIdentity> {
    const ticket = await client.verifyIdToken({ idToken, audience });
    const p = ticket.getPayload();
    if (!p?.email) throw new Error('id token has no email claim');
    return { email: p.email, emailVerified: p.email_verified === true, hd: p.hd, name: p.name, picture: p.picture };
}

// DEV ONLY: read the claims WITHOUT verifying the signature. Used locally when no OAuth client id is
// configured (so /me can still resolve a role). NEVER rely on this in prod — always verifyIdToken
// when oauthClientId is set, because an unverified token's claims can be forged.
export function decodeIdTokenUnverified(idToken: string): VerifiedIdentity {
    const payload = idToken.split('.')[1] ?? '';
    const json = Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const p = JSON.parse(json) as {
        email?: string;
        email_verified?: boolean;
        hd?: string;
        name?: string;
        picture?: string;
    };
    if (!p.email) throw new Error('id token has no email claim');
    return { email: p.email, emailVerified: p.email_verified === true, hd: p.hd, name: p.name, picture: p.picture };
}
