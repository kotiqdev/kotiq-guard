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
    return { email: p.email, emailVerified: p.email_verified === true, hd: p.hd };
}
