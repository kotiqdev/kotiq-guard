// Pure allow-list decision. No I/O, no token parsing — just the rule, so it's trivially testable.
// The identity here is ALREADY cryptographically verified (see verify.ts); we only decide access.

export interface VerifiedIdentity {
    email: string;
    emailVerified: boolean;
    hd?: string; // Google Workspace domain — a VERIFIED claim, set only for Workspace accounts
    name?: string; // display name (needs the `profile` scope)
    picture?: string; // avatar URL (needs the `profile` scope)
}

// Allow if the verified email is explicitly listed, OR the account's verified Workspace domain
// (`hd`) is allow-listed. We never derive the domain from the email string — only from `hd`,
// because the local part of an email can be spoofed/aliased but `hd` is asserted by Google.
export function isAllowed(
    id: VerifiedIdentity,
    allowedEmails: Set<string>,
    allowedDomains: Set<string>,
): boolean {
    if (!id.emailVerified) return false;
    if (allowedEmails.has(id.email.toLowerCase())) return true;
    if (id.hd && allowedDomains.has(id.hd.toLowerCase())) return true;
    return false;
}
