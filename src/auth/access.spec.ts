import { isAllowed, VerifiedIdentity } from './access';

const emails = new Set(['alice@example.com', 'team@example.com']);
const domains = new Set(['example.org']);

function id(over: Partial<VerifiedIdentity> = {}): VerifiedIdentity {
    return { email: 'alice@example.com', emailVerified: true, ...over };
}

describe('isAllowed', () => {
    it('allows an explicitly listed verified email', () => {
        expect(isAllowed(id(), emails, domains)).toBe(true);
    });

    it('is case-insensitive on the email', () => {
        expect(isAllowed(id({ email: 'Alice@Example.com' }), emails, domains)).toBe(true);
    });

    it('allows any email whose verified hd domain is listed', () => {
        expect(isAllowed(id({ email: 'someone@example.org', hd: 'example.org' }), emails, domains)).toBe(true);
    });

    it('rejects an unverified email even if listed', () => {
        expect(isAllowed(id({ emailVerified: false }), emails, domains)).toBe(false);
    });

    it('rejects an unknown email with no hd', () => {
        expect(isAllowed(id({ email: 'stranger@evil.com' }), emails, domains)).toBe(false);
    });

    it('does NOT infer the domain from the email string — only the verified hd counts', () => {
        // email ends in @example.org but hd is absent (not a Workspace account) → must be rejected.
        expect(isAllowed(id({ email: 'spoofer@example.org', hd: undefined }), new Set(), domains)).toBe(false);
    });

    it('rejects when hd is a different domain than allow-listed', () => {
        expect(isAllowed(id({ email: 'x@other.com', hd: 'other.com' }), new Set(), domains)).toBe(false);
    });
});
