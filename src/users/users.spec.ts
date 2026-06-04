import type { VerifiedIdentity } from '../auth/access';
import { decidePlan } from './index';
import type { User } from './types';

const allowedEmails = new Set(['admin@example.com']);
const allowedDomains = new Set(['corp.example']);

function id(over: Partial<VerifiedIdentity> = {}): VerifiedIdentity {
    return { email: 'user@example.com', emailVerified: true, ...over };
}
const dates = { createdAt: 't', updatedAt: 't' };
const pro: User = { plan: 'pro', ...dates };
const blocked: User = { plan: 'blocked', ...dates };

describe('decidePlan', () => {
    it('unknown verified user → free', () => {
        expect(decidePlan(id(), null, null, allowedEmails, allowedDomains)).toBe('free');
    });

    it('store grants pro → pro', () => {
        expect(decidePlan(id(), pro, null, allowedEmails, allowedDomains)).toBe('pro');
    });

    it('env allow-list → pro (admin override, no store record)', () => {
        expect(decidePlan(id({ email: 'admin@example.com' }), null, null, allowedEmails, allowedDomains)).toBe('pro');
    });

    it('blocked record wins over everything', () => {
        expect(decidePlan(id({ email: 'admin@example.com' }), blocked, null, allowedEmails, allowedDomains)).toBe('blocked');
    });

    it('unverified email is never pro', () => {
        expect(decidePlan(id({ emailVerified: false }), pro, null, allowedEmails, allowedDomains)).toBe('free');
    });

    it('verified workspace domain in env → pro', () => {
        expect(decidePlan(id({ hd: 'corp.example' }), null, null, allowedEmails, allowedDomains)).toBe('pro');
    });

    it('store grants the whole domain pro → pro', () => {
        expect(decidePlan(id({ hd: 'team.example' }), null, pro, allowedEmails, allowedDomains)).toBe('pro');
    });

    it('blocked domain denies an otherwise-free user', () => {
        expect(decidePlan(id({ hd: 'bad.example' }), null, blocked, allowedEmails, allowedDomains)).toBe('blocked');
    });
});
