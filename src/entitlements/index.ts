// The single access decision: identity → plan. Used by /me (UI tier) and the /scan gate.
// blocked wins; the env allow-list is an admin / bootstrap override on top of the store.

import { isAllowed, type VerifiedIdentity } from '../auth/access';
import { env } from '../env';
import { FileStore } from './file-store';
import type { Entitlement, EntitlementsStore, Plan } from './types';

export type { Plan } from './types';

// Pick the store by env. FileStore (dev) now; FirestoreStore (prod) wired at Cloud Run deploy.
function makeStore(): EntitlementsStore {
    // if (env.entitlementsStore === 'firestore') return new FirestoreStore(env.gcpProject); // TODO @deploy
    return new FileStore(env.entitlementsFile);
}

export const store = makeStore();

// Pure decision — no I/O — so it's trivially testable. Precedence:
//   1. unverified email      → free (never pro)
//   2. explicitly blocked    → blocked (deny)
//   3. env allow-list        → pro (admin override / bootstrap)
//   4. store says pro        → pro
//   5. verified domain (env or store) → pro
//   6. otherwise             → free
export function decidePlan(
    id: VerifiedIdentity,
    byEmail: Entitlement | null,
    byDomain: Entitlement | null,
    allowedEmails: Set<string>,
    allowedDomains: Set<string>,
): Plan {
    if (!id.emailVerified) return 'free';
    if (byEmail?.plan === 'blocked') return 'blocked';
    if (isAllowed(id, allowedEmails, allowedDomains)) return 'pro';
    if (byEmail?.plan === 'pro') return 'pro';
    if (id.hd) {
        if (byDomain?.plan === 'blocked') return 'blocked';
        if (byDomain?.plan === 'pro') return 'pro';
    }
    return 'free';
}

export async function getPlan(id: VerifiedIdentity): Promise<Plan> {
    const byEmail = await store.lookupEmail(id.email);
    const byDomain = id.hd ? await store.lookupDomain(id.hd) : null;
    return decidePlan(id, byEmail, byDomain, env.allowedEmails, env.allowedDomains);
}
