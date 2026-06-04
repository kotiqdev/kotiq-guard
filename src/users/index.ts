// Identity → plan, plus the user registry (upsert on sign-in) and admin mutations.
// Used by /me (UI tier + profile) and the /scan gate.

import { isAllowed, type VerifiedIdentity } from '../auth/access';
import { env } from '../env';
import { FileStore } from './file-store';
import type { Plan, User, UserStore } from './types';

export type { Plan, User } from './types';

function makeStore(): UserStore {
    // if (env.usersStore === 'firestore') return new FirestoreStore(env.gcpProject); // TODO @deploy
    return new FileStore(env.usersFile);
}
export const store = makeStore();

const now = (): string => new Date().toISOString();

// Pure decision (no I/O) → testable. Precedence: unverified→free · blocked wins · env allow-list→pro ·
// store pro→pro · verified domain (env/store)→pro · else free.
export function decidePlan(
    id: VerifiedIdentity,
    user: User | null,
    domain: User | null,
    allowedEmails: Set<string>,
    allowedDomains: Set<string>,
): Plan {
    if (!id.emailVerified) return 'free';
    if (user?.plan === 'blocked') return 'blocked';
    if (isAllowed(id, allowedEmails, allowedDomains)) return 'pro';
    if (user?.plan === 'pro') return 'pro';
    if (id.hd) {
        if (domain?.plan === 'blocked') return 'blocked';
        if (domain?.plan === 'pro') return 'pro';
    }
    return 'free';
}

// Read-only — the per-request /scan gate uses this (no writes).
export async function getPlan(id: VerifiedIdentity): Promise<Plan> {
    const user = await store.get(id.email);
    const domain = id.hd ? await store.get(`@${id.hd}`) : null;
    return decidePlan(id, user, domain, env.allowedEmails, env.allowedDomains);
}

// Upsert on sign-in (full registry): create on first seen, else refresh lastSeen + profile.
export async function recordSeen(id: VerifiedIdentity): Promise<User> {
    const t = now();
    const prev = await store.get(id.email);
    const user: User = prev
        ? { ...prev, updatedAt: t, lastSeenAt: t, name: id.name ?? prev.name, picture: id.picture ?? prev.picture }
        : { plan: 'free', createdAt: t, updatedAt: t, lastSeenAt: t, name: id.name, picture: id.picture };
    await store.set(id.email, user);
    return user;
}

// ── Admin mutations (CLI). key = email or "@domain". Preserve createdAt; stamp the change. ─────────
export async function grant(key: string, opts: { by?: string; note?: string } = {}): Promise<void> {
    const t = now();
    const prev = await store.get(key);
    await store.set(key, {
        ...(prev ?? { plan: 'free', createdAt: t }),
        plan: 'pro',
        grantedAt: t,
        updatedAt: t,
        source: 'manual',
        updatedBy: opts.by,
        note: opts.note ?? prev?.note,
    });
}

export async function block(key: string, reason?: string): Promise<void> {
    const t = now();
    const prev = await store.get(key);
    await store.set(key, {
        ...(prev ?? { plan: 'free', createdAt: t }),
        plan: 'blocked',
        blockedAt: t,
        blockReason: reason,
        updatedAt: t,
    });
}

export async function revoke(key: string): Promise<void> {
    const prev = await store.get(key);
    if (!prev) return;
    await store.set(key, { ...prev, plan: 'free', updatedAt: now() });
}

export async function list(): Promise<Record<string, User>> {
    return store.list();
}
