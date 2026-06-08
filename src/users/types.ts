// The user registry. One record per signed-in person — their plan, lifecycle dates, and profile.
// Same surface grants Pro AND blocks abusers.  free → Lite · pro → cloud · blocked → denied.

export type Plan = 'free' | 'pro' | 'blocked';

export interface User {
    plan: Plan;
    createdAt: string; // first seen (ISO)
    updatedAt: string; // last change to this record
    lastSeenAt?: string; // last sign-in
    grantedAt?: string; // when Pro started
    expiresAt?: string | null; // Pro expiry (null = no expiry) — for trials/renewals
    blockedAt?: string; // when blocked
    blockReason?: string;
    requestedProAt?: string; // when they clicked "Request Pro" — the conversion funnel
    source?: 'manual' | 'stripe'; // how Pro was granted
    updatedBy?: string; // admin email (audit)
    name?: string; // display name from the Google profile
    picture?: string; // avatar URL from the Google profile
    note?: string;
}

// Keyed by email (lowercased) for people, or "@domain" for a whole Workspace org.
// Swappable: FileStore (dev JSON) ↔ FirestoreStore (prod — Cloud Run is stateless).
export interface UserStore {
    get(key: string): Promise<User | null>;
    set(key: string, user: User): Promise<void>;
    remove(key: string): Promise<void>;
    list(): Promise<Record<string, User>>;
}
