// Who gets what. The single access surface: grant Pro AND block abusers through one mutable store.
//   free    → Lite (on-device)         pro → full cloud scan         blocked → denied everywhere

export type Plan = 'free' | 'pro' | 'blocked';

export interface Entitlement {
    plan: Plan;
    note?: string;
    updatedAt?: string; // ISO
}

// Source of truth for entitlements. Swappable behind this interface:
//   dev  → FileStore     (local JSON, mutable, fine because the local FS persists)
//   prod → FirestoreStore (Cloud Run is stateless — a local file would NOT survive)
export interface EntitlementsStore {
    lookupEmail(email: string): Promise<Entitlement | null>;
    lookupDomain(domain: string): Promise<Entitlement | null>;
    setEmail(email: string, e: Entitlement): Promise<void>;
    removeEmail(email: string): Promise<void>;
    listEmails(): Promise<Record<string, Entitlement>>;
}
