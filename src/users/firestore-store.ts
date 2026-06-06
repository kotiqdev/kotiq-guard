// Firestore-backed user store for the cloud (Cloud Run is stateless, so the file store can't persist).
// One document per key (email lowercased, or "@domain"), in the configured collection. Auth comes
// from ADC — the Cloud Run runtime service account locally falls back to `gcloud` ADC.
//
// `ignoreUndefinedProperties` lets us write a partially-filled User (most fields are optional) without
// Firestore rejecting `undefined` values.

import { Firestore } from '@google-cloud/firestore';

import type { User, UserStore } from './types';

export class FirestoreStore implements UserStore {
    private readonly col;

    constructor(opts: { projectId?: string; collection: string }) {
        const db = new Firestore({
            ...(opts.projectId ? { projectId: opts.projectId } : {}),
            ignoreUndefinedProperties: true,
        });
        this.col = db.collection(opts.collection);
    }

    // Same keying as FileStore: lowercase so "A@x.com" and "a@x.com" are one record.
    private docId(key: string): string {
        return key.toLowerCase();
    }

    async get(key: string): Promise<User | null> {
        const snap = await this.col.doc(this.docId(key)).get();
        return snap.exists ? (snap.data() as User) : null;
    }

    async set(key: string, user: User): Promise<void> {
        await this.col.doc(this.docId(key)).set(user);
    }

    async remove(key: string): Promise<void> {
        await this.col.doc(this.docId(key)).delete();
    }

    async list(): Promise<Record<string, User>> {
        const snap = await this.col.get();
        const out: Record<string, User> = {};
        snap.forEach((d) => {
            out[d.id] = d.data() as User;
        });
        return out;
    }
}
