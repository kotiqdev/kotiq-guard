// FirestoreStore mapped against an in-memory fake of @google-cloud/firestore (no emulator/network).
// Verifies the doc-per-key mapping, lowercase keying (matches FileStore), and exists handling.

jest.mock('@google-cloud/firestore', () => {
    const data = new Map<string, unknown>();
    class Firestore {
        collection(_name: string) {
            return {
                doc: (id: string) => ({
                    get: async () => ({ exists: data.has(id), data: () => data.get(id) }),
                    set: async (v: unknown) => void data.set(id, v),
                    delete: async () => void data.delete(id),
                }),
                get: async () => ({
                    forEach: (cb: (d: { id: string; data: () => unknown }) => void) => {
                        for (const [id, v] of data) cb({ id, data: () => v });
                    },
                }),
            };
        }
    }
    return { Firestore, __data: data };
});

import { FirestoreStore } from './firestore-store';
import type { User } from './types';

const user = (plan: User['plan'] = 'free'): User => ({
    plan,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
});

describe('FirestoreStore', () => {
    const store = new FirestoreStore({ projectId: 'p', collection: 'users' });

    it('returns null for a missing key', async () => {
        expect(await store.get('nobody@x.com')).toBeNull();
    });

    it('sets and gets a user', async () => {
        await store.set('a@x.com', user('pro'));
        expect((await store.get('a@x.com'))?.plan).toBe('pro');
    });

    it('keys case-insensitively (like FileStore)', async () => {
        await store.set('Mixed@Case.COM', user('blocked'));
        expect((await store.get('mixed@case.com'))?.plan).toBe('blocked');
    });

    it('removes a user', async () => {
        await store.set('gone@x.com', user());
        await store.remove('gone@x.com');
        expect(await store.get('gone@x.com')).toBeNull();
    });

    it('lists all users', async () => {
        const all = await store.list();
        expect(Object.keys(all).length).toBeGreaterThan(0);
        expect(all['a@x.com']?.plan).toBe('pro');
    });
});
