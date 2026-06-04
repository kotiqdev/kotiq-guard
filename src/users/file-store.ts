// JSON-file user store for local dev. Mutable (via the CLI), persists on disk.
// NOT for Cloud Run — instances are ephemeral. Use FirestoreStore in prod (wired at deploy).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import type { User, UserStore } from './types';

type Data = Record<string, User>;

export class FileStore implements UserStore {
    constructor(private readonly path: string) {}

    private read(): Data {
        if (!existsSync(this.path)) return {};
        return JSON.parse(readFileSync(this.path, 'utf8')) as Data;
    }

    private write(d: Data): void {
        mkdirSync(dirname(this.path), { recursive: true });
        writeFileSync(this.path, `${JSON.stringify(d, null, 2)}\n`);
    }

    async get(key: string): Promise<User | null> {
        return this.read()[key.toLowerCase()] ?? null;
    }

    async set(key: string, user: User): Promise<void> {
        const d = this.read();
        d[key.toLowerCase()] = user;
        this.write(d);
    }

    async remove(key: string): Promise<void> {
        const d = this.read();
        delete d[key.toLowerCase()];
        this.write(d);
    }

    async list(): Promise<Data> {
        return this.read();
    }
}
