// JSON-file entitlements store for local dev. Mutable (edit via the CLI), persists on disk.
// NOT for Cloud Run — instances are ephemeral, so a local file wouldn't survive. Use FirestoreStore
// in prod (wired at deploy time).

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import type { Entitlement, EntitlementsStore } from './types';

interface Data {
    emails: Record<string, Entitlement>;
    domains: Record<string, Entitlement>;
}

export class FileStore implements EntitlementsStore {
    constructor(private readonly path: string) {}

    private read(): Data {
        if (!existsSync(this.path)) return { emails: {}, domains: {} };
        const d = JSON.parse(readFileSync(this.path, 'utf8')) as Partial<Data>;
        return { emails: d.emails ?? {}, domains: d.domains ?? {} };
    }

    private write(d: Data): void {
        mkdirSync(dirname(this.path), { recursive: true });
        writeFileSync(this.path, `${JSON.stringify(d, null, 2)}\n`);
    }

    async lookupEmail(email: string): Promise<Entitlement | null> {
        return this.read().emails[email.toLowerCase()] ?? null;
    }

    async lookupDomain(domain: string): Promise<Entitlement | null> {
        return this.read().domains[domain.toLowerCase()] ?? null;
    }

    async setEmail(email: string, e: Entitlement): Promise<void> {
        const d = this.read();
        d.emails[email.toLowerCase()] = e;
        this.write(d);
    }

    async removeEmail(email: string): Promise<void> {
        const d = this.read();
        delete d.emails[email.toLowerCase()];
        this.write(d);
    }

    async listEmails(): Promise<Record<string, Entitlement>> {
        return this.read().emails;
    }
}
