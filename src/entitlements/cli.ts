// Admin CLI to mutate entitlements (dev: the JSON file).
//   npm run entitlements -- grant  user@x.com [note]
//   npm run entitlements -- block  user@x.com [note]
//   npm run entitlements -- revoke user@x.com
//   npm run entitlements -- list

import { store } from './index';
import type { Plan } from './types';

async function main(): Promise<void> {
    const [cmd, email, ...rest] = process.argv.slice(2);
    const note = rest.join(' ') || undefined;
    const stamp = () => new Date().toISOString();

    const set = async (plan: Plan) => {
        if (!email) throw new Error(`usage: ${cmd} <email> [note]`);
        await store.setEmail(email, { plan, note, updatedAt: stamp() });
        process.stdout.write(`${plan}: ${email}${note ? ` (${note})` : ''}\n`);
    };

    switch (cmd) {
        case 'grant':
            await set('pro');
            break;
        case 'block':
            await set('blocked');
            break;
        case 'revoke':
            if (!email) throw new Error('usage: revoke <email>');
            await store.removeEmail(email);
            process.stdout.write(`revoked: ${email}\n`);
            break;
        case 'list': {
            const all = await store.listEmails();
            const rows = Object.entries(all);
            if (!rows.length) process.stdout.write('(empty)\n');
            for (const [e, v] of rows) process.stdout.write(`${v.plan.padEnd(7)} ${e}${v.note ? ` — ${v.note}` : ''}\n`);
            break;
        }
        default:
            process.stderr.write('usage: grant|block|revoke|list <email> [note]\n');
            process.exit(1);
    }
}

main().catch((e: unknown) => {
    process.stderr.write(`error: ${(e as Error).message}\n`);
    process.exit(1);
});
