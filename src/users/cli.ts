// Admin CLI to mutate the user registry (dev: the JSON file).
//   npm run users -- grant  user@x.com [note]
//   npm run users -- block  user@x.com [reason]
//   npm run users -- grant  @example.com            (a whole Workspace domain)
//   npm run users -- revoke user@x.com
//   npm run users -- list

import { block, grant, list, revoke } from './index';

const out = (s: string): void => void process.stdout.write(`${s}\n`);

async function main(): Promise<void> {
    const [cmd, key, ...rest] = process.argv.slice(2);
    const text = rest.join(' ') || undefined;

    switch (cmd) {
        case 'grant':
            if (!key) throw new Error('usage: grant <email|@domain> [note]');
            await grant(key, { note: text });
            out(`pro: ${key}`);
            break;
        case 'block':
            if (!key) throw new Error('usage: block <email|@domain> [reason]');
            await block(key, text);
            out(`blocked: ${key}`);
            break;
        case 'revoke':
            if (!key) throw new Error('usage: revoke <email|@domain>');
            await revoke(key);
            out(`revoked → free: ${key}`);
            break;
        case 'list': {
            const rows = Object.entries(await list());
            if (!rows.length) return out('(empty)');
            for (const [k, u] of rows) {
                out(`${u.plan.padEnd(7)} ${k}${u.name ? `  (${u.name})` : ''}${u.note ? ` — ${u.note}` : ''}`);
            }
            break;
        }
        default:
            process.stderr.write('usage: grant|block|revoke|list <email|@domain> [text]\n');
            process.exit(1);
    }
}

main().catch((e: unknown) => {
    process.stderr.write(`error: ${(e as Error).message}\n`);
    process.exit(1);
});
