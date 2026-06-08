// Mapper — deterministic reachability (NO LLM, executes nothing).
//
// Answers: when you OPEN or INSTALL this repo, which files run automatically (LIVE) vs which only run
// if you later choose to (DEAD)? It starts from the auto-run entry points (lifecycle hooks, VS Code
// folderOpen tasks, git/husky hooks), follows what each runs (the command's target file → its static
// `require('./x')` / `import './y'` → transitively), and everything it reaches is LIVE.
//
// This is the scope for the LLM analyst (it reads only LIVE) and the honest basis for the verdict:
// a scary file that nothing auto-runs is inert. CONSERVATIVE: anything we can't statically resolve in
// a LIVE path (dynamic require, computed path) is recorded as `unresolved` and treated as risky — never
// silently marked dead.

import type { RepoFiles } from './self-scan';

export interface Trigger {
    kind: 'install_hook' | 'vscode_task' | 'git_hook';
    source: string; // where found, e.g. 'package.json:postinstall' or '.vscode/tasks.json:env'
    command: string;
    entries: string[]; // local files this trigger runs (resolved within the repo)
}

export interface ScanMap {
    triggers: Trigger[];
    live: string[]; // files reachable from a trigger
    dead: string[]; // source files not reachable from any trigger
    unresolved: string[]; // live-path references we couldn't follow statically (treat as risky)
}

const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly', 'prepack'];
const SOURCE_EXT = /\.(?:js|cjs|mjs|jsx|ts|cts|mts|tsx)$/;
const MAX_LIVE = 300;

// Tolerant JSON (VS Code config allows // comments + trailing commas).
function looseJson(text: string): any {
    try {
        return JSON.parse(
            text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:"'])\/\/[^\n]*/g, '$1').replace(/,\s*([}\]])/g, '$1'),
        );
    } catch {
        try {
            return JSON.parse(text);
        } catch {
            return null;
        }
    }
}

// Join a base dir with a relative spec, resolving . and ..
function joinPath(dir: string, spec: string): string {
    const out: string[] = [];
    for (const p of (dir ? dir.split('/') : []).concat(spec.split('/'))) {
        if (p === '' || p === '.') continue;
        else if (p === '..') out.pop();
        else out.push(p);
    }
    return out.join('/');
}

// Resolve a relative import spec to an actual repo path (try extensions + /index).
function resolveSpec(fromFile: string, spec: string, fileSet: Set<string>): string | null {
    const dir = fromFile.includes('/') ? fromFile.slice(0, fromFile.lastIndexOf('/')) : '';
    const base = joinPath(dir, spec);
    const exts = ['', '.js', '.cjs', '.mjs', '.jsx', '.ts', '.cts', '.mts', '.tsx'];
    for (const e of exts) if (fileSet.has(base + e)) return base + e;
    for (const e of exts.slice(1)) if (fileSet.has(`${base}/index${e}`)) return `${base}/index${e}`;
    return null;
}

// Static, relative imports/requires (string literals only).
function relativeSpecs(text: string): string[] {
    const re =
        /(?:require|import)\s*\(\s*['"](\.[^'"]+)['"]\s*\)|(?:import|export)\b[^'"]*?\bfrom\s*['"](\.[^'"]+)['"]|import\s*['"](\.[^'"]+)['"]/g;
    const out: string[] = [];
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) out.push(m[1] ?? m[2] ?? m[3]);
    return out;
}

// Dynamic require/import we cannot follow (argument isn't a string literal).
function hasDynamicImport(text: string): boolean {
    return /\b(?:require|import)\s*\(\s*[^'")\s]/.test(text);
}

// The local script(s) a shell command runs: `node X`, `ts-node X`, `tsx X`, `bash X.sh`, plus one level
// of `npm|pnpm|yarn run <name>` resolved through the scripts map. Handles && ; || | -separated segments.
function entriesFromCommand(cmd: string, scripts: Record<string, string>, depth = 0): string[] {
    if (depth > 3) return [];
    const out: string[] = [];
    for (const seg of cmd.split(/&&|\|\||;|\|/)) {
        const s = seg.trim();
        const run =
            s.match(/\b(?:node|ts-node|tsx|bun|deno|babel-node|nodemon)\b\s+(?:-{1,2}\S+\s+)*['"]?(\.?[\w./-]+\.(?:[cm]?[jt]sx?|sh))['"]?/) ??
            s.match(/\b(?:bash|sh)\b\s+['"]?(\.?[\w./-]+\.sh)['"]?/);
        if (run) {
            out.push(run[1].replace(/^\.\//, ''));
            continue;
        }
        const npmRun = s.match(/\b(?:npm|pnpm|yarn)\s+(?:run\s+)?([\w:-]+)\b/);
        if (npmRun && scripts[npmRun[1]]) out.push(...entriesFromCommand(scripts[npmRun[1]], scripts, depth + 1));
    }
    return out;
}

export async function buildScanMap(files: RepoFiles): Promise<ScanMap> {
    const fileSet = new Set(files.paths);
    const triggers: Trigger[] = [];
    const seeds = new Set<string>(); // entry files to start reachability from

    const addTrigger = (kind: Trigger['kind'], source: string, command: string, entries: string[]): void => {
        triggers.push({ kind, source, command, entries });
        for (const e of entries) if (fileSet.has(e)) seeds.add(e);
    };

    // 1) package.json lifecycle hooks
    let scripts: Record<string, string> = {};
    if (fileSet.has('package.json')) {
        const pkg = looseJson((await files.read('package.json')) ?? '');
        scripts = (pkg?.scripts ?? {}) as Record<string, string>;
        for (const h of LIFECYCLE) {
            const cmd = scripts[h];
            if (typeof cmd === 'string' && cmd.trim()) {
                addTrigger('install_hook', `package.json:${h}`, cmd, entriesFromCommand(cmd, scripts));
            }
        }
    }

    // 2) .vscode/tasks.json with runOn:folderOpen (per-OS commands too)
    if (fileSet.has('.vscode/tasks.json')) {
        const parsed = looseJson((await files.read('.vscode/tasks.json')) ?? '');
        for (const t of (parsed?.tasks ?? []) as any[]) {
            if (t?.runOptions?.runOn !== 'folderOpen') continue;
            const cmds = [t.command, t.osx?.command, t.linux?.command, t.windows?.command].filter(
                (c: unknown): c is string => typeof c === 'string' && c.length > 0,
            );
            for (const cmd of cmds) addTrigger('vscode_task', `.vscode/tasks.json:${t.label ?? 'task'}`, cmd, entriesFromCommand(cmd, scripts));
        }
    }

    // 3) git hooks (husky) — files under .husky/ (skip husky's own internal _/ dir)
    for (const p of files.paths.filter((p) => /(^|\/)\.husky\//.test(p) && !/\/_\//.test(p))) {
        const text = (await files.read(p)) ?? '';
        addTrigger('git_hook', p, text.trim().slice(0, 160), entriesFromCommand(text, scripts));
    }

    // Reachability BFS from seeds, following static relative imports.
    const live = new Set<string>();
    const unresolved = new Set<string>();
    const queue = [...seeds];
    while (queue.length && live.size < MAX_LIVE) {
        const f = queue.shift() as string;
        if (live.has(f)) continue;
        live.add(f);
        const text = await files.read(f);
        if (text == null) continue;
        if (hasDynamicImport(text)) unresolved.add(f); // can't see where this goes — flag, don't trust
        for (const spec of relativeSpecs(text)) {
            const r = resolveSpec(f, spec, fileSet);
            if (r) queue.push(r);
            else unresolved.add(`${f} → ${spec}`);
        }
    }

    const dead = files.paths.filter((p) => SOURCE_EXT.test(p) && !live.has(p)).sort();
    return { triggers, live: [...live].sort(), dead, unresolved: [...unresolved] };
}
