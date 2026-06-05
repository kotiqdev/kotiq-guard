// Repo SELF-scan: the malware in a Contagious-Interview / BeaverTail lure is not in the
// dependencies — it is in the repo's OWN files. This module reads those files (passively, text
// only) and flags the lure's signature behaviours so a developer is warned BEFORE opening or
// installing the project:
//
//   • package.json lifecycle hooks that auto-run project code on `npm install` (prepare/postinstall)
//   • .vscode/tasks.json with runOn:"folderOpen"  → silent code execution just from OPENING the folder
//   • commands hidden by whitespace padding (URL pushed off the right edge of the editor)
//   • .vscode/settings.json that disables workspace trust / auto-runs tasks / hijacks the terminal
//   • source that executes server-provided JS (eval / new Function) or exfiltrates process.env
//   • a base64-encoded remote URL stashed in .env (C2 obfuscation)
//
// Everything is regex/JSON heuristics over fetched text. No code is ever executed.

import { Severity } from '../models/enums';
import { scan } from '../static-analysis/web3-signatures';
import { maxSeverityRank, SEV_RANK, verdictForSeverity } from './verdict';
import type { Verdict } from '../models/enums';

export type SelfFindingKind =
    | 'install_hook'
    | 'vscode_task'
    | 'vscode_settings'
    | 'idea_runconfig'
    | 'source'
    | 'env_secret';

export interface RepoSelfFinding {
    kind: SelfFindingKind;
    file: string;
    label: string;
    severity: Severity;
    detail?: string;
}

export interface RepoSelfResult {
    findings: RepoSelfFinding[];
    worst: Verdict;
    filesScanned: number;
    /** Plain-language, developer-facing bullets: "what this repo does". Empty when nothing fired. */
    what: string[];
}

/** What the scanner can read. `read` returns file text, or null if absent/too big. */
export interface RepoFiles {
    paths: string[];
    read: (path: string) => Promise<string | null>;
}

// npm lifecycle hooks that run automatically. `prepare` runs on `npm install` of a git/local dep
// and on plain `npm install` in the project root — the Contagious-Interview lure uses exactly it.
const LIFECYCLE = [
    'preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly', 'prepack',
] as const;
const RUNS_LOCAL_CODE = /\b(?:node|ts-node|tsx|bun|deno|babel-node|nodemon)\b|\.(?:js|cjs|mjs|ts|sh)\b/;
const MAX_SOURCE_FILES = 40;
const SOURCE_EXT = /\.(?:js|cjs|mjs|ts|cts|mts)$/;
// Vendored toolchains / generated / bundled code legitimately use eval/new Function — never scan them.
const SKIP_DIR = /(?:^|\/)(?:node_modules|dist|build|out|lib|coverage|\.next|\.nuxt|\.yarn|\.pnp|vendor|third_party|__generated__|generated)\//;
const SKIP_FILE = /\.(?:min|bundle|chunk)\.(?:js|cjs|mjs)$|(?:^|\/)\.pnp\.[\w.]+$|(?:^|\/)yarn-[\d.]+\.cjs$/;
// Signatures that are normal in ordinary application source — flagged only inside install hooks /
// auto-run paths, NOT as a risk just for appearing in a source file:
//   making HTTP calls, using eval / new Function (templating, parsers), `node -e`.
const SOURCE_SKIP = new Set(['outbound_http', 'eval_call', 'function_constructor', 'node_dash_e']);

// Tolerant JSON parse: VS Code config files allow // and /* */ comments and trailing commas.
function looseJsonParse(text: string): unknown {
    const noComments = text
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/(^|[^:"'])\/\/[^\n]*/g, '$1'); // // line comments not inside a string/url
    const noTrailingCommas = noComments.replace(/,\s*([}\]])/g, '$1');
    try {
        return JSON.parse(noTrailingCommas);
    } catch {
        try {
            return JSON.parse(text);
        } catch {
            return null;
        }
    }
}

function add(out: RepoSelfFinding[], f: RepoSelfFinding): void {
    if (!out.some((x) => x.kind === f.kind && x.file === f.file && x.label === f.label)) out.push(f);
}

// --- package.json own lifecycle hooks -----------------------------------------------------------
function checkPackageJson(text: string, out: RepoSelfFinding[]): void {
    const pkg = looseJsonParse(text) as { scripts?: Record<string, string> } | null;
    const scripts = pkg?.scripts ?? {};
    for (const name of LIFECYCLE) {
        const cmd = scripts[name];
        if (typeof cmd !== 'string' || !cmd.trim()) continue;
        const hits = scan(cmd);
        if (hits.length) {
            add(out, {
                kind: 'install_hook',
                file: 'package.json',
                label: `lifecycle hook "${name}" runs a dangerous command`,
                severity: hits.reduce((s, h) => (SEV_RANK[h.severity] > SEV_RANK[s] ? h.severity : s), hits[0].severity),
                detail: `${name}: ${cmd}`,
            });
        } else if (RUNS_LOCAL_CODE.test(cmd)) {
            // Benign-looking command, but it auto-executes project code on install — follow the file.
            add(out, {
                kind: 'install_hook',
                file: 'package.json',
                label: `lifecycle hook "${name}" auto-runs project code on install`,
                severity: Severity.MEDIUM,
                detail: `${name}: ${cmd}`,
            });
        }
    }
}

// --- .vscode/tasks.json -------------------------------------------------------------------------
interface VsTask {
    label?: string;
    command?: string;
    osx?: { command?: string };
    linux?: { command?: string };
    windows?: { command?: string };
    runOptions?: { runOn?: string };
    presentation?: { reveal?: string; echo?: boolean };
}

function checkVscodeTasks(text: string, out: RepoSelfFinding[]): void {
    // Whitespace-padding trick: a command line indented far past the viewport hides its URL.
    for (const line of text.split('\n')) {
        const indent = line.length - line.trimStart().length;
        if (indent > 60 && /(?:curl|wget|https?:\/\/|command)/i.test(line)) {
            add(out, {
                kind: 'vscode_task',
                file: '.vscode/tasks.json',
                label: 'command hidden by whitespace padding (pushed off-screen)',
                severity: Severity.HIGH,
                detail: line.trim().slice(0, 160),
            });
            break;
        }
    }

    const parsed = looseJsonParse(text) as { tasks?: VsTask[] } | null;
    for (const t of parsed?.tasks ?? []) {
        const label = t.label ?? '(unnamed task)';
        const cmds = [t.command, t.osx?.command, t.linux?.command, t.windows?.command].filter(
            (c): c is string => typeof c === 'string' && c.length > 0,
        );
        const folderOpen = t.runOptions?.runOn === 'folderOpen';
        const silent = t.presentation?.reveal === 'silent' || t.presentation?.echo === false;

        if (folderOpen) {
            add(out, {
                kind: 'vscode_task',
                file: '.vscode/tasks.json',
                label: `task "${label}" auto-executes when the folder is opened (no install needed)`,
                severity: Severity.CRITICAL,
                detail: (silent ? 'silent · ' : '') + (cmds[0] ?? '').slice(0, 160),
            });
        }
        for (const cmd of cmds) {
            for (const hit of scan(cmd)) {
                add(out, {
                    kind: 'vscode_task',
                    file: '.vscode/tasks.json',
                    label: `task "${label}": ${hit.label}`,
                    severity: hit.severity,
                    detail: cmd.slice(0, 160),
                });
            }
        }
    }
}

// --- .vscode/settings.json ----------------------------------------------------------------------
function checkVscodeSettings(text: string, out: RepoSelfFinding[]): void {
    // Raw-text checks first — the real lure ships deliberately BROKEN JSON, so a parse may fail.
    if (/"security\.workspace\.trust\.enabled"\s*:\s*false/.test(text)) {
        add(out, {
            kind: 'vscode_settings',
            file: '.vscode/settings.json',
            label: 'disables VS Code Workspace Trust (removes the run-on-open guard)',
            severity: Severity.HIGH,
        });
    }
    if (/"task\.allowAutomaticTasks"\s*:\s*"on"/.test(text)) {
        add(out, {
            kind: 'vscode_settings',
            file: '.vscode/settings.json',
            label: 'auto-runs tasks on folder open without prompting',
            severity: Severity.HIGH,
        });
    }
    if (/"files\.autoSave"/.test(text) && /"editor\.wordWrap"\s*:\s*"off"/.test(text)) {
        add(out, {
            kind: 'vscode_settings',
            file: '.vscode/settings.json',
            label: 'concealment combo: auto-save + word-wrap off (keeps padded URLs off-screen)',
            severity: Severity.LOW,
        });
    }
    // Terminal profile hijack: a profile whose args carry an inline shell command (best-effort parse).
    const s = looseJsonParse(text) as Record<string, unknown> | null;
    if (!s) return;
    for (const key of Object.keys(s).filter((k) => k.startsWith('terminal.integrated.profiles.'))) {
        const profiles = s[key] as Record<string, { args?: unknown }> | undefined;
        for (const p of Object.values(profiles ?? {})) {
            const args = Array.isArray(p?.args) ? p.args.join(' ') : '';
            if (/\b-c\b|\/c\b/.test(args) && scan(args).length) {
                add(out, {
                    kind: 'vscode_settings',
                    file: '.vscode/settings.json',
                    label: 'overrides the integrated terminal to run a custom command',
                    severity: Severity.MEDIUM,
                    detail: args.slice(0, 160),
                });
            }
        }
    }
}

// --- .idea/ run configurations ------------------------------------------------------------------
function checkIdea(path: string, text: string, out: RepoSelfFinding[]): void {
    const hits = scan(text);
    const autoRun = /EXECUTE_IN_TERMINAL"\s+value="true"|folderOpen|"runOn"/.test(text);
    if (hits.length || autoRun) {
        add(out, {
            kind: 'idea_runconfig',
            file: path,
            label: 'JetBrains run configuration that executes a shell command',
            severity: hits.length && SEV_RANK[hits[0].severity] >= SEV_RANK[Severity.MEDIUM] ? hits[0].severity : Severity.MEDIUM,
            detail: (hits[0]?.snippet ?? '').slice(0, 160),
        });
    }
}

// --- source files -------------------------------------------------------------------------------
const ENV_EXFIL_RE =
    /(?:fetch|axios\s*\.\s*(?:post|get|put|patch)|\.\s*(?:post|get|put))\s*\([^)]*\.\.\.\s*process\.env|\{\s*\.\.\.\s*process\.env\s*\}/;

function checkSource(path: string, text: string, out: RepoSelfFinding[]): void {
    for (const hit of scan(text)) {
        if (SOURCE_SKIP.has(hit.name)) continue; // normal in ordinary app source — not a risk by itself
        add(out, {
            kind: 'source',
            file: path,
            label: hit.label,
            severity: hit.severity,
            detail: hit.snippet.slice(0, 160),
        });
    }
    if (ENV_EXFIL_RE.test(text)) {
        add(out, {
            kind: 'source',
            file: path,
            label: 'exfiltrates environment variables (process.env) to a remote host',
            severity: Severity.HIGH,
        });
    }
}

// --- .env: base64-encoded remote URL ------------------------------------------------------------
function checkEnv(path: string, text: string, out: RepoSelfFinding[]): void {
    for (const line of text.split('\n')) {
        const eq = line.indexOf('=');
        if (eq < 1) continue;
        const key = line.slice(0, eq).trim();
        const val = line.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
        if (val.length < 16 || !/^[A-Za-z0-9+/]+={0,2}$/.test(val)) continue;
        let decoded = '';
        try {
            decoded = Buffer.from(val, 'base64').toString('utf8');
        } catch {
            continue;
        }
        if (/^https?:\/\/(?!localhost|127\.0\.0\.1)\S+$/.test(decoded)) {
            add(out, {
                kind: 'env_secret',
                file: path,
                label: `base64-encoded remote URL in ${key} (C2 obfuscation)`,
                severity: Severity.HIGH,
                detail: `${key} → ${decoded}`,
            });
        }
    }
}

// Pick which source files to read: real code only, capped, hook target prioritised.
function pickSourceFiles(paths: string[], pkgMain?: string): string[] {
    const candidates = paths.filter(
        (p) => SOURCE_EXT.test(p) && !SKIP_DIR.test('/' + p) && !SKIP_FILE.test(p),
    );
    const score = (p: string): number => {
        if (pkgMain && p === pkgMain) return 0;
        if (/^server\//.test(p)) return 1;
        if (/^src\//.test(p)) return 2;
        if (/^(?:scripts|bin)\//.test(p)) return 1;
        if (!p.includes('/')) return 1; // root-level files
        return 4;
    };
    return candidates.sort((a, b) => score(a) - score(b)).slice(0, MAX_SOURCE_FILES);
}

// Turn findings into developer-facing "what this is" bullets. The alarming narrative is produced
// ONLY when a high-confidence lure signal is present (auto-exec on open/install, remote shell pipe,
// base64 C2, env exfiltration, hidden command). A lone eval / fetch / new Function in ordinary
// source does NOT trigger it — that is normal application code, not a "do not install" situation.
function explain(findings: RepoSelfFinding[]): string[] {
    const sev = (f: RepoSelfFinding) => SEV_RANK[f.severity];
    const folderOpen = findings.some((f) => f.label.includes('folder is opened'));
    const remotePipe = findings.some((f) => /remote shell pipe|\bcurl\b|\bwget\b/i.test(f.label));
    const c2env = findings.some((f) => f.kind === 'env_secret');
    const exfil = findings.some((f) => /environment variables/i.test(f.label));
    const padding = findings.some((f) => /whitespace padding/i.test(f.label));
    const trust = findings.some((f) => /Workspace Trust|allowAutomaticTasks/i.test(f.label));
    const dangerousHook = findings.some((f) => f.kind === 'install_hook' && sev(f) >= SEV_RANK[Severity.HIGH]);

    const lure = folderOpen || remotePipe || c2env || exfil || padding || dangerousHook;
    if (!lure) return []; // only context-level findings → no alarming narrative

    const out: string[] = [];
    if (folderOpen) out.push('Runs code automatically the moment you OPEN the folder in VS Code (.vscode/tasks.json runOn:folderOpen) — no `npm install` required.');
    if (dangerousHook) out.push('Runs a dangerous command automatically on `npm install` via a package.json lifecycle hook.');
    if (remotePipe) out.push('Downloads a remote script and pipes it straight into your shell (curl … | sh).');
    if (exfil) out.push('Sends your environment variables (tokens, keys) to a remote host.');
    if (c2env) out.push('Hides a command-and-control URL as a base64 string in .env.');
    if (padding) out.push('Hides the malicious URL off-screen using whitespace padding / word-wrap tricks.');
    if (trust) out.push('Weakens VS Code safety settings so the auto-run task fires silently.');
    out.push('This matches the “Contagious Interview” / BeaverTail fake-recruiter malware pattern. Do NOT open or install this repository — inspect it in a sandbox only.');
    return out;
}

export async function selfScan(files: RepoFiles): Promise<RepoSelfResult> {
    const out: RepoSelfFinding[] = [];
    let scanned = 0;
    const have = new Set(files.paths);

    const readCount = async (path: string): Promise<string | null> => {
        const t = await files.read(path);
        if (t != null) scanned++;
        return t;
    };

    // package.json (own hooks) + find `main` for source prioritisation.
    let pkgMain: string | undefined;
    if (have.has('package.json')) {
        const text = await readCount('package.json');
        if (text) {
            checkPackageJson(text, out);
            const pkg = looseJsonParse(text) as { main?: string } | null;
            if (typeof pkg?.main === 'string') pkgMain = pkg.main.replace(/^\.\//, '');
        }
    }

    if (have.has('.vscode/tasks.json')) {
        const text = await readCount('.vscode/tasks.json');
        if (text) checkVscodeTasks(text, out);
    }
    if (have.has('.vscode/settings.json')) {
        const text = await readCount('.vscode/settings.json');
        if (text) checkVscodeSettings(text, out);
    }
    for (const p of files.paths.filter((p) => p.startsWith('.idea/'))) {
        const text = await readCount(p);
        if (text) checkIdea(p, text, out);
    }
    for (const p of files.paths.filter((p) => /(?:^|\/)\.env(?:\.[\w.-]+)?$/.test(p))) {
        const text = await readCount(p);
        if (text) checkEnv(p, text, out);
    }
    for (const p of pickSourceFiles(files.paths, pkgMain)) {
        const text = await readCount(p);
        if (text) checkSource(p, text, out);
    }

    const worst = verdictForSeverity(maxSeverityRank(out.map((f) => f.severity)));
    return { findings: out, worst, filesScanned: scanned, what: explain(out) };
}
