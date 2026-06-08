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
import { buildScanMap } from './mapper';
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
    /**
     * Heads-up notes on code that does NOT auto-run (DEAD per the Mapper). High-confidence dangerous
     * patterns only. INFORMATIONAL: never drives `worst` — it's a security review courtesy, not a
     * "do not install" signal. A developer who later edits/runs these files deserves the warning.
     */
    fyi: RepoSelfFinding[];
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
// Real exfil = process.env spread INTO an outbound request (the env object handed to an HTTP call).
// NOT a bare process.env spread — that is the normal way to forward env to a child process
// (spawn with env set to a process.env spread), which thousands of legit dev scripts do.
const ENV_EXFIL_RE =
    /(?:fetch|axios\s*\.\s*(?:post|get|put|patch)|\.\s*(?:post|get|put))\s*\([^)]*\.\.\.\s*process\.env/;

function checkSource(path: string, text: string, out: RepoSelfFinding[]): void {
    // Only auto-run-reachable (LIVE) files reach here. We flag the high-confidence exfil pattern:
    // process.env passed straight into an outbound request. (Wallet/curl signatures stay for hook
    // commands — in arbitrary source they're too noisy: security tools, tests, docs all contain them.)
    if (ENV_EXFIL_RE.test(text)) {
        add(out, {
            kind: 'source',
            file: path,
            label: 'exfiltrates environment variables (process.env) to a remote host',
            severity: Severity.HIGH,
        });
    }
}

// --- dead-code FYI audit ------------------------------------------------------------------------
// Dead code does not auto-run on open/install, so it CANNOT drive the verdict. But if a developer
// later opens or runs one of these files, high-confidence dangerous behaviour is worth a heads-up.
// Conservative on purpose (only the two patterns we trust with near-zero false positives) and we
// skip vendored/built output so the notes stay signal, not noise.
// Skip vendored/built output AND test files/fixtures for the courtesy pass. Skipping tests is SAFE
// here: FYI never drives the verdict, and a test file actually reached by a trigger is LIVE (scanned
// for the verdict) — so this only suppresses noise from inert malware-pattern samples in test suites.
const DEAD_AUDIT_SKIP =
    /(?:^|\/)(?:node_modules|\.yarn|\.pnp|vendor|dist|build|out|coverage|\.next|\.git|__tests__|__mocks__|fixtures|test|tests)\/|\.(?:spec|test)\.[cm]?[jt]sx?$/;
const MAX_DEAD_AUDIT = 200; // cap files read for the courtesy pass (dead set can be huge)

// eval / new Function whose body comes from request/response data → builds & runs remote-controlled
// code. The property-access form (response.data, req.body) is what separates it from legit templating
// (new Function('ctx', src)), which we must never flag.
const REMOTE_EXEC_RE = /\b(?:eval|new\s+Function)\s*\([\s\S]{0,120}?\b(?:res|resp|response|req|request)\b\s*\.\s*\w+/;

function auditDeadFile(path: string, text: string): RepoSelfFinding[] {
    const out: RepoSelfFinding[] = [];
    if (ENV_EXFIL_RE.test(text)) {
        out.push({
            kind: 'source',
            file: path,
            label: 'not auto-run, but contains code that sends environment variables to a remote host',
            severity: Severity.HIGH,
        });
    }
    if (REMOTE_EXEC_RE.test(text)) {
        out.push({
            kind: 'source',
            file: path,
            label: 'not auto-run, but builds and executes code from request/response data (eval / new Function)',
            severity: Severity.HIGH,
        });
    }
    return out;
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
    const have = new Set(files.paths);

    // Config / trigger checks (specific files, always read).
    if (have.has('package.json')) {
        const text = await files.read('package.json');
        if (text) checkPackageJson(text, out);
    }
    if (have.has('.vscode/tasks.json')) {
        const text = await files.read('.vscode/tasks.json');
        if (text) checkVscodeTasks(text, out);
    }
    if (have.has('.vscode/settings.json')) {
        const text = await files.read('.vscode/settings.json');
        if (text) checkVscodeSettings(text, out);
    }
    for (const p of files.paths.filter((p) => p.startsWith('.idea/'))) {
        const text = await files.read(p);
        if (text) checkIdea(p, text, out);
    }
    for (const p of files.paths.filter((p) => /(?:^|\/)\.env(?:\.[\w.-]+)?$/.test(p))) {
        const text = await files.read(p);
        if (text) checkEnv(p, text, out);
    }

    // Reachability: scan ONLY the source that auto-runs (LIVE). Dead code is inert for open/install,
    // so it never drives the verdict — this is what kills false positives on security tools/tests AND
    // closes the "hide in a test folder" evasion (a test file run by a trigger IS live → scanned).
    const map = await buildScanMap(files);
    for (const p of map.live) {
        const text = await files.read(p);
        if (text) checkSource(p, text, out);
    }
    // Fail-loud: auto-run code we couldn't follow (dynamic require / unresolved import) = treat as risky.
    for (const u of map.unresolved) {
        add(out, {
            kind: 'source',
            file: u.split(' → ')[0],
            label: 'auto-run code loads code dynamically — Kotiq could not fully analyze it',
            severity: Severity.MEDIUM,
            detail: u,
        });
    }

    // Courtesy pass over DEAD code: high-confidence dangerous patterns only, capped, vendored skipped.
    // These NEVER enter `out`, so they cannot move the verdict — they're informational heads-up notes.
    const fyi: RepoSelfFinding[] = [];
    let audited = 0;
    for (const p of map.dead) {
        if (audited >= MAX_DEAD_AUDIT) break;
        if (DEAD_AUDIT_SKIP.test(p)) continue;
        const text = await files.read(p);
        if (text == null) continue;
        audited++;
        for (const f of auditDeadFile(p, text)) add(fyi, f);
    }

    const worst = verdictForSeverity(maxSeverityRank(out.map((f) => f.severity)));
    return { findings: out, worst, filesScanned: map.live.length, what: explain(out), fyi };
}
