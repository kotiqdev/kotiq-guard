// Pro repo brain — the AI layer over the deterministic scan.
//
//   repoAnalyst — READS the code that auto-runs on open/install (LIVE), says what it really does,
//                 de-obfuscates, and flags malicious behaviour the signatures missed. Escalate-only.
//   repoCritic  — verifies the analysis is grounded in the actual code; on fail, sends it back (≤ N).
//
// The deterministic verdict is the floor: the analyst can only RAISE it (via `escalate`), never lower.

import type { RunnableConfig } from '@langchain/core/runnables';
import { traceable } from 'langsmith/traceable';

import { debug } from '../logger';
import { contentToText } from './llm/content';
import { makeModel } from './llm/model';
import { agents, render } from './prompts';
import { Verdict } from '../core/models/enums';
import { buildScanMap } from '../core/repo/mapper';
import { openRepo } from '../core/repo/repo-scan';
import type { DepFinding, RepoResult } from '../core/repo/repo-scan';
import type { RepoFiles, RepoSelfFinding } from '../core/repo/self-scan';

export type Escalate = 'none' | 'needs_review' | 'suspicious' | 'malicious';

export interface RepoExplainResult {
    explanation: string;
    grounded: boolean;
    escalate: Escalate;
}

const LIVE_BUDGET = 24_000; // total chars of live code fed to the model
const PER_FILE_CAP = 4_000;

export function escalateToVerdict(e: Escalate): Verdict {
    return e === 'malicious'
        ? Verdict.MALICIOUS
        : e === 'suspicious'
          ? Verdict.SUSPICIOUS
          : e === 'needs_review'
            ? Verdict.NEEDS_REVIEW
            : Verdict.SAFE;
}

// First {...} JSON object out of a possibly <think>-wrapped reply.
function extractJson(raw: string): Record<string, unknown> | null {
    const cleaned = raw.replace(/<think>[\s\S]*?<\/think>/g, '');
    const match = cleaned.match(/\{[\s\S]*\}/);
    if (!match) return null;
    try {
        return JSON.parse(match[0]) as Record<string, unknown>;
    } catch {
        return null;
    }
}

function selfLine(f: RepoSelfFinding): string {
    return `- ${f.severity} · ${f.file} · ${f.label}${f.detail ? ` (${f.detail})` : ''}`;
}
function depLine(d: DepFinding): string {
    return `- ${d.verdict} · dependency ${d.name}@${d.version} · ${d.findings.map((x) => x.label).join('; ')}`;
}
function findingsBlock(result: RepoResult): string {
    const lines = [...(result.self?.findings ?? []).map(selfLine), ...result.flagged.map(depLine)];
    return lines.length ? lines.join('\n') : '(no risky behaviour detected)';
}

// Read the auto-run (LIVE) source for the analyst, within a char budget (truncate big files).
async function readLiveCode(files: RepoFiles, live: string[]): Promise<string> {
    const out: string[] = [];
    let used = 0;
    for (const p of live) {
        if (used >= LIVE_BUDGET) {
            out.push(`… (${live.length - out.length} more live files omitted)`);
            break;
        }
        const t = await files.read(p);
        if (t == null) continue;
        const slice = t.length > PER_FILE_CAP ? `${t.slice(0, PER_FILE_CAP)}\n… (truncated)` : t;
        out.push(`=== ${p} ===\n${slice}`);
        used += slice.length;
    }
    return out.join('\n\n') || '(no auto-run code reachable)';
}

function normEscalate(v: unknown): Escalate {
    return v === 'malicious' || v === 'suspicious' || v === 'needs_review' ? v : 'none';
}

async function repoExplainImpl(
    owner: string,
    repo: string,
    result: RepoResult,
    config?: RunnableConfig,
): Promise<RepoExplainResult> {
    const findings = findingsBlock(result);
    const maxTries = agents.repoCritic.maxTries ?? 2;

    // Bail between LLM calls if the caller aborted (in-call abort is handled by the model stream).
    const ensureLive = (): void => {
        if (config?.signal?.aborted) {
            const e = new Error('aborted');
            e.name = 'AbortError';
            throw e;
        }
    };

    // Read the code that actually auto-runs — this is what the analyst reasons over.
    let liveCode = '(could not read repository files)';
    try {
        const files = await openRepo(owner, repo);
        const map = await buildScanMap(files);
        liveCode = await readLiveCode(files, map.live);
    } catch (e) {
        debug('repoExplain: could not read live code ·', (e as Error).message);
    }

    let explanation = '';
    let grounded = false;
    let escalate: Escalate = 'none';
    let retryNote = '';

    for (let attempt = 1; attempt <= maxTries; attempt++) {
        ensureLive();
        const analystPrompt = render(agents.repoAnalyst.prompt, {
            repo: result.repo,
            worst: result.worst,
            findings,
            liveCode,
            retryNote,
        });
        debug('repoAnalyst → calling LLM (attempt', String(attempt) + ')');
        const t0 = Date.now();
        const res = await makeModel(agents.repoAnalyst.temperature).invoke(analystPrompt, config);
        const text = contentToText(res.content);
        const obj = extractJson(text);
        explanation = (typeof obj?.summary === 'string' ? obj.summary : text.replace(/<think>[\s\S]*?<\/think>/g, '')).trim();
        escalate = normEscalate(obj?.escalate);
        debug(`repoAnalyst ← done (${Date.now() - t0}ms) · escalate=${escalate}`);

        ensureLive();
        const criticPrompt = render(agents.repoCritic.prompt, {
            findings,
            liveCode,
            analysis: JSON.stringify(obj ?? { summary: explanation }),
        });
        const cres = await makeModel(agents.repoCritic.temperature).invoke(criticPrompt, config);
        const cobj = extractJson(contentToText(cres.content));
        if (cobj?.ok !== false) {
            grounded = true;
            debug('repoCritic ← grounded');
            break;
        }
        retryNote = `\n\nA reviewer flagged your previous analysis: "${String(cobj.issue ?? '')}". Correct it, using ONLY the code/findings.`;
        debug('repoCritic ← not grounded →', String(cobj.issue ?? ''), '(retry)');
    }

    return { explanation, grounded, escalate };
}

// One parent trace per /repo/explain: the analyst ⇄ critic calls (and any retries) nest under a
// single run in LangSmith — so you can see all LLM calls for one request together — tagged with the
// repo and request id (rid) for filtering. No-op when tracing is off.
export async function repoExplain(
    owner: string,
    repo: string,
    result: RepoResult,
    config?: RunnableConfig,
): Promise<RepoExplainResult> {
    const rid = config?.metadata?.rid as string | undefined;
    const traced = traceable(repoExplainImpl, {
        name: 'repoExplain',
        run_type: 'chain',
        metadata: { owner, repo, ...(rid ? { rid } : {}) },
        tags: ['repo-explain'],
    });
    return traced(owner, repo, result, config);
}
