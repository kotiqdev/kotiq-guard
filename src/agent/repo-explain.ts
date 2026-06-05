// Pro repo-scan explainer — the AI layer over the deterministic repo self-scan.
//
// The self-scan findings are authoritative facts. This adds a small agentic loop on top:
//   repoAnalyst — narrates, in plain language, what the repo does and the attacker's goal,
//                 grounded STRICTLY in the findings.
//   repoCritic  — checks the narration invented nothing; on fail, sends it back (≤ maxTries).
// The deterministic findings remain the floor; the narrative only adds context, never lowers it.

import type { RunnableConfig } from '@langchain/core/runnables';

import { debug } from '../logger';
import { makeModel } from './llm/model';
import { agents, render } from './prompts';
import type { DepFinding, RepoResult } from '../core/repo/repo-scan';
import type { RepoSelfFinding } from '../core/repo/self-scan';

export interface RepoExplainResult {
    explanation: string;
    grounded: boolean;
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
    const self = (result.self?.findings ?? []).map(selfLine);
    const deps = result.flagged.map(depLine);
    const lines = [...self, ...deps];
    return lines.length ? lines.join('\n') : '(no risky behaviour detected)';
}

export async function repoExplain(result: RepoResult, config?: RunnableConfig): Promise<RepoExplainResult> {
    const findings = findingsBlock(result);
    const maxTries = agents.repoCritic.maxTries ?? 2;

    let explanation = '';
    let grounded = false;
    let retryNote = '';

    for (let attempt = 1; attempt <= maxTries; attempt++) {
        const analystPrompt = render(agents.repoAnalyst.prompt, {
            repo: result.repo,
            worst: result.worst,
            findings,
            retryNote,
        });
        debug('repoAnalyst → calling LLM (attempt', String(attempt) + ')');
        const t0 = Date.now();
        const res = await makeModel(agents.repoAnalyst.temperature).invoke(analystPrompt, config);
        explanation = String(res.content).replace(/<think>[\s\S]*?<\/think>/g, '').trim();
        debug(`repoAnalyst ← done (${Date.now() - t0}ms)`);

        const criticPrompt = render(agents.repoCritic.prompt, { findings, explanation });
        const cres = await makeModel(agents.repoCritic.temperature).invoke(criticPrompt, config);
        const obj = extractJson(String(cres.content));
        if (obj?.ok !== false) {
            grounded = true;
            debug('repoCritic ← grounded');
            break;
        }
        retryNote = `\n\nA reviewer flagged your previous explanation: "${String(obj.issue ?? '')}". Correct it, using ONLY the findings.`;
        debug('repoCritic ← not grounded →', String(obj.issue ?? ''), '(retry)');
    }

    return { explanation, grounded };
}
