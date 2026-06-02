// Kotiq Guard — LangGraph orchestration over the deterministic engine.
// Graph: scan (deterministic verdict) → explain (LLM turns it into plain language).


import { Annotation, END, START, StateGraph } from '@langchain/langgraph';

import { splitSpec } from '../../cli/scan';
import { debug } from '../../logger';
import { makeModel } from '../llm/model';
import { VerdictCard } from '../../core/models/contracts';
import { analyzePackage } from '../../core/pipeline/pipeline';

// Graph state: shared channels the nodes read/write.
const GuardState = Annotation.Root({
    packageName: Annotation<string>(),
    verdict: Annotation<VerdictCard | null>(),
    explanation: Annotation<string>(),
});

// Node 1 — run the deterministic engine. Its return is merged into the state.
async function scanNode(
    state: typeof GuardState.State,
): Promise<Partial<typeof GuardState.State>> {
    const { name, version } = splitSpec(state.packageName);
    debug('scan →', name, version ?? '(latest)');
    const verdict = await analyzePackage(name, version);
    debug(
        'verdict:', verdict.verdict,
        `risk=${verdict.risk_score}`,
        `findings=${verdict.top_findings.length}`,
        `osint=${verdict.reputation.length}`,
    );
    return { verdict };
}

// Node 2 — ask the LLM to explain the verdict in plain language. It never changes the verdict.
async function explainNode(
    state: typeof GuardState.State,
): Promise<Partial<typeof GuardState.State>> {
    const v = state.verdict;
    if (!v) return {};

    const prompt = `You are a security assistant for developers. A developer asked whether the npm package "${state.packageName}" is safe to install.
Here is a deterministic scan result — do NOT change the verdict, only explain it:

${JSON.stringify(v, null, 2)}

In 2-3 short sentences of plain language: what this verdict means and what the developer should do. No markdown.`;

    debug('explain → calling LLM');
    const res = await makeModel().invoke(prompt);
    // qwen3 (Ollama) may wrap reasoning in <think>…</think>; strip it for a clean answer.
    const explanation = String(res.content).replace(/<think>[\s\S]*?<\/think>/g, '').trim();
    return { explanation };
}

export const guardGraph = new StateGraph(GuardState)
    .addNode('scan', scanNode)
    .addNode('explain', explainNode)
    .addEdge(START, 'scan')
    .addEdge('scan', 'explain')
    .addEdge('explain', END)
    .compile();

// Run directly: npm run guard -- event-stream@3.3.6
if (require.main === module) {
    const spec = process.argv[2];
    debug('spec:', spec);
    if (!spec) {
        process.stderr.write('usage: npm run guard -- <name>[@<version>]\n');
        process.exit(1);
    }
    guardGraph
        .invoke({ packageName: spec })
        .then((result) => {
            const out = result.verdict
                ? { ...result.verdict, explanation: result.explanation }
                : { explanation: result.explanation };
            process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
            process.exit(result.verdict?.verdict === 'MALICIOUS' ? 2 : 0);
        })
        .catch((err: unknown) => {
            process.stderr.write(`error: ${(err as Error).message}\n`);
            process.exit(1);
        });
}
