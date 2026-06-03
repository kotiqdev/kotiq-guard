// Kotiq Guard — LangGraph orchestration over the deterministic engine.
//
// Graph:  scan → (END | security ⇄ critic → decide → explain)
//   scan      — deterministic verdict (the trustworthy floor). Fast; runs always.
//   security  — LLM reads the install-hook command + source and judges WHAT it actually does.
//               Escalate-only: it can raise concern, never lower the deterministic verdict.
//   critic    — checks the security judgment is grounded in the real scripts (no hallucination).
//               If not, sends it back to `security` to reconsider (≤3 tries), then a conservative
//               fallback. A self-correcting cycle.
//   decide    — escalate-only: bumps the verdict by the (validated) security level (SAFE→SUSPICIOUS),
//               never to MALICIOUS, never lower.
//   explain   — turns the effective verdict + security note into plain language for the user.
// withExplanation=false → stop after scan (instant deterministic badge, no LLM).

import { Annotation, END, START, StateGraph } from '@langchain/langgraph';

import { splitSpec } from '../../cli/scan';
import { debug } from '../../logger';
import { makeModel } from '../llm/model';
import { HookSource, VerdictCard } from '../../core/models/contracts';
import { Action, Verdict } from '../../core/models/enums';
import { analyzeWithContext } from '../../core/pipeline/pipeline';

type SecurityLevel = 'ok' | 'warn' | 'alert';

const MAX_SECURITY_TRIES = 3;

const GuardState = Annotation.Root({
    packageName: Annotation<string>(),
    withExplanation: Annotation<boolean>(),
    verdict: Annotation<VerdictCard | null>(),
    installHooks: Annotation<Record<string, string>>(),
    hookSources: Annotation<HookSource[]>(),
    securityLevel: Annotation<SecurityLevel>(),
    securityNote: Annotation<string>(),
    securityAttempts: Annotation<number>(),
    criticPass: Annotation<boolean>(),
    criticIssue: Annotation<string>(),
    effectiveVerdict: Annotation<VerdictCard['verdict']>(),
    effectiveAction: Annotation<VerdictCard['recommended_action']>(),
    explanation: Annotation<string>(),
});

type State = typeof GuardState.State;

// Render the readable hook script sources (or note that none were shipped).
function renderSources(sources: HookSource[]): string {
    return sources.length
        ? sources.map((s) => `--- ${s.path} ---\n${s.content}`).join('\n\n')
        : '(none of the hook scripts were shipped in the package, so we could NOT read them)';
}

// Pull the first {...} JSON object out of a possibly <think>-wrapped / prose-padded LLM reply.
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

// ── Node: deterministic engine (the floor) ──────────────────────────────────────────────────────
async function scanNode(state: State): Promise<Partial<State>> {
    const { name, version } = splitSpec(state.packageName);
    debug('scan → (engine, no LLM)', name, version ?? '(latest)');
    const t0 = Date.now();
    const { card, installHooks, hookSources } = await analyzeWithContext(name, version);
    debug(
        `scan ← done (${Date.now() - t0}ms):`, card.verdict,
        `risk=${card.risk_score}`,
        `findings=${card.top_findings.length}`,
        `osint=${card.reputation.length}`,
        `hooks=${Object.keys(installHooks).length}`,
    );
    return { verdict: card, installHooks, hookSources };
}

// ── Node: security analyst over the install hooks (escalate-only) ────────────────────────────────
async function securityNode(state: State): Promise<Partial<State>> {
    const hooks = state.installHooks ?? {};
    const sources = state.hookSources ?? [];
    const attempt = (state.securityAttempts ?? 0) + 1;

    if (Object.keys(hooks).length === 0) {
        debug('security → no install hooks, skip');
        return { securityLevel: 'ok', securityNote: 'No install hooks declared.', securityAttempts: attempt };
    }

    const retryNote = state.criticIssue
        ? `\n\nA reviewer flagged your previous analysis: "${state.criticIssue}". Reconsider carefully and correct it.`
        : '';

    const prompt = `You are a security analyst. A developer is about to add the npm package "${state.packageName}" as a DEPENDENCY. Judge ONLY its install hooks.

Install hooks (hookName: command):
${JSON.stringify(hooks, null, 2)}

Source of hook scripts we could read from the package tarball:
${renderSources(sources)}

Rules:
- preinstall / install / postinstall RUN automatically on a dependency install. "prepare" does NOT run for dependency installs (only the package's own local/git install).
- You can only RAISE concern, never lower it.
- "alert": a hook that runs on dependency install fetches/executes remote code, reads sensitive paths (~/.ssh, ~/.config/solana, wallet, keystore, .env), uses obfuscation/eval, or exfiltrates data.
- "warn": a hook that runs on dependency install calls a script we could NOT read (genuine uncertainty), or looks suspicious but unclear.
- "ok": only benign build tooling (tsc/build/husky setup), or the only hook is "prepare" (won't run for dependencies), or no real concern.${retryNote}

Respond with ONLY this JSON, nothing else:
{"level":"ok"|"warn"|"alert","reason":"<one short sentence>"}`;

    debug('security → analyzing', Object.keys(hooks).length, 'hook(s),', sources.length, 'readable source(s)', `(attempt ${attempt})`);
    const started = Date.now();
    const res = await makeModel().invoke(prompt);
    debug(`security ← done (${Date.now() - started}ms)`);

    const obj = extractJson(String(res.content));
    const level: SecurityLevel = obj?.level === 'ok' || obj?.level === 'alert' ? obj.level : 'warn';
    const reason = typeof obj?.reason === 'string' && obj.reason.trim() ? obj.reason.trim() : 'Install hooks need review.';
    debug('security verdict:', level, '—', reason);
    return { securityLevel: level, securityNote: reason, securityAttempts: attempt };
}

// ── Node: critic — is the security judgment grounded in the real scripts? ────────────────────────
async function criticNode(state: State): Promise<Partial<State>> {
    const hooks = state.installHooks ?? {};
    if (Object.keys(hooks).length === 0) return { criticPass: true };

    const prompt = `You verify a security analyst's judgment about an npm package's install hooks. Your ONLY job: check the judgment is GROUNDED in the actual hook data below — i.e. it does not invent scripts/paths/behavior that aren't present, and does not contradict the visible command/source.

Do NOT re-argue npm lifecycle facts — these are GIVEN and correct, do not flag a judgment for relying on them:
- preinstall / install / postinstall RUN on a dependency install.
- "prepare" does NOT run for dependency installs (only the package's own local/git install).

Install hooks:
${JSON.stringify(hooks, null, 2)}

Readable hook sources:
${renderSources(state.hookSources ?? [])}

The analyst concluded: level="${state.securityLevel}", reason="${state.securityNote}".

Flag (ok:false) ONLY if the reason references something not present in the data, or contradicts the visible scripts. A statement consistent with the data and the lifecycle facts above is grounded → ok:true.
Respond with ONLY this JSON: {"ok":true|false,"issue":"<short, empty if ok>"}`;

    debug('critic → calling LLM');
    const t0 = Date.now();
    const res = await makeModel().invoke(prompt);
    debug(`critic ← done (${Date.now() - t0}ms)`);
    const obj = extractJson(String(res.content));
    const ok = obj?.ok !== false; // can't parse / not explicitly false → don't block
    const issue = typeof obj?.issue === 'string' ? obj.issue : '';

    if (ok) {
        debug('critic ← pass');
        return { criticPass: true };
    }
    if ((state.securityAttempts ?? 0) >= MAX_SECURITY_TRIES) {
        debug('critic ← fail, retries exhausted → conservative fallback');
        return {
            criticPass: true,
            securityLevel: 'warn',
            securityNote: 'Could not reliably analyze the install hooks after several attempts — treat with caution.',
        };
    }
    debug('critic ← fail →', issue, '(retry security)');
    return { criticPass: false, criticIssue: issue };
}

// Escalate-only: the LLM agents may raise a clean/unknown verdict up to SUSPICIOUS, never to
// MALICIOUS (reserved for deterministic CRITICAL), never lower an already-higher verdict.
function escalate(
    verdict: VerdictCard['verdict'],
    action: VerdictCard['recommended_action'],
    level: SecurityLevel | undefined,
): { verdict: VerdictCard['verdict']; action: VerdictCard['recommended_action'] } {
    if ((level !== 'warn' && level !== 'alert') || (verdict !== 'SAFE' && verdict !== 'NEEDS_REVIEW')) {
        return { verdict, action };
    }
    return { verdict: Verdict.SUSPICIOUS, action: level === 'alert' ? Action.QUARANTINE : Action.ALLOW_WITH_WARNING };
}

// ── Node: decide the EFFECTIVE verdict from engine + (validated) security level ──────────────────
async function decideNode(state: State): Promise<Partial<State>> {
    const v = state.verdict;
    if (!v) return {};
    const { verdict, action } = escalate(v.verdict, v.recommended_action, state.securityLevel);
    if (verdict !== v.verdict) debug('escalate:', v.verdict, '→', verdict, `(security=${state.securityLevel})`);
    return { effectiveVerdict: verdict, effectiveAction: action };
}

// ── Node: explain the effective verdict (+ validated security note) in plain language ────────────
async function explainNode(state: State): Promise<Partial<State>> {
    const v = state.verdict;
    if (!v) return {};

    const hooks = state.installHooks ?? {};
    const sources = state.hookSources ?? [];
    const effective = state.effectiveVerdict ?? v.verdict;
    const escalated = effective !== v.verdict;

    const hooksLine = Object.keys(hooks).length
        ? `Install hooks it declares: ${JSON.stringify(hooks)}. Kotiq ${
              sources.length
                  ? `READ the source of these hook scripts: ${sources.map((s) => s.path).join(', ')}`
                  : 'could NOT read any hook script source (none were shipped in the package)'
          }.`
        : 'It declares no install hooks.';

    const securityLine =
        state.securityLevel && state.securityLevel !== 'ok'
            ? `Security review of the hooks: ${state.securityLevel.toUpperCase()} — "${state.securityNote}".${escalated ? ` Because of this it is flagged ${effective} even though the deterministic scan alone was ${v.verdict}.` : ''}`
            : '';

    const prompt = `You are a security assistant for developers. A developer asked whether the npm package "${state.packageName}" is safe to install. Overall verdict: ${effective}.

Deterministic scan detail:
${JSON.stringify(v, null, 2)}

${hooksLine}
${securityLine}

Write 3-4 short, transparent sentences: name which install hooks exist (if any), state clearly whether Kotiq could read their script source or not, what the check concluded, and what the developer should do. Do NOT lower the verdict. No markdown.`;

    debug('explain → calling LLM');
    const started = Date.now();
    const res = await makeModel().invoke(prompt);
    debug(`explain ← done (${Date.now() - started}ms)`);
    const explanation = String(res.content).replace(/<think>[\s\S]*?<\/think>/g, '').trim();
    return { explanation };
}

// ── Routers ─────────────────────────────────────────────────────────────────────────────────────
function afterScan(state: State): 'security' | typeof END {
    return state.withExplanation === false ? END : 'security';
}

function afterCritic(state: State): 'security' | 'decide' {
    return state.criticPass ? 'decide' : 'security';
}

export const guardGraph = new StateGraph(GuardState)
    .addNode('scan', scanNode)
    .addNode('security', securityNode)
    .addNode('critic', criticNode)
    .addNode('decide', decideNode)
    .addNode('explain', explainNode)
    .addEdge(START, 'scan')
    .addConditionalEdges('scan', afterScan)
    .addEdge('security', 'critic')
    .addConditionalEdges('critic', afterCritic)
    .addEdge('decide', 'explain')
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
                ? {
                      ...result.verdict,
                      effective_verdict: result.effectiveVerdict ?? result.verdict.verdict,
                      effective_action: result.effectiveAction ?? result.verdict.recommended_action,
                      scripts: {
                          hooks: result.installHooks ?? {},
                          readable: (result.hookSources ?? []).map((s) => s.path),
                      },
                      security: { level: result.securityLevel, note: result.securityNote },
                      explanation: result.explanation,
                  }
                : { explanation: result.explanation };
            process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
            process.exit(result.verdict?.verdict === 'MALICIOUS' ? 2 : 0);
        })
        .catch((err: unknown) => {
            process.stderr.write(`error: ${(err as Error).message}\n`);
            process.exit(1);
        });
}
