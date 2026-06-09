import type { IncomingMessage, ServerResponse } from 'node:http';

import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Fastify from 'fastify';

import { guardGraph } from '../agent/graph/guard-graph';
import { escalateToVerdict, repoExplain } from '../agent/repo-explain';
import { decodeIdTokenUnverified, verifyIdToken } from '../auth/verify';
import { repoScan } from '../core/repo/repo-scan';
import { worseVerdict } from '../core/repo/verdict';
import { getPlan, recordSeen } from '../users';
import { env } from '../env';
import { debug } from '../logger';

// Abort an in-flight request's work (LLM agents) when the client goes away — extension Cancel, tab
// close, navigation. For an already-consumed GET, Node fires `aborted`/response `close`, NOT request
// `close`, so we listen on all three. Returns the AbortController to thread into the agent calls.
function abortWhenClientGone(rawReq: IncomingMessage, rawRes: ServerResponse, label: string): AbortController {
    const ac = new AbortController();
    const onGone = (src: string) => (): void => {
        if (!rawRes.writableEnded && !ac.signal.aborted) {
            ac.abort();
            debug(`${label} ✕ client gone (${src}) — aborting agents`);
        }
    };
    rawReq.on('close', onGone('req.close'));
    rawReq.on('aborted', onGone('req.aborted'));
    rawRes.on('close', onGone('res.close'));
    rawReq.socket?.on('close', onGone('socket.close')); // lowest-level, most reliable signal
    return ac;
}

// In-flight LLM requests by client-supplied id, so the client can cancel EXPLICITLY (POST /cancel).
// Browsers don't reliably tear down a keep-alive socket on fetch-abort, so socket-close detection
// alone misses extension cancels — the explicit signal is the reliable path.
const activeRequests = new Map<string, AbortController>();

async function start(): Promise<void> {
    // trustProxy → req.ip reflects the client (Cloud Run sets X-Forwarded-For), used as a rate-limit key.
    const app = Fastify({ logger: false, trustProxy: true });

    // Permissive CORS so the browser extension (and local tools) can call /scan.
    // The Authorization header makes requests "non-simple", so the browser sends a CORS preflight
    // (OPTIONS) first — we must answer it with 204 + these headers, or the real request is blocked.
    app.addHook('onRequest', async (req, reply) => {
        reply.header('Access-Control-Allow-Origin', '*');
        reply.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        reply.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
        reply.header('Access-Control-Max-Age', '86400');
        if (req.method === 'OPTIONS') return reply.code(204).send(); // answer the preflight
    });

    // Abuse guard: cap requests per client IP within a window, before auth/heavy work. We key on IP,
    // not on the token's email — the token's signature isn't verified at this stage (that happens in the
    // auth hook below), so its claims aren't a trust source here. In-memory per instance; a per-user
    // Firestore quota keyed on the verified email is the accurate follow-up. Tune via RATE_LIMIT_*.
    await app.register(rateLimit, {
        max: env.rateLimitMax,
        timeWindow: env.rateLimitWindowMs,
        allowList: (req) => req.method === 'OPTIONS' || req.url === '/health',
        keyGenerator: (req) => `ip:${req.ip}`,
    });

    // Auth gate. When enabled, every request (except /health and CORS preflight) must carry a
    // valid Google ID token whose verified identity is on the allow-list. Verification checks the
    // token's SIGNATURE — a client cannot forge email/hd. Disabled locally so dev/curl just works.
    if (env.authEnabled) {
        if (!env.oauthClientId) throw new Error('AUTH_ENABLED is set but GOOGLE_OAUTH_CLIENT_ID is missing');
        app.addHook('onRequest', async (req, reply) => {
            // /me (tier) and /repo (deterministic, any verified user) do their own auth → skip the pro-gate.
            if (
                req.method === 'OPTIONS' ||
                req.url === '/health' ||
                req.url.startsWith('/me') ||
                req.url.startsWith('/repo') ||
                req.url.startsWith('/cancel') // only aborts an in-flight request by its random id
            )
                return;
            const header = req.headers.authorization ?? '';
            const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
            if (!token) return reply.code(401).send({ error: 'missing bearer token' });
            try {
                const id = await verifyIdToken(token, env.oauthClientId as string);
                const plan = await getPlan(id);
                if (plan !== 'pro') {
                    debug('auth ✕', plan, '·', id.email);
                    return reply.code(403).send({ error: plan === 'blocked' ? 'blocked' : 'not allowed' });
                }
                debug('auth ✓ pro', id.email);
            } catch (e) {
                debug('auth ✕ invalid token ·', (e as Error).message);
                return reply.code(401).send({ error: 'invalid token' });
            }
        });
    }

    // OpenAPI spec + interactive Swagger UI at /docs.
    await app.register(swagger, {
        openapi: {
            info: {
                title: 'Kotiq Guard API',
                description: 'Scan an npm package for malicious install hooks before you install it.',
                version: '1.0.0',
            },
        },
    });
    await app.register(swaggerUi, { routePrefix: '/docs' });

    app.get('/health', async () => ({ ok: true }));

    // POST /cancel?rid=<id> → abort an in-flight LLM request the client started (explicit cancel).
    app.post<{ Querystring: { rid?: string } }>('/cancel', async (req) => {
        const ac = req.query.rid ? activeRequests.get(req.query.rid) : undefined;
        if (ac) {
            ac.abort();
            debug('/cancel → aborted', req.query.rid);
        }
        return { ok: true, cancelled: !!ac };
    });

    // Who am I + which tier. The extension calls this after sign-in to choose Pro vs Lite UI.
    //   allow-listed verified Google user → "pro" · any other verified Google user → "lite".
    app.get('/me', async (req, reply) => {
        const header = req.headers.authorization ?? '';
        const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
        if (!token) return reply.code(401).send({ error: 'missing bearer token' });
        try {
            // Verify the signature when an OAuth client id is set; locally (none set) decode-only.
            const id = env.oauthClientId
                ? await verifyIdToken(token, env.oauthClientId)
                : decodeIdTokenUnverified(token);
            const user = await recordSeen(id); // upsert the registry (lastSeen + name/picture)
            const plan = await getPlan(id);
            if (plan === 'blocked') return reply.code(403).send({ error: 'blocked' });
            const role = plan === 'pro' ? 'pro' : 'lite';
            debug('/me', id.email, '→', role);
            return { role, email: id.email, name: user.name, picture: user.picture };
        } catch (e) {
            debug('/me ✕', (e as Error).message);
            return reply.code(401).send({ error: 'invalid token' });
        }
    });

    // GET /repo?owner=vitejs&repo=vite → scan a repo's dependency tree (deterministic, any verified user).
    app.get<{ Querystring: { owner?: string; repo?: string } }>('/repo', async (req, reply) => {
        if (env.authEnabled) {
            const header = req.headers.authorization ?? '';
            const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
            if (!token) return reply.code(401).send({ error: 'missing bearer token' });
            try {
                await verifyIdToken(token, env.oauthClientId as string);
            } catch {
                return reply.code(401).send({ error: 'invalid token' });
            }
        }
        const { owner, repo } = req.query;
        if (!owner || !repo) return reply.code(400).send({ error: 'owner and repo are required' });
        debug('GET /repo', `${owner}/${repo}`);
        const result = await repoScan(owner, repo);
        debug(
            '/repo ←',
            `${owner}/${repo}`,
            result.found ? `${result.worst} · ${result.withHooks} hook deps` : `skipped · ${result.error ?? 'not a Node project'}`,
        );
        return result;
    });

    // GET /repo/explain?owner=&repo=&rid= → Pro: an AI narrative (analyst ⇄ critic) over the findings.
    app.get<{ Querystring: { owner?: string; repo?: string; rid?: string } }>('/repo/explain', async (req, reply) => {
        const { owner, repo, rid } = req.query;
        if (!owner || !repo) return reply.code(400).send({ error: 'owner and repo are required' });

        // Pro gate: the AI layer is a paid feature. (Local dev with auth off → allowed.)
        if (env.authEnabled) {
            const header = req.headers.authorization ?? '';
            const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
            if (!token) return reply.code(401).send({ error: 'missing bearer token' });
            try {
                const id = await verifyIdToken(token, env.oauthClientId as string);
                const plan = await getPlan(id);
                if (plan !== 'pro') return reply.code(403).send({ error: 'pro_required' });
            } catch {
                return reply.code(401).send({ error: 'invalid token' });
            }
        }

        // Register for explicit cancel (POST /cancel?rid) BEFORE the multi-second repo re-scan, so
        // Cancel works the whole time the spinner shows; a cancel during the scan makes repoExplain
        // bail before any LLM call.
        const ac = abortWhenClientGone(req.raw, reply.raw, `/repo/explain ${owner}/${repo}`);
        if (rid) activeRequests.set(rid, ac);
        const t0 = Date.now();
        try {
            const result = await repoScan(owner, repo);
            if (!result.found) return reply.code(404).send({ error: result.error ?? 'not a Node repo' });

            const hasRisk = (result.self?.findings.length ?? 0) > 0 || result.flagged.length > 0;
            if (!hasRisk) {
                return { explanation: "Kotiq found no risky behaviour in this repository's own files or its dependencies' install hooks.", grounded: true, worst: result.worst };
            }
            if (ac.signal.aborted) return { aborted: true };

            debug('GET /repo/explain', `${owner}/${repo}`, '·', result.worst);
            const ai = await repoExplain(owner, repo, result, { signal: ac.signal, metadata: { rid } });
            const worst = worseVerdict(result.worst, escalateToVerdict(ai.escalate)); // escalate-only
            debug(`/repo/explain ← ${Date.now() - t0}ms · grounded=${ai.grounded} · escalate=${ai.escalate}`);
            return { explanation: ai.explanation, grounded: ai.grounded, worst };
        } catch (e) {
            if (ac.signal.aborted) return { aborted: true };
            debug('/repo/explain ✕', (e as Error).message);
            return reply.code(502).send({ error: 'AI explanation failed', detail: (e as Error).message });
        } finally {
            if (rid) activeRequests.delete(rid);
        }
    });

    // GET /scan?pkg=event-stream@3.3.6  →  VerdictCard + explanation
    app.get<{ Querystring: { pkg: string; from?: string; explain?: string; rid?: string } }>(
        '/scan',
        {
            schema: {
                description: 'Scan an npm package and return a verdict + plain-language explanation.',
                querystring: {
                    type: 'object',
                    required: ['pkg'],
                    properties: {
                        pkg: { type: 'string', description: 'npm package, e.g. "event-stream@3.3.6"' },
                        from: { type: 'string', description: 'page URL the scan was triggered from (for logs)' },
                        explain: { type: 'string', description: 'set to "false" to skip the LLM explanation (instant verdict)' },
                        rid: { type: 'string', description: 'client request id, for explicit cancel via POST /cancel' },
                    },
                },
            },
        },
        async (req, reply) => {
            const pkg = req.query.pkg.trim();
            const withExplanation = req.query.explain !== 'false';
            debug('GET /scan', pkg, withExplanation ? '' : '(fast, no LLM)', req.query.from ? `from ${req.query.from}` : '');

            // Abort on explicit client cancel (POST /cancel?rid) or if the client goes away.
            const rid = req.query.rid;
            const ac = abortWhenClientGone(req.raw, reply.raw, `/scan ${pkg}`);
            if (rid) activeRequests.set(rid, ac);

            const t0 = Date.now();
            try {
                const result = await guardGraph.invoke({ packageName: pkg, withExplanation }, { signal: ac.signal, metadata: { pkg, rid } });
                debug(`/scan ← total ${Date.now() - t0}ms ·`, pkg, result.verdict?.verdict ?? '?');
                return {
                    ...result.verdict,
                    ...(result.effectiveVerdict
                        ? { effective_verdict: result.effectiveVerdict, effective_action: result.effectiveAction }
                        : {}),
                    scripts: {
                        hooks: result.installHooks ?? {},
                        readable: (result.hookSources ?? []).map((s) => s.path),
                    },
                    ...(result.securityLevel ? { security: { level: result.securityLevel, note: result.securityNote } } : {}),
                    explanation: result.explanation,
                };
            } catch (e) {
                if (ac.signal.aborted) {
                    debug(`/scan ✕ aborted after ${Date.now() - t0}ms ·`, pkg);
                    return { aborted: true };
                }
                throw e;
            } finally {
                if (rid) activeRequests.delete(rid);
            }
        },
    );

    // host 0.0.0.0 is required for Cloud Run (bind all interfaces, not just localhost).
    await app.listen({ port: env.port, host: '0.0.0.0' });
    console.log(`kotiq-guard server on http://localhost:${env.port}  ·  docs: /docs`);
}

start().catch((err) => {
    console.error(err);
    process.exit(1);
});
