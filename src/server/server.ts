import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Fastify from 'fastify';

import { guardGraph } from '../agent/graph/guard-graph';
import { isAllowed } from '../auth/access';
import { decodeIdTokenUnverified, verifyIdToken } from '../auth/verify';
import { env } from '../env';
import { debug } from '../logger';

async function start(): Promise<void> {
    const app = Fastify({ logger: false });

    // Permissive CORS so the browser extension (and local tools) can call /scan.
    // The Authorization header makes requests "non-simple", so the browser sends a CORS preflight
    // (OPTIONS) first — we must answer it with 204 + these headers, or the real request is blocked.
    app.addHook('onRequest', async (req, reply) => {
        reply.header('Access-Control-Allow-Origin', '*');
        reply.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
        reply.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
        reply.header('Access-Control-Max-Age', '86400');
        if (req.method === 'OPTIONS') return reply.code(204).send(); // answer the preflight
    });

    // Auth gate. When enabled, every request (except /health and CORS preflight) must carry a
    // valid Google ID token whose verified identity is on the allow-list. Verification checks the
    // token's SIGNATURE — a client cannot forge email/hd. Disabled locally so dev/curl just works.
    if (env.authEnabled) {
        if (!env.oauthClientId) throw new Error('AUTH_ENABLED is set but GOOGLE_OAUTH_CLIENT_ID is missing');
        app.addHook('onRequest', async (req, reply) => {
            // /me resolves the user's tier (incl. Lite, who are NOT allow-listed) → must skip the gate.
            if (req.method === 'OPTIONS' || req.url === '/health' || req.url.startsWith('/me')) return;
            const header = req.headers.authorization ?? '';
            const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
            if (!token) return reply.code(401).send({ error: 'missing bearer token' });
            try {
                const id = await verifyIdToken(token, env.oauthClientId as string);
                if (!isAllowed(id, env.allowedEmails, env.allowedDomains)) {
                    debug('auth ✕ forbidden ·', id.email);
                    return reply.code(403).send({ error: 'not allowed' });
                }
                debug('auth ✓', id.email);
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
            const role = isAllowed(id, env.allowedEmails, env.allowedDomains) ? 'pro' : 'lite';
            debug('/me', id.email, '→', role);
            return { role, email: id.email };
        } catch (e) {
            debug('/me ✕', (e as Error).message);
            return reply.code(401).send({ error: 'invalid token' });
        }
    });

    // GET /scan?pkg=event-stream@3.3.6  →  VerdictCard + explanation
    app.get<{ Querystring: { pkg: string; from?: string; explain?: string } }>(
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
                    },
                },
            },
        },
        async (req, reply) => {
            const pkg = req.query.pkg.trim();
            const withExplanation = req.query.explain !== 'false';
            debug('GET /scan', pkg, withExplanation ? '' : '(fast, no LLM)', req.query.from ? `from ${req.query.from}` : '');

            // If the client goes away (extension cancel), abort the graph → aborts the in-flight LLM call.
            const ac = new AbortController();
            req.raw.on('close', () => {
                if (!reply.raw.writableEnded) {
                    ac.abort();
                    debug('/scan ✕ client disconnected — aborting agents ·', pkg);
                }
            });

            const t0 = Date.now();
            try {
                const result = await guardGraph.invoke({ packageName: pkg, withExplanation }, { signal: ac.signal });
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
