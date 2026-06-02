import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Fastify from 'fastify';

import { guardGraph } from '../agent/graph/guard-graph';
import { env } from '../env';
import { debug } from '../logger';

async function start(): Promise<void> {
    const app = Fastify({ logger: false });

    // Permissive CORS so the browser extension (and local tools) can call /scan.
    app.addHook('onRequest', async (_req, reply) => {
        reply.header('Access-Control-Allow-Origin', '*');
        reply.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
    });

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

    // GET /scan?pkg=event-stream@3.3.6  →  VerdictCard + explanation
    app.get<{ Querystring: { pkg: string } }>(
        '/scan',
        {
            schema: {
                description: 'Scan an npm package and return a verdict + plain-language explanation.',
                querystring: {
                    type: 'object',
                    required: ['pkg'],
                    properties: {
                        pkg: { type: 'string', description: 'npm package, e.g. "event-stream@3.3.6"' },
                    },
                },
            },
        },
        async (req) => {
            const pkg = req.query.pkg.trim();
            debug('GET /scan', pkg);
            const result = await guardGraph.invoke({ packageName: pkg });
            return { ...result.verdict, explanation: result.explanation };
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
