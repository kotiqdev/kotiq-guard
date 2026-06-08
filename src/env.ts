import 'dotenv/config'; // load .env once, before anything reads process.env
import { z } from 'zod';

// Single source of runtime config. Validated with zod so a bad value fails fast and clearly.
const EnvSchema = z.object({
    KOTIQ_DEBUG: z.string().optional(),
    LLM_PROVIDER: z.enum(['ollama', 'gemini', 'vertex']).default('ollama'),
    OLLAMA_MODEL: z.string().default('qwen3:32b'),
    OLLAMA_BASE_URL: z.string().default('http://localhost:11434'),
    GOOGLE_API_KEY: z.string().optional(),
    GEMINI_MODEL: z.string().default('gemini-2.5-flash'),
    // Vertex AI (cloud): no API key — auth comes from ADC (gcloud locally / the
    // Cloud Run service account in prod). It only needs to know project + region + model.
    GOOGLE_CLOUD_PROJECT: z.string().optional(), // GCP project id; on Cloud Run ADC fills it in
    GOOGLE_CLOUD_LOCATION: z.string().default('europe-west1'),
    VERTEX_MODEL: z.string().default('gemini-2.5-flash'),
    // Cost guard: hard cap on tokens a cloud model may emit per call (Ollama is local/free, exempt).
    LLM_MAX_OUTPUT_TOKENS: z.coerce.number().default(1024),
    // Cap the model's internal "thinking" tokens (gemini-2.5 reasoning). Lower = faster, less depth.
    // Unset/empty → model default (dynamic). 0 → thinking off. Empty is treated as unset so a
    // forgotten secret doesn't silently disable thinking.
    LLM_THINKING_BUDGET: z.preprocess(
        (v) => (v === '' || v == null ? undefined : v),
        z.coerce.number().int().nonnegative().optional(),
    ),
    // Auth: verify a Google ID token and check it against an allow-list before serving /scan.
    AUTH_ENABLED: z.string().optional(), // "1"/"true" → on. Off locally, on in the cloud.
    GOOGLE_OAUTH_CLIENT_ID: z.string().optional(), // expected `aud` of the ID token
    ALLOWED_EMAILS: z.string().optional(), // comma-separated, e.g. "a@x.com,b@y.com"
    ALLOWED_DOMAINS: z.string().optional(), // comma-separated Workspace domains, matched vs verified `hd`
    // User store (who is pro/blocked): 'file' (dev JSON) | 'firestore' (prod, wired at deploy).
    USERS_STORE: z.enum(['file', 'firestore']).default('file'),
    USERS_FILE: z.string().default('data/users.json'),
    // Firestore collection for the user registry. Each env has its own project (→ its own Firestore),
    // so 'users' is enough; override only if a project is ever shared between environments.
    USERS_COLLECTION: z.string().default('users'),
    // Optional GitHub token for the repo scanner: lifts the 60/hr unauthenticated rate limit to
    // 5000/hr and lets it read private repos. Read-only; never required.
    GITHUB_TOKEN: z.string().optional(),
    // Abuse guard: max requests per identity (verified email when present, else client IP) per window.
    RATE_LIMIT_MAX: z.coerce.number().default(60),
    RATE_LIMIT_WINDOW_MS: z.coerce.number().default(60_000),
    PORT: z.coerce.number().default(8080),
});

const parsed = EnvSchema.parse(process.env);

// "a@x.com, b@y.com" → Set{"a@x.com","b@y.com"} (trimmed, lowercased, blanks dropped).
function toLowerSet(csv?: string): Set<string> {
    return new Set((csv ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
}

export interface Env {
    debug: boolean;
    llmProvider: 'ollama' | 'gemini' | 'vertex';
    ollamaModel: string;
    ollamaBaseUrl: string;
    googleApiKey?: string;
    geminiModel: string;
    vertexProject?: string;
    vertexLocation: string;
    vertexModel: string;
    maxOutputTokens: number;
    thinkingBudget?: number;
    authEnabled: boolean;
    oauthClientId?: string;
    allowedEmails: Set<string>;
    allowedDomains: Set<string>;
    usersStore: 'file' | 'firestore';
    usersFile: string;
    usersCollection: string;
    githubToken?: string;
    rateLimitMax: number;
    rateLimitWindowMs: number;
    port: number;
}

export const env: Env = {
    debug: parsed.KOTIQ_DEBUG === '1',
    llmProvider: parsed.LLM_PROVIDER,
    ollamaModel: parsed.OLLAMA_MODEL,
    ollamaBaseUrl: parsed.OLLAMA_BASE_URL,
    googleApiKey: parsed.GOOGLE_API_KEY,
    geminiModel: parsed.GEMINI_MODEL,
    vertexProject: parsed.GOOGLE_CLOUD_PROJECT,
    vertexLocation: parsed.GOOGLE_CLOUD_LOCATION,
    vertexModel: parsed.VERTEX_MODEL,
    maxOutputTokens: parsed.LLM_MAX_OUTPUT_TOKENS,
    thinkingBudget: parsed.LLM_THINKING_BUDGET,
    authEnabled: parsed.AUTH_ENABLED === '1' || parsed.AUTH_ENABLED === 'true',
    oauthClientId: parsed.GOOGLE_OAUTH_CLIENT_ID,
    allowedEmails: toLowerSet(parsed.ALLOWED_EMAILS),
    allowedDomains: toLowerSet(parsed.ALLOWED_DOMAINS),
    usersStore: parsed.USERS_STORE,
    usersFile: parsed.USERS_FILE,
    usersCollection: parsed.USERS_COLLECTION,
    githubToken: parsed.GITHUB_TOKEN,
    rateLimitMax: parsed.RATE_LIMIT_MAX,
    rateLimitWindowMs: parsed.RATE_LIMIT_WINDOW_MS,
    port: parsed.PORT,
};
