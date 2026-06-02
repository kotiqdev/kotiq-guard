import 'dotenv/config'; // load .env once, before anything reads process.env
import { z } from 'zod';

// Single source of runtime config. Validated with zod so a bad value fails fast and clearly.
const EnvSchema = z.object({
    KOTIQ_DEBUG: z.string().optional(),
    LLM_PROVIDER: z.enum(['ollama', 'gemini']).default('ollama'),
    OLLAMA_MODEL: z.string().default('qwen3:32b'),
    OLLAMA_BASE_URL: z.string().default('http://localhost:11434'),
    GOOGLE_API_KEY: z.string().optional(),
    GEMINI_MODEL: z.string().default('gemini-2.5-flash'),
});

const parsed = EnvSchema.parse(process.env);

export interface Env {
    debug: boolean;
    llmProvider: 'ollama' | 'gemini';
    ollamaModel: string;
    ollamaBaseUrl: string;
    googleApiKey?: string;
    geminiModel: string;
}

export const env: Env = {
    debug: parsed.KOTIQ_DEBUG === '1',
    llmProvider: parsed.LLM_PROVIDER,
    ollamaModel: parsed.OLLAMA_MODEL,
    ollamaBaseUrl: parsed.OLLAMA_BASE_URL,
    googleApiKey: parsed.GOOGLE_API_KEY,
    geminiModel: parsed.GEMINI_MODEL,
};
