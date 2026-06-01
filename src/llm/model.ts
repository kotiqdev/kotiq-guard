import { ChatGoogleGenerativeAI } from '@langchain/google-genai';
import { ChatOllama } from '@langchain/ollama';
import type { BaseChatModel } from '@langchain/core/language_models/chat_models';

// Picks the LLM provider from env. Same interface either way, so node code never changes.
//   LLM_PROVIDER=ollama (default) → local, free, private. Needs Ollama running + a pulled model.
//   LLM_PROVIDER=gemini           → Google AI Studio. Needs GOOGLE_API_KEY.
export function makeModel(): BaseChatModel {
    const provider = process.env.LLM_PROVIDER ?? 'ollama';

    if (provider === 'gemini') {
        return new ChatGoogleGenerativeAI({
            model: process.env.GEMINI_MODEL ?? 'gemini-2.5-flash',
            apiKey: process.env.GOOGLE_API_KEY,
            temperature: 0,
        });
    }

    return new ChatOllama({
        model: process.env.OLLAMA_MODEL ?? 'qwen3:32b',
        baseUrl: process.env.OLLAMA_BASE_URL ?? 'http://localhost:11434',
        temperature: 0,
    });
}
