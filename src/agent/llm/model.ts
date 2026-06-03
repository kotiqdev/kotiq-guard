import { ChatGoogleGenerativeAI } from '@langchain/google-genai';
import { ChatOllama } from '@langchain/ollama';
import type { BaseChatModel } from '@langchain/core/language_models/chat_models';

import { env } from '../../env';

// Picks the LLM provider from env. Same interface either way, so node code never changes.
//   ollama (default) → local, free, private. Needs Ollama running + a pulled model.
//   gemini           → Google AI Studio. Needs GOOGLE_API_KEY.
export function makeModel(temperature = 0): BaseChatModel {
    if (env.llmProvider === 'gemini') {
        return new ChatGoogleGenerativeAI({
            model: env.geminiModel,
            apiKey: env.googleApiKey,
            temperature,
        });
    }

    return new ChatOllama({
        model: env.ollamaModel,
        baseUrl: env.ollamaBaseUrl,
        temperature,
    });
}
