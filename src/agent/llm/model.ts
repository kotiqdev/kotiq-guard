import { ChatGoogleGenerativeAI } from '@langchain/google-genai';
import { ChatVertexAI } from '@langchain/google-vertexai';
import { ChatOllama } from '@langchain/ollama';
import type { BaseChatModel } from '@langchain/core/language_models/chat_models';

import { env } from '../../env';

// Picks the LLM provider from env. Same interface either way, so node code never changes.
//   ollama (default) → local, free, private. Needs Ollama running + a pulled model.
//   gemini           → Google AI Studio. Needs GOOGLE_API_KEY.
//   vertex           → Vertex AI on Google Cloud. NO key — auth via ADC (gcloud locally,
//                      the Cloud Run service account in prod). Needs project + location.
export function makeModel(temperature = 0): BaseChatModel {
    if (env.llmProvider === 'gemini') {
        return new ChatGoogleGenerativeAI({
            model: env.geminiModel,
            apiKey: env.googleApiKey,
            temperature,
            maxOutputTokens: env.maxOutputTokens, // cost cap: bound the reply length
            ...(env.thinkingBudget !== undefined ? { maxReasoningTokens: env.thinkingBudget } : {}),
        });
    }

    if (env.llmProvider === 'vertex') {
        return new ChatVertexAI({
            model: env.vertexModel,
            location: env.vertexLocation,
            temperature,
            maxOutputTokens: env.maxOutputTokens, // cost cap: bound the reply length
            ...(env.thinkingBudget !== undefined ? { maxReasoningTokens: env.thinkingBudget } : {}),
            // project comes from ADC; pass it explicitly when set so local + prod agree.
            ...(env.vertexProject ? { authOptions: { projectId: env.vertexProject } } : {}),
        });
    }

    return new ChatOllama({
        model: env.ollamaModel,
        baseUrl: env.ollamaBaseUrl,
        temperature,
        // Ollama has no token budget — only on/off. Treat budget 0 as "disable thinking" (e.g. qwen3);
        // unset / >0 leaves the model's default (thinking on). The numeric budget only affects cloud.
        ...(env.thinkingBudget === 0 ? { think: false } : {}),
    });
}
