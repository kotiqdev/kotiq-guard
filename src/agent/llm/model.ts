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
        });
    }

    if (env.llmProvider === 'vertex') {
        return new ChatVertexAI({
            model: env.vertexModel,
            location: env.vertexLocation,
            temperature,
            maxOutputTokens: env.maxOutputTokens, // cost cap: bound the reply length
            // project comes from ADC; pass it explicitly when set so local + prod agree.
            ...(env.vertexProject ? { authOptions: { projectId: env.vertexProject } } : {}),
        });
    }

    return new ChatOllama({
        model: env.ollamaModel,
        baseUrl: env.ollamaBaseUrl,
        temperature,
    });
}
