// Loads the agent prompts/config from agents.yml, validates them, and renders {{placeholders}}.
// The prompts are DATA (agents.yml); the agent logic lives in the graph nodes.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { parse } from 'yaml';
import { z } from 'zod';

const AgentSchema = z.object({
    purpose: z.string().optional(), // human doc: what this agent is for
    next: z.string().optional(), // human doc: where it routes
    temperature: z.number().default(0),
    maxTries: z.number().int().positive().optional(), // critic: re-runs before fallback
    prompt: z.string().min(1),
});

const ConfigSchema = z.object({
    agents: z.object({
        security: AgentSchema,
        critic: AgentSchema,
        explain: AgentSchema,
        repoAnalyst: AgentSchema,
        repoCritic: AgentSchema,
    }),
});

export type AgentConfig = z.infer<typeof AgentSchema>;
export type AgentName = keyof z.infer<typeof ConfigSchema>['agents'];

// Read + validate once at startup. A malformed agents.yml fails fast with a clear zod error.
const raw = readFileSync(join(__dirname, 'agents.yml'), 'utf8');
export const agents = ConfigSchema.parse(parse(raw)).agents;

// Fill {{var}} placeholders from `vars`; unknown placeholders become empty strings.
export function render(template: string, vars: Record<string, string>): string {
    return template.replace(/\{\{(\w+)\}\}/g, (_, key: string) => vars[key] ?? '');
}
