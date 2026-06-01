// Data contracts for Kotiq (Plan.md §3). Mirrors kotiq/models.py via zod.
//
// The zod schemas are the runtime source of truth (validation + defaults); the inferred TS types
// are the static source of truth. Objects are constructed with every field present (optionals as
// `null`) so JSON serialization matches Pydantic's `model_dump()` shape exactly.
import { z } from 'zod';

import { Action, Severity, Verdict } from './enums';

export const HookSourceSchema = z.object({
  path: z.string(),
  content: z.string(),
});
export type HookSource = z.infer<typeof HookSourceSchema>;

// Structured result of safely unpacking a package. `install_hooks` / `hook_sources` expose the
// actual pre/post-install code — where Contagious-Interview / Lazarus malware hides. On failure,
// `found` is false and `suggested_verdict` is NEEDS_REVIEW.
export const PackageManifestSchema = z.object({
  source_type: z.string().default('npm'),
  found: z.boolean(),
  name: z.string().nullable().default(null),
  version: z.string().nullable().default(null),
  file_tree: z.array(z.string()).default([]),
  scripts: z.record(z.string(), z.string()).default({}),
  dependencies: z.record(z.string(), z.string()).default({}),
  entrypoints: z.array(z.string()).default([]),
  notable_files: z.array(z.string()).default([]),
  install_hooks: z.record(z.string(), z.string()).default({}),
  hook_sources: z.array(HookSourceSchema).default([]),
  error: z.string().nullable().default(null),
  suggested_verdict: z.string().nullable().default(null),
});
export type PackageManifest = z.infer<typeof PackageManifestSchema>;

// A single static-analysis observation. Categories: `crypto_theft`, `install_hook`,
// `sensitive_file`.
export const RiskFindingSchema = z.object({
  category: z.string(),
  severity: z.nativeEnum(Severity),
  title: z.string(),
  file: z.string().nullable().default(null),
  line: z.number().int().nullable().default(null),
  snippet: z.string().nullable().default(null),
  explanation: z.string(),
  confidence: z.number().default(1.0),
});
export type RiskFinding = z.infer<typeof RiskFindingSchema>;

// An OSINT signal. `source` identifies the data feed: osv | depsdev | ghsa | web | typosquat.
export const ReputationFindingSchema = z.object({
  source: z.string(),
  severity: z.nativeEnum(Severity),
  summary: z.string(),
  references: z.array(z.string()).default([]),
});
export type ReputationFinding = z.infer<typeof ReputationFindingSchema>;

// Final aggregated decision returned by the reporter.
export const VerdictCardSchema = z.object({
  verdict: z.nativeEnum(Verdict),
  risk_score: z.number().int(),
  recommended_action: z.nativeEnum(Action),
  summary: z.string(),
  top_findings: z.array(RiskFindingSchema).default([]),
  reputation: z.array(ReputationFindingSchema).default([]),
});
export type VerdictCard = z.infer<typeof VerdictCardSchema>;
