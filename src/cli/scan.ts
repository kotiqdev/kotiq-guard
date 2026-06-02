// One-shot scan CLI — `npm run scan -- <name>[@<version>]`.
//
// Runs the deterministic pipeline on a single npm package and prints the resulting VerdictCard as
// JSON to stdout.
//
// Exit codes:
//   0  SAFE / SUSPICIOUS / NEEDS_REVIEW (informational — see the verdict)
//   2  MALICIOUS
//   1  usage error

import { analyzePackage } from '../core/pipeline/pipeline';

export function splitSpec(spec: string): { name: string; version: string | null } {
  const trimmed = spec.trim();
  // Last `@` after position 0 splits name@version; a leading `@` belongs to a scoped name.
  const at = trimmed.lastIndexOf('@');
  if (at > 0) return { name: trimmed.slice(0, at), version: trimmed.slice(at + 1) };
  return { name: trimmed, version: null };
}

export async function main(argv: string[]): Promise<number> {
  if (argv.length !== 1 || !argv[0].trim()) {
    process.stderr.write('usage: npm run scan -- <name>[@<version>]\n');
    return 1;
  }
  const { name, version } = splitSpec(argv[0]);
  const card = await analyzePackage(name, version);
  process.stdout.write(`${JSON.stringify(card, null, 2)}\n`);
  return card.verdict === 'MALICIOUS' ? 2 : 0;
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      process.stderr.write(`error: ${(err as Error).message}\n`);
      process.exit(1);
    },
  );
}
