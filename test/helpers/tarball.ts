// Shared helpers used by tests that mock the npm registry — ports kotiq-app/tests/conftest.py.
//
// Builds an in-memory gzipped tarball with the npm `package/` prefix layout and lets tests inject
// raw members (path-traversal, symlinks, oversized files) to exercise the safety guards.

import { gzipSync } from 'node:zlib';

import { Headers as TarHeaders, pack as tarPack } from 'tar-stream';

export interface RawMember {
  headers: TarHeaders;
  content: Buffer | null;
}

export async function makeTarball(
  files: Record<string, Buffer | string>,
  rawMembers: RawMember[] = [],
): Promise<Buffer> {
  const pack = tarPack();
  const chunks: Buffer[] = [];
  pack.on('data', (c: Buffer) => chunks.push(c));
  const done = new Promise<void>((resolve, reject) => {
    pack.on('end', () => resolve());
    pack.on('error', reject);
  });

  for (const [path, content] of Object.entries(files)) {
    const body = typeof content === 'string' ? Buffer.from(content) : content;
    await new Promise<void>((resolve, reject) => {
      pack.entry({ name: `package/${path}`, size: body.length }, body, (err) =>
        err ? reject(err) : resolve(),
      );
    });
  }
  for (const member of rawMembers) {
    await new Promise<void>((resolve, reject) => {
      const body = member.content ?? Buffer.alloc(0);
      pack.entry({ ...member.headers, size: body.length }, body, (err) =>
        err ? reject(err) : resolve(),
      );
    });
  }
  pack.finalize();
  await done;
  return gzipSync(Buffer.concat(chunks));
}

export interface PackageJsonOverrides {
  name?: string;
  version?: string;
  main?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  [key: string]: unknown;
}

export function makePackageJson(overrides: PackageJsonOverrides = {}): Buffer {
  const base = {
    name: 'demo-pkg',
    version: '1.2.3',
    main: 'index.js',
    scripts: { test: 'node test.js' },
    dependencies: { 'left-pad': '^1.3.0' },
  };
  return Buffer.from(JSON.stringify({ ...base, ...overrides }));
}
