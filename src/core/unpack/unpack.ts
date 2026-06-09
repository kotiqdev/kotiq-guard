// Safe npm ingestion. Downloads a package tarball and unpacks it **without executing anything**,
// returning an PackageManifest (file tree, scripts, dependencies, entrypoints, notable files) and —
// the killer feature — the *source* of any install hooks.
//
// Safety: passive HTTP GETs only. Reads selected files straight out of the tar stream in memory.
// Never writes the package to disk, never runs install scripts, spawns a subprocess, or evaluates
// code. Hardened against path-traversal, symlinks, and decompression bombs via the caps in
// `../config/configuration`.

import { createGunzip } from 'node:zlib';
import { Readable } from 'node:stream';

import { extract as tarExtract, Headers as TarHeaders } from 'tar-stream';

import {
  HTTP_TIMEOUT_MS,
  MAX_FILE_BYTES,
  MAX_FILES,
  MAX_HOOK_SOURCE_BYTES,
  MAX_TARBALL_BYTES,
  MAX_TOTAL_EXTRACTED_BYTES,
  NPM_REGISTRY,
} from '../config/configuration';
import { HookSource, PackageManifest, PackageManifestSchema } from '../models/contracts';
import { Verdict } from '../models/enums';

// Lifecycle scripts that run automatically on install — the dangerous ones.
const HOOK_NAMES = ['preinstall', 'install', 'postinstall', 'prepare'] as const;

// Sensitive filenames worth flagging (Plan.md §6: wallet / seed-phrase / key access).
const NOTABLE_RE = /(^|\/)(\.env(\..+)?|wallet.*|.*keystore.*|id_rsa.*|.*\.pem|.*\.key)$/i;

// Local script files an install hook may invoke (`node install.js`, `sh setup.sh`, …).
const SCRIPT_FILE_RE = /[\w./\-]+\.(?:c?js|mjs|ts|sh|py)/gi;

function failManifest(name: string, message: string): PackageManifest {
  return PackageManifestSchema.parse({
    found: false,
    name,
    error: message,
    suggested_verdict: Verdict.NEEDS_REVIEW,
  });
}

function encodePackageName(name: string): string {
  // npm scoped names: keep the leading `@` intact, percent-encode the `/`.
  if (name.startsWith('@')) {
    const slash = name.indexOf('/');
    if (slash > 0) return `@${encodeURIComponent(name.slice(1, slash))}%2F${encodeURIComponent(name.slice(slash + 1))}`;
  }
  return encodeURIComponent(name);
}

async function fetchWithTimeout(url: string, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

interface ResolvedTarball {
  resolvedVersion: string;
  tarballUrl: string;
}

async function resolveTarball(name: string, version: string | null): Promise<ResolvedTarball> {
  const url = `${NPM_REGISTRY}/${encodePackageName(name)}`;
  let resp: Response;
  try {
    resp = await fetchWithTimeout(url, { headers: { Accept: 'application/json' } });
  } catch (exc) {
    throw new Error(`registry request failed: ${(exc as Error).message}`);
  }
  if (resp.status === 404) throw new Error('package not found in the npm registry');
  if (!resp.ok) throw new Error(`registry returned HTTP ${resp.status}`);

  const doc = (await resp.json()) as Record<string, any>;
  const versions = (doc.versions ?? {}) as Record<string, any>;
  const resolved = version ?? (doc['dist-tags'] ?? {}).latest;
  if (!resolved || !(resolved in versions)) {
    throw new Error(`version ${JSON.stringify(version)} not found for ${JSON.stringify(name)}`);
  }
  const tarball = ((versions[resolved] ?? {}).dist ?? {}).tarball;
  if (!tarball) throw new Error(`no tarball URL for ${name}@${resolved}`);
  return { resolvedVersion: resolved, tarballUrl: tarball };
}

async function downloadTarball(tarballUrl: string): Promise<Buffer> {
  let resp: Response;
  try {
    resp = await fetchWithTimeout(tarballUrl, { redirect: 'follow' });
  } catch (exc) {
    throw new Error(`tarball download failed: ${(exc as Error).message}`);
  }
  if (!resp.ok) throw new Error(`tarball download returned HTTP ${resp.status}`);
  if (!resp.body) throw new Error('tarball download returned an empty body');

  const chunks: Buffer[] = [];
  let total = 0;
  const reader = resp.body.getReader();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > MAX_TARBALL_BYTES) {
      try {
        await reader.cancel();
      } catch {
        /* ignore */
      }
      throw new Error(`tarball exceeds ${MAX_TARBALL_BYTES} bytes`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

function stripPkgPrefix(name: string): string {
  return name.startsWith('package/') ? name.slice('package/'.length) : name;
}

interface ExtractedFile {
  header: TarHeaders;
  relPath: string;
  // The raw body bytes, sliced to MAX_FILE_BYTES + 1 (so we can detect oversized).
  body: Buffer;
}

function readStreamToBuffer(stream: NodeJS.ReadableStream, limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    stream.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total <= limit) {
        chunks.push(chunk);
      } else {
        const remaining = limit - (total - chunk.length);
        if (remaining > 0) chunks.push(chunk.slice(0, remaining));
        // Add a single overflow byte sentinel so the caller can know we exceeded the cap.
        chunks.push(Buffer.from([0]));
      }
    });
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

// Extract every regular-file member from the tarball in memory, applying the safety caps and
// path-traversal/symlink filters. Files larger than MAX_FILE_BYTES are kept as empty bodies; the
// caller decides whether that entry is still useful (e.g. for the file_tree).
async function extractAll(tarball: Buffer): Promise<ExtractedFile[]> {
  return new Promise((resolve, reject) => {
    const out: ExtractedFile[] = [];
    const extractor = tarExtract();
    let count = 0;
    let totalBytes = 0; // running total of decompressed bytes held — keeps memory bounded
    let stopped = false;

    extractor.on('entry', (header, stream, next) => {
      if (stopped) {
        stream.resume();
        next();
        return;
      }
      if (header.type !== 'file') {
        stream.resume();
        next();
        return;
      }
      const rel = stripPkgPrefix(header.name);
      if (rel.startsWith('/') || rel.startsWith('../') || rel.includes('/../') || rel === '..') {
        stream.resume();
        next();
        return;
      }
      if (count >= MAX_FILES) {
        stopped = true;
        stream.resume();
        next();
        return;
      }
      count++;
      // Capacity for the body is one byte past the per-file cap so callers can detect overflow.
      readStreamToBuffer(stream, MAX_FILE_BYTES + 1)
        .then((body) => {
          out.push({ header, relPath: rel, body });
          totalBytes += body.length;
          if (totalBytes > MAX_TOTAL_EXTRACTED_BYTES) stopped = true; // over budget → stop reading more
          next();
        })
        .catch((err) => {
          // A member read error aborts the whole unpack (next(err) → extractor 'error' → reject):
          // fail-closed, so the package gets a cautious/error verdict instead of a partial scan that
          // could silently skip — and miss — a malicious file.
          next(err);
        });
    });

    extractor.on('finish', () => resolve(out));
    extractor.on('error', reject);

    const gunzip = createGunzip();
    gunzip.on('error', reject);
    Readable.from(tarball).pipe(gunzip).pipe(extractor);
  });
}

function decodeBody(body: Buffer, limit: number): string | null {
  if (body.length > MAX_FILE_BYTES) return null;
  return body.slice(0, limit).toString('utf8');
}

function entrypoints(pkg: Record<string, any>): string[] {
  const out: string[] = [];
  for (const key of ['main', 'module']) {
    const val = pkg[key];
    if (typeof val === 'string') out.push(val);
  }
  const bin = pkg.bin;
  if (typeof bin === 'string') {
    out.push(bin);
  } else if (bin && typeof bin === 'object') {
    for (const v of Object.values(bin)) {
      if (typeof v === 'string') out.push(v);
    }
  }
  const exp = pkg.exports;
  if (typeof exp === 'string') out.push(exp);
  // De-dup while preserving order.
  const seen = new Set<string>();
  return out.filter((e) => (seen.has(e) ? false : (seen.add(e), true)));
}

export async function unpackNpm(name: string, version: string | null = null): Promise<PackageManifest> {
  let resolved: ResolvedTarball;
  try {
    resolved = await resolveTarball(name, version);
  } catch (err) {
    return failManifest(name, (err as Error).message);
  }

  let tarball: Buffer;
  try {
    tarball = await downloadTarball(resolved.tarballUrl);
  } catch (err) {
    return failManifest(name, (err as Error).message);
  }

  let members: ExtractedFile[];
  try {
    members = await extractAll(tarball);
  } catch (err) {
    return failManifest(name, `malformed tarball: ${(err as Error).message}`);
  }

  const byPath = new Map<string, ExtractedFile>();
  for (const m of members) byPath.set(m.relPath, m);
  const fileTree = [...byPath.keys()].sort();
  const notableFiles = fileTree.filter((p) => NOTABLE_RE.test(p));

  let pkg: Record<string, any> = {};
  const pkgMember = byPath.get('package.json');
  if (pkgMember) {
    const raw = decodeBody(pkgMember.body, MAX_FILE_BYTES);
    if (raw !== null) {
      try {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) pkg = parsed;
      } catch {
        pkg = {};
      }
    }
  }

  const scripts: Record<string, string> = {};
  const rawScripts = pkg.scripts ?? {};
  if (rawScripts && typeof rawScripts === 'object') {
    for (const [k, v] of Object.entries(rawScripts)) {
      if (typeof v === 'string') scripts[k] = v;
    }
  }

  const installHooks: Record<string, string> = {};
  for (const name of HOOK_NAMES) {
    if (name in scripts) installHooks[name] = scripts[name];
  }

  // For each hook command, attach the source of any local script file it references.
  const hookSources: HookSource[] = [];
  const seenPaths = new Set<string>();
  for (const command of Object.values(installHooks)) {
    SCRIPT_FILE_RE.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = SCRIPT_FILE_RE.exec(command)) !== null) {
      const token = match[0];
      const rel = stripPkgPrefix(token.replace(/^\.\//, ''));
      if (seenPaths.has(rel) || !byPath.has(rel)) continue;
      const member = byPath.get(rel)!;
      const content = decodeBody(member.body, MAX_HOOK_SOURCE_BYTES);
      if (content !== null) {
        hookSources.push({ path: rel, content });
        seenPaths.add(rel);
      }
    }
  }

  const dependencies: Record<string, string> = {};
  const rawDeps = pkg.dependencies ?? {};
  if (rawDeps && typeof rawDeps === 'object') {
    for (const [k, v] of Object.entries(rawDeps)) {
      if (typeof v === 'string') dependencies[k] = v;
    }
  }

  // Keep only the first 50 paths in the tree; downstream tools don't iterate it and the full
  // listing (600+ entries for lodash) bloats every agent's context window.
  return PackageManifestSchema.parse({
    found: true,
    name: (typeof pkg.name === 'string' && pkg.name) || name,
    version: (typeof pkg.version === 'string' && pkg.version) || resolved.resolvedVersion,
    file_tree: fileTree.slice(0, 50),
    scripts,
    dependencies,
    entrypoints: entrypoints(pkg),
    notable_files: notableFiles,
    install_hooks: installHooks,
    hook_sources: hookSources,
  });
}
