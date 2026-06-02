// Static configuration for Kotiq. Mirrors kotiq/config.py.

// Gemini model used by the agent layer (Google AI Studio).
export const MODEL = 'gemini-2.5-flash';

// Public npm registry base URL. Read-only / passive access only.
export const NPM_REGISTRY = 'https://registry.npmjs.org';

// Network timeout (milliseconds) for registry / OSINT calls (Python used 10.0s).
export const HTTP_TIMEOUT_MS = 10_000;

// --- Safe-ingestion extraction caps -------------------------------------------------------------
// Defenses against decompression bombs / oversized archives. Tarballs are unpacked in memory and
// only what we need is read (package.json + install-hook sources); the package is never written
// to disk.
export const MAX_TARBALL_BYTES = 25 * 1024 * 1024; // refuse to download a larger (compressed) tarball
export const MAX_FILES = 5_000; // cap on members enumerated from the archive
export const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip reading any single file larger than this
export const MAX_HOOK_SOURCE_BYTES = 64 * 1024; // cap on hook-source text attached to the manifest
