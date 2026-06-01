// Mock the global `fetch` used by ingest.ts / osint.ts / npm-metadata.ts.
//
// The Python tests used pytest's monkeypatch against `httpx.get`/`httpx.stream`. The NestJS port
// uses the WHATWG `fetch` everywhere, so we route every test through a single matcher list and
// install a `jest.spyOn(globalThis, 'fetch')` that returns the first matching response.

type ResponseBuilder = () => Response;
export type FetchMatcher = (url: string, init: RequestInit | undefined) => ResponseBuilder | null;

let matchers: FetchMatcher[] = [];
let spy: jest.SpyInstance | null = null;

export function installFetchMock(): void {
  matchers = [];
  spy = jest.spyOn(globalThis, 'fetch').mockImplementation(async (input: any, init?: RequestInit) => {
    const url =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input?.url ?? '';
    for (const m of matchers) {
      const builder = m(url, init);
      if (builder) return builder();
    }
    throw new Error(`unexpected fetch call: ${url}`);
  });
}

export function restoreFetchMock(): void {
  matchers = [];
  spy?.mockRestore();
  spy = null;
}

export function addMatcher(matcher: FetchMatcher): void {
  matchers.push(matcher);
}

export interface MockRegistryOpts {
  name: string;
  version: string;
  blob: Buffer;
}

export function mockNpmRegistry(opts: MockRegistryOpts): void {
  const tarballUrl = `https://registry.npmjs.org/${opts.name}/-/${opts.name}-${opts.version}.tgz`;
  const packument = {
    name: opts.name,
    'dist-tags': { latest: opts.version },
    versions: {
      [opts.version]: {
        name: opts.name,
        version: opts.version,
        dist: { tarball: tarballUrl },
      },
    },
  };
  // Packument GET.
  addMatcher((url) => {
    if (url === `https://registry.npmjs.org/${encodeURIComponent(opts.name).replace(/^%40/, '@')}`) {
      return () =>
        new Response(JSON.stringify(packument), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
    }
    return null;
  });
  // Tarball GET. `new Response()` wants a Uint8Array view, not a Node Buffer.
  addMatcher((url) => {
    if (url === tarballUrl) {
      return () =>
        new Response(new Uint8Array(opts.blob.buffer, opts.blob.byteOffset, opts.blob.byteLength) as unknown as BodyInit, {
          status: 200,
          headers: { 'Content-Type': 'application/octet-stream' },
        });
    }
    return null;
  });
}

export function mockPackumentStatus(name: string, status: number): void {
  addMatcher((url) => {
    if (url === `https://registry.npmjs.org/${encodeURIComponent(name).replace(/^%40/, '@')}`) {
      return () => new Response('', { status });
    }
    return null;
  });
}

export function mockPackumentNetworkError(name: string): void {
  addMatcher((url) => {
    if (url === `https://registry.npmjs.org/${encodeURIComponent(name).replace(/^%40/, '@')}`) {
      return () => {
        throw new TypeError('no network');
      };
    }
    return null;
  });
}
