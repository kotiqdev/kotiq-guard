import { defineManifest } from '@crxjs/vite-plugin';
import { loadEnv } from 'vite';

// Manifest is built per Vite mode so the backend host permission matches THIS build's backend exactly
// — minimal permissions (smoother Web Store review), and each build can only reach its own backend:
//   npm run dev        → mode development → .env        → http://localhost:8080/*
//   npm run build:dev  → mode dev         → .env.dev    → the dev Cloud Run URL
//   npm run build:prod → mode prod        → .env.prod   → https://kotiq.dev/api/*
// Pins the unpacked extension ID deterministically. ID = ggejgokpkdifpjpgfidcpllfmlhhkeii →
// redirect https://ggejgokpkdifpjpgfidcpllfmlhhkeii.chromiumapp.org/. Used for local/dev only; the
// Web Store assigns (and forever keeps) prod's own ID, so the prod build ships WITHOUT a key.
const DEV_KEY =
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxFFxIl8kYCu1XQ1Kb+TujSzUCyUBYGMr2J8k6ZATsnKS4eE3Cp/io2/F+S44q/lOr/PVZ+PBerdhWhn3t8fzwjmShbqpL2fh9v9Q/DnrFdxTmvr3XNjfUxWlcPbHeV7zGfGr8PE9qRiCo+A/zwjHa6T5bJAyes0p5dcg0kVVJZvthpQHOS2u+pZqb1tjliL0bLDPS6xg6zZ+Qjls6vFNiI5FWRPNV225qKjsbMvSJ4RTzTutVwzT4g6546JUJaUvxdoRH5WekRh7to9JoIPXnvyLlootPqlgxvvzlfEm8mS4AXma9dDRNA0K0J9SPPyHCBzMdoODWR/nUyehbpmGQQIDAQAB';

export default defineManifest(({ mode }) => {
    const env = loadEnv(mode, process.cwd(), 'VITE_');
    const apiBase = env.VITE_API_BASE || 'http://localhost:8080';
    const apiHost = `${apiBase.replace(/\/+$/, '')}/*`; // e.g. https://kotiq.dev/api → https://kotiq.dev/api/*
    const isStoreBuild = mode === 'prod'; // build:prod → the package uploaded to the Web Store

    return {
        manifest_version: 3,
        name: 'Kotiq Guard',
        version: '0.1.0',
        description: 'Is this npm package safe to install? Kotiq checks it before you run it.',
        // Keep the key for unpacked (local/dev) so the ID — and its OAuth redirect — stay stable.
        // Omit it for the store build: the Web Store owns prod's ID.
        ...(isStoreBuild ? {} : { key: DEV_KEY }),
        // identity → Google sign-in (launchWebAuthFlow); storage → cache the session token.
        permissions: ['identity', 'storage'],
        // backend (this build's API base) + npm registry (Lite reads install-hook commands).
        host_permissions: [apiHost, 'https://registry.npmjs.org/*'],
        // Privileged context that runs the sign-in flow on behalf of the content script.
        background: {
            service_worker: 'src/background.ts',
            type: 'module',
        },
        // The toolbar icon opens this popup (sign-in + tier).
        action: {
            default_title: 'Kotiq Guard',
            default_popup: 'src/popup/index.html',
        },
        content_scripts: [
            {
                matches: ['https://www.npmjs.com/package/*'],
                js: ['src/content/main.tsx'],
            },
            {
                matches: ['https://github.com/*'],
                js: ['src/github/main.tsx'],
            },
        ],
    };
});
