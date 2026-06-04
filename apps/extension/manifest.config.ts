import { defineManifest } from '@crxjs/vite-plugin';

export default defineManifest({
    manifest_version: 3,
    name: 'Kotiq Guard',
    version: '0.1.0',
    description: 'Is this npm package safe to install? Kotiq checks it before you run it.',
    // Pins the extension ID deterministically (public key). Result:
    //   id ggejgokpkdifpjpgfidcpllfmlhhkeii → redirect https://ggejgokpkdifpjpgfidcpllfmlhhkeii.chromiumapp.org/
    // Never changes across reinstalls/machines, so the OAuth redirect URI stays valid.
    key: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxFFxIl8kYCu1XQ1Kb+TujSzUCyUBYGMr2J8k6ZATsnKS4eE3Cp/io2/F+S44q/lOr/PVZ+PBerdhWhn3t8fzwjmShbqpL2fh9v9Q/DnrFdxTmvr3XNjfUxWlcPbHeV7zGfGr8PE9qRiCo+A/zwjHa6T5bJAyes0p5dcg0kVVJZvthpQHOS2u+pZqb1tjliL0bLDPS6xg6zZ+Qjls6vFNiI5FWRPNV225qKjsbMvSJ4RTzTutVwzT4g6546JUJaUvxdoRH5WekRh7to9JoIPXnvyLlootPqlgxvvzlfEm8mS4AXma9dDRNA0K0J9SPPyHCBzMdoODWR/nUyehbpmGQQIDAQAB',
    // identity → Google sign-in (launchWebAuthFlow); storage → cache the session token.
    permissions: ['identity', 'storage'],
    host_permissions: ['http://localhost:8080/*'],
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
    ],
});
