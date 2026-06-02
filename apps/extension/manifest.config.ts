import { defineManifest } from '@crxjs/vite-plugin';

export default defineManifest({
    manifest_version: 3,
    name: 'Kotiq Guard',
    version: '0.1.0',
    description: 'Is this npm package safe to install? Kotiq checks it before you run it.',
    host_permissions: ['http://localhost:8080/*'],
    content_scripts: [
        {
            matches: ['https://www.npmjs.com/package/*'],
            js: ['src/content/main.tsx'],
        },
    ],
});
