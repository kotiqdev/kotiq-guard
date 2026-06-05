import { createRoot } from 'react-dom/client';

import { RepoBadge } from './RepoBadge';

// Mount inside a shadow root so GitHub's page styles can't leak into ours.
const host = document.createElement('div');
host.id = 'kotiq-repo-root';
document.body.appendChild(host);

const shadow = host.attachShadow({ mode: 'open' });
const mount = document.createElement('div');
shadow.appendChild(mount);

createRoot(mount).render(<RepoBadge />);
