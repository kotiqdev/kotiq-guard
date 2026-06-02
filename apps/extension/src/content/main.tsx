import { createRoot } from 'react-dom/client';

import { Badge } from './Badge';

// Mount the widget inside a shadow root so npm's page styles can't leak into ours.
const host = document.createElement('div');
host.id = 'kotiq-root';
document.body.appendChild(host);

const shadow = host.attachShadow({ mode: 'open' });
const mount = document.createElement('div');
shadow.appendChild(mount);

createRoot(mount).render(<Badge />);
