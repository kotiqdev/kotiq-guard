// Kotiq Guard — content script. Injects a verdict badge on npm package pages.
// Minimal no-build version; we convert to Vite + React + TS next.

const SERVER = 'http://localhost:8080';

const COLORS = {
    SAFE: '#1a7f37',
    SUSPICIOUS: '#bf8700',
    MALICIOUS: '#cf222e',
    NEEDS_REVIEW: '#6e7781',
    checking: '#6e7781',
    error: '#cf222e',
};

// /package/<name> or /package/@scope/name (optionally followed by /v/<version>)
function packageNameFromUrl() {
    const m = location.pathname.match(/^\/package\/((?:@[^/]+\/)?[^/]+)/);
    return m ? decodeURIComponent(m[1]) : null;
}

function renderBadge(text, color, tooltip) {
    let el = document.getElementById('kotiq-badge');
    if (!el) {
        el = document.createElement('div');
        el.id = 'kotiq-badge';
        el.style.cssText =
            'position:fixed;top:12px;right:12px;z-index:99999;padding:8px 12px;border-radius:8px;' +
            'font:600 13px system-ui,sans-serif;color:#fff;box-shadow:0 2px 8px rgba(0,0,0,.2);';
        document.body.appendChild(el);
    }
    el.textContent = `🐱 Kotiq: ${text}`;
    el.style.background = color;
    if (tooltip) el.title = tooltip;
    return el;
}

function closeMenu() {
    document.getElementById('kotiq-menu')?.remove();
    document.removeEventListener('click', onOutsideClick);
}

function onOutsideClick(e) {
    const menu = document.getElementById('kotiq-menu');
    const badge = document.getElementById('kotiq-badge');
    if (menu && !menu.contains(e.target) && e.target !== badge) closeMenu();
}

// Dropdown under the badge: actions + a panel where results appear.
function openMenu(pkg) {
    closeMenu();
    const menu = document.createElement('div');
    menu.id = 'kotiq-menu';
    menu.style.cssText =
        'position:fixed;top:48px;right:12px;z-index:99999;width:320px;background:#fff;color:#24292f;' +
        'border:1px solid #d0d7de;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.18);' +
        'font:13px system-ui,sans-serif;overflow:hidden;';

    const explainItem = document.createElement('div');
    explainItem.textContent = '🤖 Explain with AI';
    explainItem.style.cssText = 'padding:10px 12px;cursor:pointer;border-bottom:1px solid #eaeef2;';
    explainItem.onmouseenter = () => (explainItem.style.background = '#f6f8fa');
    explainItem.onmouseleave = () => (explainItem.style.background = '#fff');

    const panel = document.createElement('div');
    panel.style.cssText = 'padding:10px 12px;color:#57606a;line-height:1.45;white-space:pre-wrap;';
    panel.textContent = 'Pick an action above, or click outside to close.';

    explainItem.onclick = async () => {
        panel.textContent = 'Thinking…';
        try {
            const full = await fetch(
                `${SERVER}/scan?pkg=${encodeURIComponent(pkg)}&from=${encodeURIComponent(location.href)}`,
            ).then((r) => r.json());
            panel.textContent = full.explanation || full.summary || '(no explanation)';
        } catch {
            panel.textContent = 'Could not reach the server.';
        }
    };

    menu.appendChild(explainItem);
    menu.appendChild(panel);
    document.body.appendChild(menu);
    // Defer so this same click doesn't immediately trigger the outside-click handler.
    setTimeout(() => document.addEventListener('click', onOutsideClick), 0);
}

async function run() {
    const pkg = packageNameFromUrl();
    if (!pkg) return;

    const from = encodeURIComponent(location.href);
    renderBadge('checking…', COLORS.checking);
    try {
        // Fast path: deterministic verdict only (no LLM) — instant badge.
        const res = await fetch(`${SERVER}/scan?pkg=${encodeURIComponent(pkg)}&explain=false&from=${from}`);
        const data = await res.json();
        const el = renderBadge(data.verdict, COLORS[data.verdict] || COLORS.NEEDS_REVIEW, data.summary || '');
        el.style.cursor = 'pointer';
        el.onclick = (e) => {
            e.stopPropagation();
            if (document.getElementById('kotiq-menu')) closeMenu();
            else openMenu(pkg);
        };
    } catch (e) {
        renderBadge('error — is the server running?', COLORS.error, String(e));
    }
}

run();
