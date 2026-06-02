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
            'font:600 13px system-ui,sans-serif;color:#fff;box-shadow:0 2px 8px rgba(0,0,0,.2);max-width:320px;';
        document.body.appendChild(el);
    }
    el.textContent = `🐱 Kotiq: ${text}`;
    el.style.background = color;
    if (tooltip) el.title = tooltip;
}

async function run() {
    const pkg = packageNameFromUrl();
    if (!pkg) return;

    renderBadge('checking…', COLORS.checking);
    try {
        const res = await fetch(`${SERVER}/scan?pkg=${encodeURIComponent(pkg)}&from=${encodeURIComponent(location.href)}`);
        const data = await res.json();
        renderBadge(data.verdict, COLORS[data.verdict] || COLORS.NEEDS_REVIEW, data.explanation || data.summary);
    } catch (e) {
        renderBadge('error — is the server running?', COLORS.error, String(e));
    }
}

run();
