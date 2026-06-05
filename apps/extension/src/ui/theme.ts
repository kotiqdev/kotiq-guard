// Shared visual tokens for Kotiq badges (GitHub repo badge, npm package badge).

export const VERDICT_COLOR: Record<string, string> = {
    SAFE: '#1a7f37',
    NEEDS_REVIEW: '#6e7781',
    SUSPICIOUS: '#bf8700',
    MALICIOUS: '#cf222e',
};

export const SEV_COLOR: Record<string, string> = {
    INFO: '#6e7781',
    LOW: '#6e7781',
    MEDIUM: '#bf8700',
    HIGH: '#bc4c00',
    CRITICAL: '#cf222e',
};

// One section inside a dropdown panel.
export const panel = { padding: '10px 12px', borderBottom: '1px solid #eaeef2' } as const;

// The white dropdown container under a badge pill (callers add `width` + overflow handling).
export const dropdownPanel = { marginTop: 6, background: '#fff', color: '#24292f', border: '1px solid #d0d7de', borderRadius: 8, boxShadow: '0 4px 16px rgba(0,0,0,.18)' } as const;

// Small uppercase section caption.
export const sectionLabel = { fontSize: 11, textTransform: 'uppercase', letterSpacing: '.4px', color: '#8a929b', marginBottom: 4 } as const;

// Fixed top-right anchor shared by every badge.
export const badgeShell = { position: 'fixed', top: 12, right: 12, zIndex: 99999, font: '13px system-ui, sans-serif' } as const;

// The coloured verdict pill.
export const badgePill = (bg: string, cursor: 'pointer' | 'default' = 'pointer') =>
    ({ padding: '8px 12px', borderRadius: 8, color: '#fff', fontWeight: 600, background: bg, cursor, boxShadow: '0 2px 8px rgba(0,0,0,.2)' }) as const;

// "Grey acid-wash" (варёнка) AI surface — the Pro/agent layer, shared by both badges, visually
// distinct from the deterministic verdict blocks.
export const AI = {
    accent: '#5b7083',
    accentText: '#46586a',
    card: 'linear-gradient(135deg, #eef1f4 0%, #f5f7f9 55%, #e9edf1 100%)',
    cardBorder: '1px solid #d6dde4',
} as const;

export const aiButton = {
    width: '100%',
    padding: '9px 12px',
    border: '1px solid #cdd6df',
    borderRadius: 8,
    background: 'linear-gradient(135deg, #eef1f4 0%, #f4f6f8 55%, #e7ecf0 100%)',
    color: AI.accentText,
    fontWeight: 700,
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
} as const;
