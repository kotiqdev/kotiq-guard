// Shared presentation of the "Explain with AI" surface (grey acid-wash / варёнка). Stateless —
// each badge owns its request state and passes it in. Used by both the npm and GitHub badges so the
// button, the analyzing card, and the result card look and sit identically.

import { actionBtn, BlockHeader, CopyButton, Spinner } from './primitives';
import { AI, aiButton } from './theme';

export function AiBlock({
    busy,
    text,
    error,
    pro,
    proChip = false,
    agentsLabel,
    disclaimer,
    onExplain,
    onCancel,
}: {
    busy: boolean;
    text?: string;
    error?: string;
    pro?: boolean; // 403 → upsell instead of the button
    proChip?: boolean; // show a PRO tag on the button
    agentsLabel: string; // e.g. "analyst ⇄ critic" / "security ⇄ critic"
    disclaimer: string;
    onExplain: () => void;
    onCancel: () => void;
}) {
    if (busy) {
        return (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, padding: '10px 12px', background: AI.card, border: AI.cardBorder, borderLeft: `3px solid ${AI.accent}`, borderRadius: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
                    <Spinner size={16} color={AI.accent} />
                    <div>
                        <div style={{ fontSize: 12.5, fontWeight: 700, color: AI.accentText }}>Analyzing with Kotiq's agents…</div>
                        <div style={{ fontSize: 10.5, color: '#8a95a1', marginTop: 1 }}>{agentsLabel} · this can take a moment</div>
                    </div>
                </div>
                <button onClick={(e) => { e.stopPropagation(); onCancel(); }} title="Stop the agents" style={{ ...actionBtn, flexShrink: 0 }}>
                    ✕ Cancel
                </button>
            </div>
        );
    }

    if (pro) {
        return (
            <div style={{ fontSize: 12, color: '#57606a' }}>
                AI analysis is a Pro feature.{' '}
                <a href="https://kotiq.dev" target="_blank" rel="noreferrer" style={{ color: '#0969da' }}>Request Pro access</a>.
            </div>
        );
    }

    return (
        <>
            <button onClick={onExplain} style={aiButton}>
                ✨ {text ? 'Re-explain with AI' : 'Explain with AI'}
                {proChip && <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.4px', color: '#fff', background: AI.accent, borderRadius: 999, padding: '1px 6px' }}>PRO</span>}
            </button>
            {text && (
                <div style={{ marginTop: 10, background: AI.card, border: AI.cardBorder, borderLeft: `3px solid ${AI.accent}`, borderRadius: 8, padding: '10px 12px' }}>
                    <BlockHeader
                        title={
                            <span style={{ fontSize: 12, fontWeight: 700, color: AI.accentText, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                                ✨ AI analysis
                                <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: '.3px', textTransform: 'uppercase', color: AI.accentText, background: '#e3e9ef', borderRadius: 999, padding: '1px 6px' }}>agents</span>
                            </span>
                        }
                        actions={<CopyButton text={text} />}
                    />
                    <div style={{ fontSize: 12.5, lineHeight: 1.5, whiteSpace: 'pre-wrap', color: '#2b333c' }}>{text}</div>
                    <div style={{ fontSize: 10.5, color: '#8a95a1', marginTop: 8 }}>{disclaimer}</div>
                </div>
            )}
            {error && <div style={{ fontSize: 12, color: '#bc4c00', marginTop: 8 }}>{error}</div>}
        </>
    );
}
