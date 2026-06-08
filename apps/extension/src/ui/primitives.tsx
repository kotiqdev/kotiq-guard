// Small reusable UI primitives shared across Kotiq badges. No app logic here.

import { useState, type ReactNode } from 'react';

export const actionBtn = {
    fontSize: 11,
    padding: '2px 7px',
    border: '1px solid #d0d7de',
    borderRadius: 6,
    background: '#fff',
    color: '#57606a',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
    lineHeight: 1.6,
} as const;

// Copy `text` to the clipboard with a brief "Copied" confirmation.
export function CopyButton({ text }: { text: string }) {
    const [done, setDone] = useState(false);
    return (
        <button
            title="Copy to clipboard"
            onClick={(e) => {
                e.stopPropagation();
                void navigator.clipboard
                    .writeText(text)
                    .then(() => {
                        setDone(true);
                        setTimeout(() => setDone(false), 1500);
                    })
                    .catch(() => {});
            }}
            style={actionBtn}
        >
            {done ? '✓ Copied' : '⧉ Copy'}
        </button>
    );
}

// Block header: title on the left, a row of action buttons on the right. The actions row is the
// place to add more per-block commands later (Open in sandbox, Report, Copy IOCs, …).
export function BlockHeader({ title, actions }: { title: ReactNode; actions?: ReactNode }) {
    return (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
            <div style={{ minWidth: 0 }}>{title}</div>
            <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>{actions}</div>
        </div>
    );
}

// Smooth rotating spinner (no opacity blinking — easier on the eyes). Self-contained: ships its own
// keyframes so it works in any render path (content scripts have no shared stylesheet).
export function Spinner({ size = 14, color = '#57606a' }: { size?: number; color?: string }) {
    return (
        <>
            <style>{'@keyframes kotiqSpin{to{transform:rotate(360deg)}}'}</style>
            <span
                style={{
                    display: 'inline-block',
                    width: size,
                    height: size,
                    border: `2px solid ${color}40`,
                    borderTopColor: color,
                    borderRadius: '50%',
                    animation: 'kotiqSpin .7s linear infinite',
                    flexShrink: 0,
                }}
            />
        </>
    );
}
