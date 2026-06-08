// Draggable, collapsible floating shell shared by every Kotiq badge (npm + GitHub + sign-in).
// Replaces the old fixed top-right anchor (which overlapped the sites' own menus).
//   • drag by the top "Kotiq" handle to move it anywhere
//   • collapse to a compact pill (▸/▾)
//   • position + collapsed state persist in chrome.storage.local, so F5 does NOT reset it
// Position is remembered PER SITE (github vs npm) — their layouts differ, so a spot that's clear on
// npm may cover GitHub's header icons. Each host keeps its own saved position + collapsed state.

import { useEffect, useRef, useState } from 'react';

import { Spinner } from './primitives';

const SITE = location.hostname.includes('github.com') ? 'github' : 'npm';
const KEY = `kotiq-dock-v2-${SITE}`;

// Horizontal anchor: when docked on the right half we pin the RIGHT edge (so expanding grows leftward,
// never off-screen); on the left half we pin the LEFT edge. `top` is always the vertical offset.
type Pos = { top: number; left?: number; right?: number };
type DockState = { pos: Pos | null; collapsed: boolean };

// `status` lets the COLLAPSED handle act as a mini indicator: a spinner while work is running, then a
// verdict-coloured dot when it's done — so progress/result is visible without expanding.
export function Dock({ children, status }: { children: React.ReactNode; status?: { busy?: boolean; color?: string } }) {
    const [state, setState] = useState<DockState>({ pos: null, collapsed: false });
    const [ready, setReady] = useState(false);
    const [dark, setDark] = useState(false);
    const ref = useRef<HTMLDivElement>(null);
    const drag = useRef<{ dx: number; dy: number } | null>(null);

    useEffect(() => {
        void chrome.storage.local.get(KEY).then((o) => {
            const s = o?.[KEY] as DockState | undefined;
            if (s) setState({ pos: s.pos ?? null, collapsed: !!s.collapsed });
            setReady(true);
        });
    }, []);

    // Adapt the handle to the user's light/dark scheme so it never blends into the page.
    useEffect(() => {
        const mq = window.matchMedia('(prefers-color-scheme: dark)');
        const sync = (): void => setDark(mq.matches);
        sync();
        mq.addEventListener('change', sync);
        return () => mq.removeEventListener('change', sync);
    }, []);

    function save(next: DockState): void {
        setState(next);
        void chrome.storage.local.set({ [KEY]: next });
    }

    function onPointerDown(e: React.PointerEvent<HTMLDivElement>): void {
        const r = ref.current?.getBoundingClientRect();
        if (!r) return;
        drag.current = { dx: e.clientX - r.left, dy: e.clientY - r.top };
        e.currentTarget.setPointerCapture(e.pointerId);
        e.preventDefault();
    }
    function onPointerMove(e: React.PointerEvent<HTMLDivElement>): void {
        if (!drag.current) return;
        const w = ref.current?.offsetWidth ?? 0;
        const h = ref.current?.offsetHeight ?? 0;
        const left = Math.min(Math.max(0, e.clientX - drag.current.dx), Math.max(0, window.innerWidth - w));
        const top = Math.min(Math.max(0, e.clientY - drag.current.dy), Math.max(0, window.innerHeight - h));
        setState((s) => ({ ...s, pos: { left, top } }));
    }
    function onPointerUp(): void {
        if (!drag.current) return;
        drag.current = null;
        const r = ref.current?.getBoundingClientRect();
        setState((s) => {
            const pos: Pos = r
                ? r.left + r.width / 2 > window.innerWidth / 2
                    ? { top: r.top, right: Math.max(0, window.innerWidth - r.right) } // snap to right edge
                    : { top: r.top, left: Math.max(0, r.left) } //                      snap to left edge
                : (s.pos ?? { top: 12 });
            const next = { ...s, pos };
            void chrome.storage.local.set({ [KEY]: next });
            return next;
        });
    }

    if (!ready) return null;

    const posStyle: React.CSSProperties = state.pos
        ? { top: state.pos.top, ...(state.pos.right != null ? { right: state.pos.right } : { left: state.pos.left ?? 0 }) }
        : { top: 12, right: 12 };

    // Theme-aware handle: dark page → light bar, light page → dark bar. Border + shadow keep it
    // delineated on any background (so it never "blends in").
    const bar = dark
        ? { bg: 'rgba(241,245,249,.96)', fg: '#0f172a', border: '1px solid rgba(15,23,42,.18)' }
        : { bg: 'rgba(17,24,39,.94)', fg: '#ffffff', border: '1px solid rgba(255,255,255,.22)' };

    return (
        <div
            ref={ref}
            style={{ position: 'fixed', zIndex: 2147483647, font: '13px system-ui, sans-serif', ...posStyle }}
        >
            <div
                onPointerDown={onPointerDown}
                onPointerMove={onPointerMove}
                onPointerUp={onPointerUp}
                style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    padding: '4px 8px',
                    cursor: 'grab',
                    touchAction: 'none',
                    userSelect: 'none',
                    background: bar.bg,
                    color: bar.fg,
                    border: bar.border,
                    boxShadow: '0 2px 12px rgba(0,0,0,.28)',
                    borderRadius: state.collapsed ? 999 : '8px 8px 0 0',
                }}
            >
                <span style={{ fontSize: 12 }}>🐾</span>
                {!state.collapsed && (
                    <span style={{ flex: 1, fontSize: 11, opacity: 0.7, letterSpacing: 0.3, paddingRight: 8 }}>Kotiq</span>
                )}
                {state.collapsed && status?.busy && (
                    <span title="Kotiq is analyzing…" style={{ display: 'inline-flex', lineHeight: 0 }}>
                        <Spinner size={11} color={bar.fg} />
                    </span>
                )}
                {state.collapsed && !status?.busy && status?.color && (
                    <span
                        style={{
                            width: 9,
                            height: 9,
                            borderRadius: 999,
                            background: status.color,
                            boxShadow: `0 0 0 1.5px ${dark ? 'rgba(0,0,0,.3)' : 'rgba(255,255,255,.6)'}`,
                        }}
                    />
                )}
                <span
                    onPointerDown={(e) => e.stopPropagation()}
                    onClick={(e) => {
                        e.stopPropagation();
                        save({ ...state, collapsed: !state.collapsed });
                    }}
                    title={state.collapsed ? 'Expand' : 'Collapse'}
                    style={{
                        cursor: 'pointer',
                        fontSize: 16,
                        fontWeight: 800,
                        lineHeight: 1,
                        padding: '0 6px',
                        marginLeft: 2,
                        letterSpacing: '-1px',
                    }}
                >
                    {state.collapsed ? '«' : '»'}
                </span>
            </div>
            {/* Hide (not unmount) when collapsed → preserves badge state + any in-flight AI request. */}
            <div style={{ display: state.collapsed ? 'none' : 'block' }}>{children}</div>
        </div>
    );
}
