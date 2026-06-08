// Shared first-run consent, used by BOTH the popup and the on-page badges. The user must acknowledge
// once before Kotiq scans anything (sets expectations + no backend call pre-consent). The flag lives
// in chrome.storage.local under one key, and `useAcked` live-syncs — acknowledge in either place and
// both update. The badge shows `ConsentGate` until acknowledged; scanning is gated on `acked`.

import { useEffect, useState } from 'react';

import { Dock } from './Dock';
import { badgePill, dropdownPanel, panel } from './theme';

export const ACK_KEY = 'kotiqAcked';

export function useAcked(): boolean | undefined {
    const [acked, setAcked] = useState<boolean | undefined>(undefined); // undefined = reading storage
    useEffect(() => {
        void chrome.storage.local.get(ACK_KEY).then((o) => setAcked(!!o[ACK_KEY]));
        const onChange = (changes: Record<string, chrome.storage.StorageChange>, area: string): void => {
            if (area === 'local' && ACK_KEY in changes) setAcked(!!changes[ACK_KEY].newValue);
        };
        chrome.storage.onChanged.addListener(onChange);
        return () => chrome.storage.onChanged.removeListener(onChange);
    }, []);
    return acked;
}

export function ackConsent(): void {
    void chrome.storage.local.set({ [ACK_KEY]: true });
}

// On-page gate: shown by the npm/GitHub badges until the user acknowledges. Open by default so the
// disclaimer is visible; "Got it" sets the shared flag → the badge re-renders and starts scanning.
export function ConsentGate() {
    const [open, setOpen] = useState(true);
    return (
        <Dock>
            <div onClick={() => setOpen((o) => !o)} style={badgePill('#6e7781')}>
                🐾 Kotiq — read before scanning
            </div>
            {open && (
                <div style={{ ...dropdownPanel, width: 300, overflow: 'hidden' }}>
                    <div style={{ ...panel, color: '#57606a', lineHeight: 1.5 }}>
                        <b>A signal, not a guarantee.</b> Attackers keep evolving — a “safe” result can
                        still miss something brand-new. For anything untrusted or suspicious, open or
                        install it in an <b>isolated environment (a VM, container or sandbox)</b> — not on
                        your main machine. You stay responsible for what you run.
                        <div style={{ marginTop: 8, fontSize: 11, color: '#8a929b' }}>
                            Currently focused on the Node.js ecosystem. Sign-in uses your Google profile;
                            Kotiq sends the package/repo you check to its backend.{' '}
                            <a href="https://kotiq.dev/privacy" target="_blank" rel="noreferrer" style={{ color: '#57606a' }}>
                                Privacy
                            </a>
                            .
                        </div>
                    </div>
                    <div style={{ padding: '10px 12px' }}>
                        <button
                            onClick={ackConsent}
                            style={{
                                width: '100%',
                                padding: '8px 12px',
                                border: 'none',
                                borderRadius: 8,
                                background: '#1a7f37',
                                color: '#fff',
                                fontWeight: 700,
                                cursor: 'pointer',
                            }}
                        >
                            Got it — start scanning
                        </button>
                    </div>
                </div>
            )}
        </Dock>
    );
}
