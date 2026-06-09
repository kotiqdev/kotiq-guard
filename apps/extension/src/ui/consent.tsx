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

// On-page gate: shown by the npm/GitHub badges until the user acknowledges. The badge does NOT confirm
// consent itself — it just opens the extension popup (where the user reads the notice + taps "Got it").
// Once acknowledged there, the shared flag flips and the badge unlocks (live, via useAcked). Opening
// the popup needs the privileged context, so we ask the background; if that's unavailable on this
// Chrome version, the dropdown tells the user to click the toolbar icon instead.
export function ConsentGate() {
    const [hint, setHint] = useState(false);
    function openExtension(): void {
        void chrome.runtime.sendMessage({ type: 'openPopup' }).catch(() => undefined);
        setHint(true);
    }
    return (
        <Dock>
            <div onClick={openExtension} style={badgePill('#6e7781')} title="Open Kotiq to get started">
                🐾 Kotiq — tap to set up
            </div>
            {hint && (
                <div style={{ ...dropdownPanel, width: 270, overflow: 'hidden' }}>
                    <div style={{ ...panel, color: '#57606a', lineHeight: 1.5 }}>
                        Open the <b>Kotiq</b> icon in your browser toolbar (top-right ↗) and tap{' '}
                        <b>Got it</b> to read the notice and enable scanning.
                    </div>
                </div>
            )}
        </Dock>
    );
}
