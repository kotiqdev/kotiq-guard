// Pro "Explain with AI" block for the repo badge. Owns the request state + the analyst⇄critic call
// and cancel; the presentation is the shared <AiBlock>. Shown only when worst != SAFE.

import { useEffect, useState } from 'react';

import { AiBlock } from '../ui/AiBlock';
import { panel } from '../ui/theme';

type AiState = { loading: boolean; text?: string; error?: string; pro?: boolean } | null;

export function AiAnalysis({ owner, repo, onBusy }: { owner: string; repo: string; onBusy?: (busy: boolean) => void }) {
    const [ai, setAi] = useState<AiState>(null);

    // Report "AI thinking" up to the badge so the collapsed Dock can show a spinner.
    useEffect(() => {
        onBusy?.(!!ai?.loading);
    }, [ai, onBusy]);
    // Reset the badge's busy flag if this block unmounts (e.g. dropdown closed) mid-request.
    useEffect(() => () => onBusy?.(false), [onBusy]);

    async function runExplain() {
        setAi({ loading: true });
        try {
            const r = (await chrome.runtime.sendMessage({ type: 'repoExplain', owner, repo })) as {
                ok?: boolean;
                status?: number;
                result?: { explanation?: string };
                aborted?: boolean;
                error?: string;
            };
            if (r?.aborted) return; // user stopped the agents → cancelExplain already reset the UI
            if (r?.status === 403) return setAi({ loading: false, pro: true });
            if (r?.ok && r.result?.explanation) return setAi({ loading: false, text: r.result.explanation });
            setAi({ loading: false, error: r?.error ?? 'AI explanation unavailable — is the model running?' });
        } catch (e) {
            setAi({ loading: false, error: (e as Error).message });
        }
    }

    // Stop the in-flight agents (aborts the backend request → server cancels the LLM graph).
    function cancelExplain() {
        void chrome.runtime.sendMessage({ type: 'cancel' });
        setAi(null); // back to the "Explain with AI" button
    }

    return (
        <div style={panel}>
            <AiBlock
                busy={!!ai?.loading}
                text={ai?.text}
                error={ai?.error}
                pro={ai?.pro}
                proChip
                agentsLabel="analyst ⇄ critic"
                disclaimer="AI summary, grounded in the findings below — double-check critical actions."
                onExplain={runExplain}
                onCancel={cancelExplain}
            />
        </div>
    );
}
