// Chrome built-in AI (Gemini Nano) via the Prompt API. Runs in the background service worker, where
// the extension has access to the on-device model. Everything degrades to null/'unavailable' when
// the model isn't present, so callers can hide the AI button instead of erroring.

export type NanoStatus = 'available' | 'downloadable' | 'downloading' | 'unavailable';

interface DownloadMonitor {
    addEventListener(type: 'downloadprogress', cb: (e: { loaded: number }) => void): void;
}
interface LanguageModelSession {
    prompt(input: string): Promise<string>;
    destroy(): void;
}
interface LanguageModelApi {
    availability(): Promise<NanoStatus>;
    create(opts?: {
        initialPrompts?: { role: 'system' | 'user'; content: string }[];
        monitor?: (m: DownloadMonitor) => void;
    }): Promise<LanguageModelSession>;
}

// Read the global without a `declare const` (which would throw if absent). undefined → not supported.
const LM = (globalThis as { LanguageModel?: LanguageModelApi }).LanguageModel;

export async function nanoStatus(): Promise<NanoStatus> {
    if (!LM) return 'unavailable';
    try {
        return await LM.availability();
    } catch {
        return 'unavailable';
    }
}

// One-shot explanation. Returns null when Nano can't run → caller hides the button / shows nothing.
// One-shot explanation. Returns null when Nano can't run. On first use with status 'downloadable',
// create() triggers the (one-time) model download and resolves once it's ready — we log progress.
export async function explainWithNano(
    system: string,
    user: string,
    onProgress?: (pct: number) => void,
): Promise<string | null> {
    if (!LM) return null;
    if ((await LM.availability()) === 'unavailable') return null;
    const session = await LM.create({
        initialPrompts: [{ role: 'system', content: system }],
        monitor: (m) =>
            m.addEventListener('downloadprogress', (e) => {
                const pct = Math.round(e.loaded * 100);
                console.info('[kotiq bg] Nano download', `${pct}%`);
                onProgress?.(pct);
            }),
    });
    try {
        return (await session.prompt(user)).trim();
    } finally {
        session.destroy();
    }
}
