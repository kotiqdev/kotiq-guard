// Pull plain text out of an LLM reply. Content is a string, OR — when reasoning is on (e.g.
// gemini-2.5 with a thinking budget) — an array of parts like [{type:'thinking',...},{type:'text',
// text:'...'}]. We keep only the text so downstream JSON parsing sees the real answer, not the
// "[object Object]" you get from String()-ing an array of objects. Non-text parts (thoughts) drop.
export function contentToText(content: unknown): string {
    if (typeof content === 'string') return content;
    if (Array.isArray(content)) {
        return content
            .map((p) =>
                typeof p === 'string'
                    ? p
                    : typeof (p as { text?: unknown }).text === 'string'
                      ? (p as { text: string }).text
                      : '',
            )
            .join('');
    }
    return '';
}
