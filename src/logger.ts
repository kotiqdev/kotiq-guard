// Lightweight debug logger. Enable with KOTIQ_DEBUG=1.
// Writes to stderr so it never pollutes the JSON verdict printed on stdout.
const enabled = process.env.KOTIQ_DEBUG === '1';

export function debug(...args: unknown[]): void {
    if (enabled) console.error(`[kotiq ${new Date().toISOString()}]`, ...args);
}
