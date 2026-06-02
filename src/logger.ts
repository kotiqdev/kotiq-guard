// Lightweight debug logger. Enable with KOTIQ_DEBUG=1.
// Writes to stderr so it never pollutes the JSON verdict printed on stdout.
import { env } from './env';

export function debug(...args: unknown[]): void {
    if (env.debug) console.error(`[kotiq ${new Date().toISOString()}]`, ...args);
}
