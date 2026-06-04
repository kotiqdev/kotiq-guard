// Web3 / crypto-theft signature detectors — a browser port of src/core/static-analysis/web3-signatures.ts.
// Pure regex/heuristics, no I/O. Lite runs these over install-hook COMMANDS from the npm registry.
// Keep roughly in sync with the backend catalog. (Lite sees commands only, not the script source.)

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface SignatureHit {
    name: string;
    label: string;
    severity: Severity;
    snippet: string;
}

interface Signature {
    name: string;
    label: string;
    severity: Severity;
    pattern: RegExp;
    requiresHint?: boolean;
}

const HINTS_RE = /(mnemonic|seed[\s_-]?phrase|private[\s_-]?key|wallet|keystore|account[\s_-]?recovery)/i;
const CLIPBOARD_LIB_RE = /clipboardy|clipboard-event|clipboard\.write|require\(\s*['"]clipboardy['"]\)/;
const ETH_ADDR_RE = /0x[a-fA-F0-9]{40}\b/;
const BTC_ADDR_RE = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/;
const SOL_ADDR_RE = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/;

const SIGNATURES: readonly Signature[] = [
    { name: 'curl_pipe_sh', label: 'remote shell pipe (curl|sh / wget|sh)', severity: 'CRITICAL', pattern: /\b(?:curl|wget)\b[^\n;]{0,200}?\|\s*(?:sh|bash)\b/g },
    { name: 'node_dash_e', label: 'node -e inline execution', severity: 'HIGH', pattern: /\bnode\s+-e\b/g },
    { name: 'eval_call', label: 'eval() of dynamic source', severity: 'HIGH', pattern: /\beval\s*\(/g },
    { name: 'function_constructor', label: 'Function() constructor (eval substitute)', severity: 'HIGH', pattern: /\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"]/g },
    { name: 'base64_blob', label: 'long base64 blob (likely obfuscated payload)', severity: 'MEDIUM', pattern: /['"][A-Za-z0-9+/]{200,}={0,2}['"]/g },
    { name: 'hex_escape_blob', label: 'long hex-escape blob (likely obfuscated payload)', severity: 'MEDIUM', pattern: /(?:\\x[0-9a-fA-F]{2}){32,}/g },
    { name: 'solana_keypair', label: 'Solana keypair path access', severity: 'CRITICAL', pattern: /\.config[/\\]solana|solana[/\\]id\.json/gi },
    { name: 'wallet_dat', label: 'wallet.dat (Bitcoin Core / forks) access', severity: 'HIGH', pattern: /wallet\.dat/gi },
    { name: 'keystore_dir', label: 'keystore directory access', severity: 'HIGH', pattern: /\bkeystore\b/gi },
    { name: 'metamask', label: 'MetaMask extension data', severity: 'CRITICAL', pattern: /MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn/g },
    { name: 'phantom', label: 'Phantom wallet extension data', severity: 'CRITICAL', pattern: /Phantom|bfnaelmomeimhlpmgjnjophhpkkoljpa/g },
    { name: 'ledger_live', label: 'Ledger Live data directory', severity: 'HIGH', pattern: /Ledger\s+Live|\bledger-live\b/gi },
    { name: 'exodus', label: 'Exodus wallet data directory', severity: 'HIGH', pattern: /\bExodus\b/g },
    { name: 'electrum', label: 'Electrum wallet data directory', severity: 'HIGH', pattern: /Library\/Application Support\/Electrum|\.electrum/g },
    { name: 'bip39_mnemonic', label: 'BIP-39 mnemonic-shaped phrase near a credential hint', severity: 'HIGH', pattern: /\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b/g, requiresHint: true },
    { name: 'hex_privkey', label: '256-bit hex value near a credential hint', severity: 'HIGH', pattern: /0x[0-9a-fA-F]{64}\b/g, requiresHint: true },
    { name: 'pem_privkey', label: 'PEM-encoded private key', severity: 'HIGH', pattern: /-----BEGIN (?:EC |RSA |OPENSSH |DSA |)PRIVATE KEY-----/g },
    { name: 'outbound_http', label: 'outbound HTTP/HTTPS request to an external host', severity: 'HIGH', pattern: /(?:fetch|axios\.(?:post|get|put|delete)|new\s+XMLHttpRequest|https?\.request)\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g },
];

function snippet(text: string, start: number, end: number, padding = 40): string {
    return text.slice(Math.max(0, start - padding), Math.min(text.length, end + padding)).replace(/\n/g, ' ').trim();
}

function findClipboardSwap(text: string): SignatureHit | null {
    const lib = CLIPBOARD_LIB_RE.exec(text);
    const addr = ETH_ADDR_RE.exec(text) ?? BTC_ADDR_RE.exec(text) ?? SOL_ADDR_RE.exec(text);
    if (!lib || !addr) return null;
    return {
        name: 'clipboard_swap',
        label: 'clipboard address swap (clipboard lib + crypto address)',
        severity: 'HIGH',
        snippet: snippet(text, lib.index, lib.index + lib[0].length),
    };
}

export function scan(text: string): SignatureHit[] {
    if (!text) return [];
    const hasHint = HINTS_RE.test(text);
    const seen = new Set<string>();
    const hits: SignatureHit[] = [];
    for (const s of SIGNATURES) {
        if (s.requiresHint && !hasHint) continue;
        s.pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = s.pattern.exec(text)) !== null) {
            if (!seen.has(s.name)) {
                seen.add(s.name);
                hits.push({ name: s.name, label: s.label, severity: s.severity, snippet: snippet(text, m.index, m.index + m[0].length) });
            }
            if (m.index === s.pattern.lastIndex) s.pattern.lastIndex++;
        }
    }
    const combo = findClipboardSwap(text);
    if (combo) hits.push(combo);
    return hits;
}
