// Web3 / Contagious-Interview signature library (Plan.md §6).
//
// Pure regex/heuristic detectors. No I/O. Used by `analyzeManifest` to find crypto-theft patterns
// inside install-hook sources surfaced by Phase 1 (hook_sources).
//
// Each Signature has a stable `name` (test fixture key), a `category` (always `crypto_theft` for
// the §6 patterns), a default `severity`, and a regex `pattern`. Two patterns — the BIP-39
// mnemonic shape and a bare 256-bit hex string — require a *hint* token (`mnemonic`,
// `seed phrase`, `privateKey`, `wallet`, `keystore`) within the same text to keep false positives
// down on prose.
//
// The clipboard-address swap is a *combination* check (clipboard library import AND a crypto
// address literal appearing in the same text), implemented separately in `findClipboardSwap`.

import { Severity } from '../models/enums';

const HINTS_RE =
  /(mnemonic|seed[\s_-]?phrase|private[\s_-]?key|wallet|keystore|account[\s_-]?recovery)/i;

const CLIPBOARD_LIB_RE =
  /clipboardy|clipboard-event|clipboard\.write|require\(\s*['"]clipboardy['"]\)/;
const ETH_ADDR_RE = /0x[a-fA-F0-9]{40}\b/;
const BTC_ADDR_RE = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/;
const SOL_ADDR_RE = /\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/;

export interface SignatureHit {
  name: string;
  category: string;
  label: string;
  severity: Severity;
  snippet: string;
  // 1-based line number.
  line: number;
}

interface Signature {
  name: string;
  category: string;
  label: string;
  severity: Severity;
  pattern: RegExp;
  requiresHint?: boolean;
}

const sig = (
  name: string,
  category: string,
  label: string,
  severity: Severity,
  pattern: RegExp,
  requiresHint = false,
): Signature => ({ name, category, label, severity, pattern, requiresHint });

// Plan.md §6 signature catalog. All patterns carry the global flag so we can iterate every match.
const SIGNATURES: readonly Signature[] = [
  // --- SECOND_PAYLOAD --------------------------------------------------------------------------
  sig(
    'curl_pipe_sh',
    'crypto_theft',
    'remote shell pipe (curl|sh / wget|sh)',
    Severity.CRITICAL,
    /\b(?:curl|wget)\b[^\n;]{0,200}?\|\s*(?:sh|bash)\b/g,
  ),
  sig(
    'node_dash_e',
    'crypto_theft',
    'node -e inline execution',
    Severity.HIGH,
    /\bnode\s+-e\b/g,
  ),
  sig('eval_call', 'crypto_theft', 'eval() of dynamic source', Severity.HIGH, /\beval\s*\(/g),
  sig(
    'function_constructor',
    'crypto_theft',
    'Function() constructor (eval substitute)',
    Severity.HIGH,
    /\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"]/g,
  ),
  sig(
    'base64_blob',
    'obfuscation',
    'long base64 blob (likely obfuscated payload)',
    Severity.MEDIUM,
    /['"][A-Za-z0-9+/]{200,}={0,2}['"]/g,
  ),
  sig(
    'hex_escape_blob',
    'obfuscation',
    'long hex-escape blob (likely obfuscated payload)',
    Severity.MEDIUM,
    /(?:\\x[0-9a-fA-F]{2}){32,}/g,
  ),
  // --- WALLET_PATHS ----------------------------------------------------------------------------
  sig(
    'solana_keypair',
    'crypto_theft',
    'Solana keypair path access',
    Severity.CRITICAL,
    /\.config[/\\]solana|solana[/\\]id\.json/gi,
  ),
  sig(
    'wallet_dat',
    'crypto_theft',
    'wallet.dat (Bitcoin Core / forks) access',
    Severity.HIGH,
    /wallet\.dat/gi,
  ),
  sig(
    'keystore_dir',
    'crypto_theft',
    'keystore directory access',
    Severity.HIGH,
    /\bkeystore\b/gi,
  ),
  sig(
    'metamask',
    'crypto_theft',
    'MetaMask extension data',
    Severity.CRITICAL,
    /MetaMask|nkbihfbeogaeaoehlefnkodbefgpgknn/g,
  ),
  sig(
    'phantom',
    'crypto_theft',
    'Phantom wallet extension data',
    Severity.CRITICAL,
    /Phantom|bfnaelmomeimhlpmgjnjophhpkkoljpa/g,
  ),
  sig(
    'ledger_live',
    'crypto_theft',
    'Ledger Live data directory',
    Severity.HIGH,
    /Ledger\s+Live|\bledger-live\b/gi,
  ),
  sig(
    'exodus',
    'crypto_theft',
    'Exodus wallet data directory',
    Severity.HIGH,
    /\bExodus\b/g,
  ),
  sig(
    'electrum',
    'crypto_theft',
    'Electrum wallet data directory',
    Severity.HIGH,
    /Library\/Application Support\/Electrum|\.electrum/g,
  ),
  // --- SEED_OR_KEY (hint-gated to avoid prose false positives) ---------------------------------
  sig(
    'bip39_mnemonic',
    'crypto_theft',
    'BIP-39 mnemonic-shaped phrase near a credential hint',
    Severity.HIGH,
    /\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b/g,
    true,
  ),
  sig(
    'hex_privkey',
    'crypto_theft',
    '256-bit hex value near a credential hint',
    Severity.HIGH,
    /0x[0-9a-fA-F]{64}\b/g,
    true,
  ),
  sig(
    'pem_privkey',
    'crypto_theft',
    'PEM-encoded private key',
    Severity.HIGH,
    /-----BEGIN (?:EC |RSA |OPENSSH |DSA |)PRIVATE KEY-----/g,
  ),
  // --- EXFIL -----------------------------------------------------------------------------------
  sig(
    'outbound_http',
    'crypto_theft',
    'outbound HTTP/HTTPS request to an external host',
    Severity.HIGH,
    /(?:fetch|axios\.(?:post|get|put|delete)|new\s+XMLHttpRequest|https?\.request)\s*\(\s*['"`]https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g,
  ),
];

function snippet(text: string, start: number, end: number, padding = 40): string {
  const a = Math.max(0, start - padding);
  const b = Math.min(text.length, end + padding);
  return text.slice(a, b).replace(/\n/g, ' ').trim();
}

function lineOf(text: string, offset: number): number {
  let n = 1;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text.charCodeAt(i) === 10) n++;
  }
  return n;
}

export function findClipboardSwap(text: string): SignatureHit | null {
  const lib = CLIPBOARD_LIB_RE.exec(text);
  const addr = ETH_ADDR_RE.exec(text) ?? BTC_ADDR_RE.exec(text) ?? SOL_ADDR_RE.exec(text);
  if (!lib || !addr) return null;
  return {
    name: 'clipboard_swap',
    category: 'crypto_theft',
    label: 'clipboard address swap (clipboard lib + crypto address)',
    severity: Severity.HIGH,
    snippet: snippet(text, lib.index, lib.index + lib[0].length),
    line: lineOf(text, lib.index),
  };
}

export function scan(text: string): SignatureHit[] {
  if (!text) return [];
  const hasHint = HINTS_RE.test(text);
  const seen = new Set<string>();
  const hits: SignatureHit[] = [];
  for (const s of SIGNATURES) {
    if (s.requiresHint && !hasHint) continue;
    // Fresh state for each signature; regexes are global.
    s.pattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = s.pattern.exec(text)) !== null) {
      const line = lineOf(text, m.index);
      const key = `${s.name}:${line}`;
      if (!seen.has(key)) {
        seen.add(key);
        hits.push({
          name: s.name,
          category: s.category,
          label: s.label,
          severity: s.severity,
          snippet: snippet(text, m.index, m.index + m[0].length),
          line,
        });
      }
      // Guard against zero-width matches.
      if (m.index === s.pattern.lastIndex) s.pattern.lastIndex++;
    }
  }
  const combo = findClipboardSwap(text);
  if (combo) hits.push(combo);
  return hits;
}
