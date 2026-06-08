# Chrome Web Store listing — Kotiq Guard (copy-paste into the dashboard)

> Drafts for the CWS listing fields. Public-facing text — kept generic (no detection internals).
> Review each field before submitting; tweak voice to taste.

## Name (max 75 chars)
Kotiq Guard — is this npm package safe to install?

## Summary / short description (max 132 chars)
Checks an npm package or GitHub repo for risky install hooks and dependencies — before you install or open it.

## Category
Developer Tools

## Language
English

## Detailed description
Kotiq Guard answers one question: **is this npm package or GitHub repository safe to install or open — before you run it?**

Supply-chain attacks hide in the code that runs *during* `npm install` (install hooks) and in dependencies you never chose directly. Kotiq checks those for you and shows a clear verdict right on the page, so you can decide before anything executes on your machine.

What you get:
• A safety verdict badge on npmjs.com package pages and on GitHub repositories.
• A look at the install hooks a package declares and what its dependencies bring in.
• A plain-language explanation of *why* something is risky (Pro) — grounded in the actual findings, written by an AI analyst with a reviewer step to keep it honest.
• Fast, deterministic checks first; the AI layer only adds explanation on top.

Kotiq is built to be trustworthy: the verdict comes from a deterministic engine, and the AI can only raise concern, never hide it.

Free (Lite): the deterministic safety verdict.
Pro: the AI explanation layer.

Kotiq Guard is an independent security project. It reads the package/repo you’re viewing — it does not track your browsing.

## Single purpose (required)
Kotiq Guard shows a safety verdict for the npm package or GitHub repository you are viewing — by checking its install hooks and dependencies — so you can judge whether it is safe to install or open before you run it.

## Permission justifications (required — one per permission)

**identity**
Used to sign you in with Google (via launchWebAuthFlow) so the extension can authenticate you to the Kotiq backend and determine your tier (Lite vs Pro). No contacts or other Google data are accessed beyond your basic profile (email, name, picture).

**storage**
Used to cache your session token locally so you stay signed in between sessions. No browsing data is stored.

**host permission: https://api.kotiq.dev/***
The Kotiq backend API. The extension sends the package name (or repo owner/name) you are viewing to this endpoint to run the safety scan and return the verdict/explanation.

**host permission: https://registry.npmjs.org/***
Read public package metadata and the install-hook commands a package declares, for the on-page Lite check.

**content scripts on https://www.npmjs.com/package/* and https://github.com/***
Inject the safety badge and findings UI onto the npm package page and GitHub repository page you are viewing. The extension only acts on these pages.

## Privacy practices (Data usage tab)
Data collected:
- **Personally identifiable information** — email address (for sign-in / account & tier). 
- **Authentication information** — Google ID token / session token.
- **Website content** — the npm package name / GitHub repo identifier you are viewing (sent to the backend to scan).

Declarations:
- Not sold to third parties. ✅
- Not used or transferred for purposes unrelated to the app’s core functionality. ✅
- Not used to determine creditworthiness / for lending. ✅
- Used only to provide and improve the safety-check feature.

Privacy policy URL: https://kotiq.dev/privacy  (publish privacy-policy.md there)

## Screenshots needed (1280×800 or 640×400, ≥1; aim for 3–4)
1. npm package page with the Kotiq verdict badge (a SAFE example).
2. npm package page with a SUSPICIOUS/MALICIOUS verdict + findings expanded.
3. GitHub repo page with the badge + the AI explanation (Pro) shown.
4. The popup (signed in, tier shown).

Tip: build the keyed local build (`npm run build:prod-local`), load unpacked, capture at a 1280×800 window.
