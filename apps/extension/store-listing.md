# Chrome Web Store listing — Kotiq Guard (copy-paste into the dashboard)

> Drafts for the CWS listing fields. Public-facing text — kept generic (no detection internals).
> Review each field before submitting; tweak voice to taste.

## Name (max 75 chars)
Kotiq Guard — is this npm package safe to install?

## Summary / short description (max 132 chars)
Check npm packages & GitHub repos for malware, risky install hooks & vulnerabilities — AI insights, right on the page.

## Category
Developer Tools

## Language
English

## Detailed description
Kotiq Guard answers one question: **is this npm package or GitHub repository safe to install or open — before you run it?**

Supply-chain attacks hide in the code that runs *during* `npm install` (install hooks) and in dependencies you never chose. Kotiq checks for them and shows a clear verdict right on the page — before anything executes on your machine.

KEY FEATURES
🔍 Pre-install scan — flags risky install hooks (preinstall/postinstall), risky dependencies, and known vulnerabilities.
🐾 More than CVEs — catches hidden malware, typosquats, and malicious scripts, not just audit advisories.
🧠 AI explainer (Pro — limited early access) — turns the findings into plain, actionable language; an analyst⇄reviewer step keeps it honest.
🔒 Never executes code — static inspection of package.json, scripts and project structure; your machine stays untouched.
🌐 Works in place — instantly on npmjs.com package pages and GitHub repositories.

Trustworthy by design: the verdict comes from a deterministic engine; the AI can only raise concern, never hide it.

Scope: Kotiq currently focuses on the Node.js ecosystem — npm packages and Node projects on GitHub. Support for other ecosystems may follow.

Kotiq Guard is in beta. The safety verdict is free for everyone; the AI explanation layer (Pro) is in limited early access while we expand — you can request access from the extension. Tiers and pricing may change.

Kotiq Guard is an independent security project. It reads the package/repo page you’re viewing — it does not track your browsing.

Stop guessing — know before you install.

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
