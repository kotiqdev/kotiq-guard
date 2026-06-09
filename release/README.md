# Kotiq Guard — test build (reviewers / judges)

A pre-built, **unpacked** build of the Kotiq Guard Chrome extension, wired to the production backend
(`https://api.kotiq.dev`). Use it to try the extension before it is live on the Chrome Web Store.

## Install (Chrome / Edge / Brave)

1. Download **`kotiq-guard-extension.zip`** from this folder and unzip it.
2. Open `chrome://extensions` (or `edge://extensions`).
3. Turn on **Developer mode** (toggle, top-right).
4. Click **Load unpacked** and select the unzipped **`kotiq-guard-extension`** folder.
5. The Kotiq paw icon appears in your toolbar.

## Try it

1. Click the **Kotiq** toolbar icon → read the notice → **Got it**.
2. Click **Sign in with Google** (the only sign-in method).
3. Open an npm package page, e.g. <https://www.npmjs.com/package/express> → a **SAFE** badge appears on the page.
4. Open a deliberately-unsafe demo repo: <https://github.com/kotiqdev/example-malware-repo> → a
   **MALICIOUS** badge appears. Click it to expand the findings, then **Explain with AI** for the Pro
   analysis.
   *(That repository is an inert, defanged test fixture — it contains no working malware; every host is
   a non-resolving `*.invalid` placeholder.)*

## Notes

- The extension activates **only** on `npmjs.com/package/*` and `github.com/*` pages.
- It sends only the package name / repo identifier to the backend; it **never executes** the code it inspects.
- This is a beta build for evaluation. Sign-in credentials for reviewers are provided privately with the submission.
