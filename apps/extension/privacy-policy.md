# Kotiq Guard — Privacy Policy

_Last updated: 8 June 2026_

Kotiq Guard ("Kotiq", "we") is a browser extension that checks whether an npm package or GitHub
repository is safe to install or open, before you run it. This policy explains what data the extension
handles and why. Kotiq Guard is an independent security project.

## What we process

**Account / sign-in data.** When you sign in with Google, we receive your basic Google profile:
email address, name, and profile picture. We use this only to authenticate you and to determine your
access tier (Lite or Pro). We store a minimal user record (email, name, picture, last-seen time) to
manage your account and tier.

**Authentication tokens.** Your Google ID token / session token is cached locally in the browser
(`chrome.storage`) so you stay signed in. It is sent to our backend only to verify your identity.

**The item you are checking.** When you request a scan, the extension sends the npm package name (or
the GitHub repository owner and name) you are viewing to our backend so it can run the safety check
and return a verdict. We do not collect your browsing history; we only process the specific package or
repository you ask us to check.

## How we use it

- To provide the safety check (verdict + optional explanation).
- To authenticate you and apply your access tier.
- To operate, secure, and improve the service (including basic abuse prevention such as rate limiting).

The optional AI explanation (Pro) is generated using Google’s Vertex AI. The findings being explained
are sent to that service to produce the explanation. We do not send your Google account data to it.

## What we do NOT do

- We do **not** sell your data.
- We do **not** use or transfer your data for purposes unrelated to the safety-check feature.
- We do **not** track your general browsing or the pages you visit beyond the package/repo you choose
  to scan.

## Permissions

- **identity** — Google sign-in (authentication and tier).
- **storage** — cache your session token locally so you stay signed in.
- **api.kotiq.dev** — our backend, where scans run.
- **registry.npmjs.org** — read public package metadata / install-hook commands for the on-page check.
- Access to **npmjs.com** and **github.com** pages — only to show the safety badge on the page you are
  viewing.

## Data retention

Account records are kept while your account is active. You can request deletion of your account data
by contacting us.

## Contact

Questions or data requests: **kotiq.dev@gmail.com**

## Changes

We may update this policy; the “last updated” date will change accordingly.
