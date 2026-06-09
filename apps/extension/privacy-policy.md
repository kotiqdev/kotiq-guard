# Kotiq Guard — Privacy Policy

_Last updated: 9 June 2026_

Kotiq Guard ("Kotiq", "we") is a browser extension that checks whether an npm package or GitHub
repository is safe to install or open, before you run it. This policy explains what data the extension
handles and why. Kotiq Guard is an independent security project.

Kotiq Guard is currently provided as a **beta** service. Features, access tiers, and data handling
practices may evolve as the service develops.

> The canonical, published version of this policy is at https://kotiq.dev/privacy

## What we process

**Account / sign-in data.** When you choose to sign in with Google (the only sign-in method
available), we receive your basic Google profile information — email address, name, and profile
picture. We use it only to authenticate you and to determine which features are available to your
account, and we store a minimal user record (email, name, picture, last-seen time) to manage your
account.

**Authentication tokens.** Authentication tokens are stored locally in your browser using Chrome
extension storage to maintain your signed-in session, and are sent to our backend only to verify your
identity. A few minimal UI preferences (such as the on-page badge position and whether you have seen
the first-run notice) are also stored locally.

**The page you are viewing.** When the extension is active on an npm package page or a GitHub
repository page, it automatically sends the package or repository identifier for the page currently
being viewed to our backend in order to perform the safety check. We do not collect your general
browsing history or your activity on other sites — only the npm package or GitHub repository page
currently being viewed.

## How we use it

- To provide the safety check (verdict + optional explanation).
- To authenticate you and apply the features available to your account.
- To operate, secure, and improve the service (including basic abuse prevention such as rate limiting).

Some users may have access to AI-generated explanations as part of beta testing or future premium
features. For users with access to AI-generated explanations, the scan findings and metadata related
to the package or repository being analyzed may be sent to Google Vertex AI to generate the
explanation. We do not send your Google account data to it. These AI requests may also be logged to
LangSmith (by LangChain) so we can monitor, debug, and improve the AI feature; those traces can
include the package/repository identifier and the analysis content, but not your Google account data.

## Third-party services

The service relies on the following third parties, each with its own privacy policy and terms:

- **Google Identity Services** — authentication (sign-in).
- **Google Vertex AI** — optional AI-generated explanations.
- **LangSmith (LangChain)** — tracing/observability for the AI explanation feature.
- **npm Registry** — public package metadata.
- **GitHub** — public repository information.

## Chrome extension data usage

Kotiq Guard collects and uses data solely to provide its security-scanning functionality.
Kotiq Guard does **not**:

- sell user data;
- use user data for advertising;
- use user data to determine creditworthiness or for lending purposes;
- transfer user data to data brokers;
- use user data for purposes unrelated to the extension's core functionality.

## Permissions

- **identity** — Google sign-in (authentication and account features).
- **storage** — store your session token and minimal UI preferences locally.
- **api.kotiq.dev** — our backend, where scans run.
- **registry.npmjs.org** — read public package metadata / install-hook commands for the on-page check.
- Access to **npmjs.com** and **github.com** pages — only to show the safety badge on the page you are
  viewing.

## Data retention

Account records are retained while your account remains active. Upon verified deletion requests,
account data will be removed within a reasonable period, unless retention is required for security,
fraud prevention, or legal obligations.

## Security notice

Kotiq Guard provides automated security assessments based on publicly available information and
analysis techniques. Scan results, risk scores, and AI-generated explanations are provided for
informational purposes only and do not constitute a guarantee that a package or repository is safe or
unsafe. You remain responsible for your own decisions; for anything untrusted, use an isolated
environment (a VM, container or sandbox).

## Children

Kotiq Guard is intended for developers and technical users. It is not designed specifically for
children.

## Contact

Questions or data requests: **kotiq.dev@gmail.com**

## Changes

We may update this policy; the "last updated" date will change accordingly.
