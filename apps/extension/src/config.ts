// Shared extension config, sourced from Vite env vars (apps/extension/.env), with dev defaults.
// These values are PUBLIC (the client id ships inside every copy of the extension) — moving them to
// .env is for environment switching (dev localhost ↔ prod Cloud Run URL), not secrecy. Vite inlines
// VITE_* into the built bundle at build time.
//   API_BASE        — where the backend lives. Dev = local server; prod = the Cloud Run URL.
//   OAUTH_CLIENT_ID — the Google OAuth 2.0 *Web application* client id. Empty → sign-in throws a
//                     clear "not configured" error.
export const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8080';
export const OAUTH_CLIENT_ID = import.meta.env.VITE_OAUTH_CLIENT_ID ?? '';

// Secure by default: when true, the content script will NOT call the cloud unless the user is
// signed in. Flip to false ONLY for local dev (backend AUTH_ENABLED=false) to test without sign-in.
export const REQUIRE_AUTH = true;
