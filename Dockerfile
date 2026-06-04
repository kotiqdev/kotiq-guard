# syntax=docker/dockerfile:1

# ── Builder: install deps, compile TypeScript → dist/ ────────────────────────────────────────────
FROM node:24-slim AS builder
WORKDIR /app

# Install ALL deps (incl. devDeps like typescript/ts-node) — needed only to build.
COPY package.json package-lock.json ./
RUN npm ci

# Compile src → dist, then copy non-TS assets (agents.yml) next to the compiled code.
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

# Strip devDependencies so we ship a lean node_modules.
RUN npm prune --omit=dev

# ── Runtime: slim image, no source, no toolchain, non-root ───────────────────────────────────────
FROM node:24-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production

# Bring over only what runs: pruned deps + compiled output. Owned by the unprivileged "node" user.
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/dist ./dist
COPY --chown=node:node package.json ./

USER node
# Cloud Run injects $PORT (defaults to 8080); env.ts reads it. Server binds 0.0.0.0.
EXPOSE 8080
CMD ["node", "dist/server/server.js"]
