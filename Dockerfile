FROM node:20-bookworm-slim AS build
RUN corepack enable && corepack prepare pnpm@10.13.1 --activate
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json tsconfig.base.json eslint.config.js vitest.config.ts ./
COPY apps ./apps
COPY packages ./packages
COPY scripts ./scripts
COPY types ./types
RUN pnpm install --frozen-lockfile
RUN pnpm build
RUN pnpm prune --prod

FROM node:20-bookworm-slim AS runtime
ENV NODE_ENV=production \
    BIOSECURITY_DATA_DIR=/data \
    BIOSECURITY_DOCKER_BIND=true \
    BIOSECURITY_OFFLINE=true
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/apps/server/dist ./apps/server/dist
COPY --from=build /app/apps/viewer/dist ./apps/viewer/dist
COPY --from=build /app/package.json ./package.json
COPY demo ./demo
RUN groupadd --system biosecurity \
    && useradd --system --gid biosecurity --home-dir /data biosecurity \
    && mkdir -p /data \
    && chown biosecurity:biosecurity /data
USER biosecurity
EXPOSE 7331
CMD ["node", "apps/server/dist/index.js"]
