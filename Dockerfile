# Vorken Anti Cheat - Coolify production image
FROM node:22-alpine AS runtime
WORKDIR /app

COPY website/package.json website/pnpm-lock.yaml ./
RUN corepack enable && corepack prepare pnpm@11.25.0 --activate && pnpm install --prod --frozen-lockfile

COPY website/ ./

ENV NODE_ENV=production
ENV PORT=3000
ENV AGENT_BINARY_URL=https://github.com/kaiquedupix-max/vorkenAc/releases/download/agent-latest/Vorken.Agent.exe
ENV AGENT_BINARY_CACHE_MS=60000

EXPOSE 3000

CMD ["npm", "start"]
