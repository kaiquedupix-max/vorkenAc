# Vorken website production image.
# The Windows Agent is built/published by GitHub Actions and fetched byte-for-byte
# from the stable agent-latest release so its Authenticode signature is preserved.
FROM node:22-alpine AS runtime

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN corepack enable && corepack prepare pnpm@11.25.0 --activate && pnpm install --prod --frozen-lockfile

COPY . .

ENV NODE_ENV=production
ENV PORT=3000
ENV AGENT_BINARY_URL=https://github.com/kaiquedupix-max/vorkenAc/releases/download/agent-latest/Vorken.Agent.exe
ENV AGENT_BINARY_CACHE_MS=60000

EXPOSE 3000

CMD ["npm", "start"]
