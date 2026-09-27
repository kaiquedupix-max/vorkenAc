# Vorken Anti Cheat - Coolify production image
FROM node:22-alpine AS runtime
WORKDIR /app

COPY website/package*.json ./
RUN npm install --omit=dev

COPY website/ ./

ENV NODE_ENV=production
ENV PORT=3000
ENV AGENT_BINARY_URL=https://github.com/kaiquedupix-max/vorkenAc/releases/download/agent-latest/Vorken.Agent.exe
ENV AGENT_BINARY_CACHE_MS=60000

EXPOSE 3000

CMD ["npm", "start"]
