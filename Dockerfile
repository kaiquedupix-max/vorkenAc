# Vorken Anti Cheat - Coolify production image
# Build the Windows agent from the same private checkout as the website.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS agent-build
WORKDIR /src
COPY .config/ ./.config/
RUN dotnet tool restore
COPY agent/ ./agent/
COPY brand/ ./brand/
RUN dotnet publish ./agent/Vorken.Agent.csproj -c Release -r win-x64 --self-contained true -o /agent-output

FROM node:22-alpine AS runtime
WORKDIR /app

COPY website/package.json website/pnpm-lock.yaml ./
RUN corepack enable && corepack prepare pnpm@11.25.0 --activate && pnpm install --prod --frozen-lockfile

COPY website/ ./
COPY --from=agent-build /agent-output/Vorken.Agent.exe ./agent-build/Vorken.Agent.exe

ENV NODE_ENV=production
ENV PORT=3000
ENV AGENT_BINARY_SOURCE=local
ENV AGENT_BINARY_PATH=/app/agent-build/Vorken.Agent.exe
ENV AGENT_BINARY_CACHE_MS=60000

EXPOSE 3000

CMD ["npm", "start"]
