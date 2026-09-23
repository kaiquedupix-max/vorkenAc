# Vorken Anti Cheat - Coolify production image
# Stage 1: build the Windows scanner as a self-contained single-file executable.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS agent-build
WORKDIR /src

COPY agent/Vorken.Agent.csproj agent/
RUN dotnet restore agent/Vorken.Agent.csproj -r win-x64

COPY agent/ agent/
RUN dotnet publish agent/Vorken.Agent.csproj \
    -c Release \
    -r win-x64 \
    --self-contained true \
    --no-restore \
    -o /out/agent

# Stage 2: Node.js web/API.
FROM node:22-alpine AS runtime
WORKDIR /app

COPY website/package*.json ./
RUN npm install --omit=dev

COPY website/ ./
RUN mkdir -p /app/agent-build

COPY --from=agent-build /out/agent/Vorken.Agent.exe /app/agent-build/Vorken.Agent.exe

ENV NODE_ENV=production
ENV PORT=3000
ENV AGENT_BINARY_PATH=/app/agent-build/Vorken.Agent.exe

EXPOSE 3000

CMD ["npm", "start"]
