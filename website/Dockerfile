# Vorken website + Windows agent production image
# This Dockerfile also works when Coolify uses /website as the project root.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS agent-build

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# /website deployments cannot COPY ../agent because it is outside Docker's build
# context. Pull the public repository and build the agent from the same main branch.
RUN git clone --depth 1 --branch main https://github.com/kaiquedupix-max/vorkenAc.git /src/vorken

RUN dotnet restore /src/vorken/agent/Vorken.Agent.csproj -r win-x64 \
    && dotnet publish /src/vorken/agent/Vorken.Agent.csproj \
       -c Release \
       -r win-x64 \
       --self-contained true \
       --no-restore \
       -o /out/agent

FROM node:22-alpine AS runtime

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY . .

RUN mkdir -p /app/agent-build
COPY --from=agent-build /out/agent/Vorken.Agent.exe /app/agent-build/Vorken.Agent.exe

ENV NODE_ENV=production
ENV PORT=3000
ENV AGENT_BINARY_PATH=/app/agent-build/Vorken.Agent.exe

EXPOSE 3000

CMD ["npm", "start"]
