# Vorken Anti Cheat

Vorken is a consent-based Windows inspection tool for competitive game-server investigations.

## What this MVP contains

- Admin dashboard to create a new analysis.
- Unique public analysis link with an expiring token.
- Per-analysis downloadable ZIP containing the Vorken Agent configuration.
- Windows agent written in C#/.NET.
- Collection of technical metadata only:
  - connected USB devices;
  - historical USBSTOR entries;
  - Arduino/CH340/CP210/FTDI-like devices;
  - running processes;
  - Windows Prefetch file metadata;
  - services and system drivers;
  - startup entries;
  - suspicious file metadata and SHA-256 hashes.
- Custom detection rules managed from the admin panel.
- Report ingestion and server-side finding generation.
- PostgreSQL persistence.

The agent does **not** collect passwords, browser cookies, private messages, photos, documents, or arbitrary file contents.

## Quick start

### Website

```bash
cd website
npm install
npm start
```

Environment variables:

```
DATABASE_URL=postgresql://...
SESSION_SECRET=change-me
ADMIN_PASSWORD=change-me
PUBLIC_URL=https://your-domain.example
AGENT_BINARY_PATH=/absolute/path/to/Vorken.Agent.exe
PORT=3000
```

### Agent

```bash
cd agent
dotnet publish -c Release -r win-x64 --self-contained false
```

Copy the generated `Vorken.Agent.exe` to the path configured in `AGENT_BINARY_PATH`.

The server creates a ZIP for each analysis containing:

```
Vorken.Agent.exe
vorken-analysis.json
```

The JSON file contains the unique analysis token, so the person being inspected does not need to type a key manually.

## Detection rules

Supported MVP rule types:

- `filename_contains`
- `path_contains`
- `sha256`
- `process_name`
- `service_name`
- `driver_name`
- `device_keyword`
- `prefetch_contains`

Rules flag evidence for manual review; a match is not presented as proof of cheating by itself.

## Scope

Vorken is designed for transparent, consent-based defensive inspection. Findings should be reviewed by a human before moderation action is taken.
