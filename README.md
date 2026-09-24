# Vorken Anti Cheat

Vorken is a consent-based Windows forensic scanner for competitive game-server investigations.

## Vorken Agent 1.0

The public analysis page downloads a **single Windows EXE**. The analysis token is encoded in the downloaded filename, so there is no ZIP and no sidecar configuration file to extract.

The agent collects defensive technical evidence such as:

- USB/current and historical devices, Arduino/CH34x/CP210x/FTDI and removable-media timeline;
- Prefetch, BAM/DAM, UserAssist, MUICache, PCA, Amcache, ShimCache and Event 4688;
- NTFS USN Journal deletions plus JournalTrace-style create/delete/rename/change events;
- browser download history, browser-risk flags, suspicious search/site history, SQLite/WAL recovery and Zone.Identifier origin;
- Recycle Bin, shortcuts, Windows Error Reporting/crash metadata and deleted-file correlations;
- SHA-256, real Authenticode/WinVerifyTrust validation, PE timestamps, entropy, sections and packer indicators;
- suspicious PowerShell history/events, autoruns, scheduled tasks and NTFS Alternate Data Streams;
- Rust/high-value process module integrity and capture-excluded/streamproof-style windows;
- Defender history/exclusions, registered antivirus/firewall products, Secure Boot, BCD, service changes, SRUM state and Prefetch integrity;
- DNS indicators and current TCP connections correlated with process/signature metadata;
- VM/virtual-disk/system-time/log-clear/integrity context;
- public Rust cheat/script IOC catalog plus custom admin rules.

The agent does **not** collect passwords, browser cookies, private messages, photos, document contents or arbitrary RAM dumps.

## Website

```bash
cd website
npm install
npm start
```

Environment variables:

```text
DATABASE_URL=postgresql://...
SESSION_SECRET=change-me
ADMIN_PASSWORD=change-me
PUBLIC_URL=https://your-domain.example
AGENT_BINARY_PATH=/absolute/path/to/Vorken.Agent.exe
PORT=3000

# Optional: hash-only reputation checks. Vorken never uploads files.
VIRUSTOTAL_API_KEY=
```

## Agent

```bash
cd agent
dotnet publish -c Release -r win-x64 --self-contained true
```

The production root Dockerfile builds the Windows agent and places it at the configured `AGENT_BINARY_PATH`.

### EXE verification and code signing

Every direct download exposes the SHA-256 of the exact executable on the analysis page and through the `X-Vorken-SHA256` response header.

The GitHub Actions workflow supports optional Authenticode signing with these repository secrets:

```text
VORKEN_SIGNING_PFX_BASE64
VORKEN_SIGNING_PFX_PASSWORD
```

The PFX must contain a valid Windows code-signing certificate. Without a trusted code-signing certificate, Windows SmartScreen or antivirus products may still warn about a newly distributed executable even when the build is legitimate. Product metadata and a checksum improve verification but do not replace code-signing reputation.

## Detection philosophy

Context/inventory is not automatically a finding. High-severity findings require stronger signals such as execution evidence, deletion correlation, a known IOC, a suspicious unsigned binary, a risky origin, a catalog match or multiple corroborating artifacts.

Rules and heuristic matches are evidence for human review, not automatic proof that a player cheated.

## Public-tool compatibility layer

Vorken implements its own defensive equivalents of publicly documented screenshare/forensic capabilities such as saved-file origin, browser downloads/history, Prefetch, BAM, Amcache, USB, PowerShell, autoruns, USN/JournalTrace, ADS, WER/crashes, PE/packer inspection, integrity checks and network/DNS correlation.

It does not copy proprietary signatures, databases or source code from third-party scanners.
