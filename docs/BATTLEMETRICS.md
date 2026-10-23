# BattleMetrics in Vorken

Optional backend-only enrichment; no new scanner binary is required. Incoming reports have connection evidence recorded by the upload endpoint. Client-supplied BattleMetrics results and connection evidence are overwritten. Old reports without server-recorded public IP still support SteamID queries.

## Configuration

- `BATTLEMETRICS_API_TOKEN`: backend token. Keep it out of commits, scanner binaries, browser storage and logs.
- `BATTLEMETRICS_PLAYER_QUERY_ID`: optional saved Player Query UUID. Run against an exactly resolved BattleMetrics profile. Enable Global Player Matching in the organization and grant the corresponding read/query permissions.
- `BATTLEMETRICS_TRUST_PROXY_HOPS`: defaults to 0 (socket address). Set the exact proxy hop count only if direct access to the app is blocked and trusted proxies control that chain. For an isolated app behind one Coolify proxy, set 1. Do not trust arbitrary forwarded headers on a publicly reachable app.

The token needs `rcon:read` to view and match private identifiers and `ban:read` to read accessible bans. Scopes restrict existing account permissions; they do not grant access to other organizations’ private data.

Restart the backend after configuring variables. No token means no external requests. The US$5 Premium subscription has NOT been verified to grant private-identifier or Player Query API permissions. A 403 is shown as inaccessible, never as a clean result.

## Implemented lookup paths

1. Exact quoted SteamID and upload IP search with identifier inclusion.
2. Require an exact matching identifier attached to the returned player; unrelated included identifiers never establish a link.
3. Optional saved Player Query for up to three resolved seed profiles. Global matches can have hidden SteamIDs. Scores are not confidence percentages.
4. Read accessible bans for matched profiles and verify the ban's player relationship. Display reason, issuing server when available, dates, expiry and source link. No claim of exhaustive coverage or current innocence.

API routes used: `/players`, `/bans`, `/players/{playerId}/relationships/player-query/{savedQueryId}`. Their request/response contract is covered with fixtures, but MUST be validated against the real token before calling this integration operational. Request formats were checked against the official API documentation HTML supplied on 15 October 2026, including reverse identifier-to-player relationships, offset search pagination and inclusion of expired bans. Live token permissions and subscription eligibility remain untested. Global ban metadata fields and arbitrary-IP insertion into the matching database are not assumed or synthesized.

## Limits and failure behavior

At most 10 SteamID seeds, three search pages per seed, 20 displayed profiles and 20 ban records per profile. At most 35 request attempts and 25 seconds per enrichment. Pagination/time/quantity limits appear as partial coverage. At least 1.1 seconds between request starts per backend instance. Successful complete results cache for 15 minutes (500 entries). HTTP 429 pauses subsequent calls for Retry-After, with a minimum 60-second cooldown. No tight retry loops. Multiple backend replicas have independent throttles; size deployment accordingly.

The admin report shows a dedicated BattleMetrics block and a manual query button. Scoped session routes authorize the requesting customer/server before making an external request. The refresh patches only the external context, preserving local findings. A failed external provider never prevents the local analysis from completing. Associated accounts are not inserted into the scanner's list of accounts found on the PC, and no automatic ban findings are created.

An IP association proves neither common ownership nor execution on the scanned PC. CGNAT, VPNs and shared networks can connect different people. Only the scanner's local artifacts establish local account presence.

## Activation validation

Use a known accessible profile to compare the UI/API identifier, Player Query and ban results against the report. Confirm 401/403/429 behavior and test the current subscription with an external profile. Check proxy configuration against a known upload IP. Do not interpret a hidden identifier, inaccessible list or empty response as a global negative.
