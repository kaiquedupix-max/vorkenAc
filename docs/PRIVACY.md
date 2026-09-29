# Vorken privacy policy

Last updated: 29 September 2026

Vorken is an on-demand, consent-based forensic scanner for competitive game
investigations. This policy describes the open-source Vorken software. A person
or organization operating a Vorken server is responsible for its own deployment,
access controls, retention rules, and compliance obligations.

## Before collection

The Windows agent presents its terms and this policy before a scan can begin.
The player may decline and close the application. Vorken does not install an
unattended service or silently run a scan in the background.

## Technical data collected

After explicit consent, the agent may collect technical indicators needed for
an integrity review, including:

- operating-system, machine, security-product, and hardware metadata;
- running-process, module, executable-signature, and integrity metadata;
- Windows execution artifacts such as Prefetch, Amcache, ShimCache, BAM/DAM,
  UserAssist, MUICache, PCA, event logs, crash metadata, and USN activity;
- executable names, paths, hashes, deletion correlations, download origin, and
  removable-media execution indicators;
- connected and historical removable, USB, and relevant serial devices;
- browser download records and narrowly filtered browsing indicators relevant
  to administrator-defined or public threat rules;
- narrowly filtered PowerShell, autorun, scheduled-task, DNS, and connection
  indicators relevant to the investigation;
- Steam identifiers and administrator-supplied case identifiers; and
- scan errors, timestamps, agent version, and analysis status.

Vorken is not designed to collect passwords, authentication cookies, private
message contents, photographs, videos, personal-document contents, payment
data, or arbitrary memory dumps. Collectors must minimize unrelated content and
the administration interface separates inventory from actual findings.

## Transfer and access

The agent sends the encrypted-in-transit report to the Vorken server named by
the analysis link. Authorized administrators of that deployment can review the
report and record a decision. Reports must not be made public by default. If a
confirmed cheating decision is publicly documented under the Terms of Use, the
operator must limit disclosure to the player's public nickname and the video
excerpts or selected evidence necessary to demonstrate the violation. Unrelated
personal data, private communications, credentials, IP addresses, location,
third-party data, faces, voices, and notifications must be removed or obscured
unless strictly necessary and otherwise lawful. The operator must provide a
review or correction channel and remove or correct the publication if the
decision is reversed.

An optional AI review can send normalized finding summaries to the Google
Gemini API when the server operator enables it. Vorken's VirusTotal integration
uses executable hashes only and does not upload files. Operators are responsible
for reviewing the privacy terms of optional services they enable.

## Remote support

Remote support is off by default. A player must choose screen viewing or screen
viewing with temporary mouse and keyboard control, confirm the request, and an
available administrator must separately accept it. The player can end the
session at any time. Vorken does not provide unattended access, file transfer,
clipboard transfer, credential capture, or persistent remote-control access.
Screen frames are relayed for the live session and are not intentionally stored
by the Vorken server.

## Retention and learned decisions

An unstarted analysis link expires after the period selected by the administrator
(between 1 and 168 hours in the reference deployment). Completed report retention
is controlled by the deployment operator. Operators should keep reports only as
long as necessary for the documented investigation and provide an appropriate
deletion-request channel to their users.

Administrator decisions can create normalized trust or detection records so
future analyses do not repeat known false positives. These records should use
technical identity such as hashes, signer information, product metadata, and
normalized executable characteristics rather than personal file contents.

## Security and user choices

Access to reports requires authenticated administrator accounts. Tokens,
passwords, API keys, and private reports must never be committed to the source
repository. Players may refuse a scan, close the agent before collection, decline
remote support, or end an active remote session.

For a privacy or security concern about the reference project, use GitHub's
private report channel:

<https://github.com/kaiquedupix-max/vorkenAc/security/advisories/new>

For a deployed community server, contact that server's operator because the
open-source project does not control third-party deployments.
