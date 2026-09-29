# Code signing policy

Vorken publishes its Windows agent from GitHub Actions using source and build
instructions stored in this repository. Per-player downloads change only the
downloaded filename; the executable bytes remain identical to the official
release so its hash and Authenticode signature are preserved.

## SignPath Foundation

Free code signing provided by SignPath.io, certificate by SignPath Foundation.

This statement becomes applicable to `Vorken.Agent.exe` release binaries after the Vorken project
has been approved by SignPath Foundation and the release displays a valid
SignPath Foundation Authenticode signature. Until then, releases may remain
unsigned and must be verified using their published SHA-256 checksum.

## Team roles

- Committers and reviewers: [repository owner and maintainers](https://github.com/kaiquedupix-max/vorkenAc)
- Approvers: [repository owner](https://github.com/kaiquedupix-max)

Contributions from people without direct commit access require review before
merge. Every production signing request requires manual approval in SignPath.
Repository and SignPath accounts used by maintainers must use multi-factor
authentication.

## Build and release guarantees

- Production artifacts are built on GitHub-hosted runners from a recorded commit.
- Signing requests use the artifact uploaded by that same GitHub Actions run.
- Product and version metadata are defined in the project files and verified
  before publication.
- The signed artifact replaces the unsigned build before SHA-256 generation and
  GitHub Release upload.
- Release assets are never patched to insert a player token. The analysis token
  is read from the personalized filename.
- Official releases include a SHA-256 checksum next to each executable.

## Verification

On Windows, users may inspect **Properties → Digital Signatures** or run:

```powershell
Get-AuthenticodeSignature .\Vorken.Agent.exe
Get-FileHash .\Vorken.Agent.exe -Algorithm SHA256
```

The signature must be valid and the hash must match the checksum published in
the same GitHub Release. See also the [privacy policy](PRIVACY.md),
[security policy](../SECURITY.md), and [trademark policy](../TRADEMARKS.md).
