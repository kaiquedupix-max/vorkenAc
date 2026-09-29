# Security policy

## Supported version

Security fixes target the latest release published from the `main` branch.
Older binaries should be replaced with the latest official release.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting flow:

<https://github.com/kaiquedupix-max/vorkenAc/security/advisories/new>

Include the affected version, reproduction steps, impact, and any suggested
mitigation. Do not attach real player reports, access tokens, credentials, or
other personal data. Please allow the maintainers time to investigate before
public disclosure.

## Release integrity

Official binaries are published only through this repository's GitHub Releases
workflow. Verify the SHA-256 file supplied with each release and, once the free
signing application is approved, verify the Authenticode publisher and
timestamp as described in the
[code signing policy](docs/CODE_SIGNING_POLICY.md).
