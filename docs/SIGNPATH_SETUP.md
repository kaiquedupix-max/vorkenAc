# SignPath Foundation setup

This repository is prepared for SignPath Foundation's free Open Source code
signing program. Signing remains disabled until the project is accepted and the
repository secrets listed below are configured.

## Application references

- Repository: <https://github.com/kaiquedupix-max/vorkenAc>
- License: [AGPL-3.0-only](../LICENSE)
- Released binary: <https://github.com/kaiquedupix-max/vorkenAc/releases/tag/agent-latest>
- Privacy policy: [PRIVACY.md](PRIVACY.md)
- Code signing policy: [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md)
- Security policy: [SECURITY.md](../SECURITY.md)
- Official application form: <https://signpath.org/apply>

Suggested project description:

> Vorken is a consent-based defensive forensic scanner used by competitive game
> communities to review traces of cheating and tampering. It detects evidence of
> actual policy or integrity breaches; it does not identify or exploit software
> vulnerabilities, bypass security controls, install persistence, or provide
> unattended access. The optional remote-support session requires explicit player
> initiation, player consent, and administrator acceptance, and can be ended by
> the player at any time.

## SignPath project configuration

1. Apply to SignPath Foundation and wait for project approval.
2. Enable multi-factor authentication for GitHub and SignPath maintainers.
3. Install the SignPath GitHub App for this repository.
4. Use the predefined `GitHub.com` Trusted Build System and GitHub-hosted runners.
5. Create an artifact configuration that accepts the GitHub artifact containing
   `Vorken.Agent.exe` and applies an Authenticode signature to that file.
6. Restrict PE metadata to the values built from `agent/Vorken.Agent.csproj`:
   product `Vorken AntiCheat`, company `Vorken`, and one consistent semantic
   version for product, file, assembly, and informational metadata.
7. Create a production signing policy requiring manual approval.
8. Create a submitter API token restricted to this project and signing policy.

## GitHub repository secrets

Configure these only after SignPath provides the corresponding values:

```text
SIGNPATH_API_TOKEN
SIGNPATH_ORGANIZATION_ID
SIGNPATH_PROJECT_SLUG
SIGNPATH_SIGNING_POLICY_SLUG
SIGNPATH_ARTIFACT_CONFIGURATION_SLUG
```

When all five values exist, `.github/workflows/ci.yml` uploads the unsigned
GitHub build to SignPath, waits for manual approval, downloads the signed result,
validates the Authenticode signature, generates `SHA256SUMS.txt`, and publishes
the signed bytes. The older PFX path is skipped automatically.

Do not create placeholder secrets. A partially configured set deliberately
leaves SignPath disabled so ordinary pull-request checks continue to work.
