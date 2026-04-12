# Security Policy

Thank you for helping keep **Mac Health Check** secure.

Mac Health Check is commonly deployed through MDM Self Service and support workflows, runs with **`root` privileges**, can auto-download and install **swiftDialog**, writes operational logs, and can post failure summaries to **Microsoft Teams** or **Slack** webhooks. The maintained attack surface includes the main script, helper content under `external-checks/`, and packaging and deployment resources under `Resources/`.

## Supported Versions

The latest stable release and the current prerelease line are actively supported for security updates.

- Current stable: **v3.2.0**
- Current prerelease line: **v3.2.0b\*** 
- Older releases receive no security patches.

If you are running an older release, upgrade before requesting security support.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, report it privately.

**Do not** open a public GitHub Issue or Pull Request that discloses the vulnerability.

Send reports to: **security@snelson.us**

Please include as much of the following as possible:

- A clear description of the issue and its potential impact
- Steps to reproduce it
- Affected version(s) of Mac Health Check
- Deployment context, such as MDM platform, operation mode, or webhook usage
- Relevant logs, screenshots, or proof-of-concept details
- Any suggested mitigation or fix
- Your name or handle, if you want attribution

You should receive an acknowledgment within **48 hours**. We will work with you to validate the report, develop a fix, and coordinate disclosure once the issue is resolved.

## Safe Use Guidance

- Test changes and deployments in a lab or VM before broad rollout.
- Use trusted distribution paths, such as official GitHub releases or your own signed packaging flow.
- Review organization-specific customizations before deployment, especially support links, webhook destinations, and externally supplied checks.
- Validate any scripts under `external-checks/` and any packaging helpers under `Resources/` before promoting them into production workflows.
- Prefer current release artifacts and verified installers where applicable.

## Code Security Practices

- This repository is scanned with **Semgrep** using the `p/r2c-security-audit`, `p/ci`, and `p/secrets` rulesets.
- **Gitleaks** scans repository history for potential credential or secret exposure.
- Tracked `*.zsh` files are validated with **`zsh -n`**, including the main entrypoint and zsh helpers under `Resources/`.
- Tracked `*.sh` and `*.bash` files are checked with **ShellCheck**, including helper scripts in `external-checks/` and any tracked shell helpers in `Resources/`.
- Changes are reviewed with attention to shell quoting, download and install paths, webhook handling, external integrations, and packaging helpers.
- The current script verifies downloaded swiftDialog packages before installation and validates GitHub release download URLs before use.

## Disclosure Policy

- We follow coordinated disclosure.
- We will prioritize a fix before sharing public technical details.
- Security fixes will be released as quickly as practical, typically with a tagged release and changelog note.
- We will credit the reporter unless anonymity is requested.

## General Security Questions

For non-vulnerability questions or general usage concerns, use the public project channels.

Community-based, best-effort support is available on the [Mac Admins Slack](https://www.macadmins.org) (free, registration required) [#mac-health-check](https://slack.com/app_redirect?channel=C0977DRT7UY) Channel, or you can open an issue on [GitHub](https://github.com/dan-snelson/Mac-Health-Check/issues).

Last updated: April 2026
