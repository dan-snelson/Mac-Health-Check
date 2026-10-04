# Contributing to Mac Health Check (5.0.0)

First, thank you for your interest in contributing to **Mac Health Check**!

Community contributions have already improved and expanded this project.

## Pull Requests

When submitting a Pull Request, please submit against the `development` branch and ensure your changes are well-documented and tested. Include a clear description of the changes made and the purpose of the contribution.

### Before You Submit
- Read [`AGENTS.md`](AGENTS.md) for project rules, scripting style and boundaries (it applies to human and AI-assisted contributions alike).
- Run `zsh -n Mac-Health-Check.zsh` (and `zsh -n` / `bash -n` on any other script you changed).
- Test affected behavior in all five operation modes: `sudo zsh --no-rcs ./Mac-Health-Check.zsh "" "" "" "<mode>"` with `Self Service`, `Silent`, `Debug`, `Development` and `Test`.
- When adding, removing or renaming a check, update every affected MDM list-item array, the selector skill under [`Skills/mac-health-check-selector/`](Skills/mac-health-check-selector/SKILL.md), `README.md` and `Diagrams/`.
- Add a `CHANGELOG.md` entry describing user-visible changes.
- Keep the [Security Scan](.github/workflows/security-scan.yml) workflow (Semgrep, Gitleaks, `zsh -n`, ShellCheck) passing.
- Never commit secrets, organization-specific data, generated `Artifacts/`, packages or self-extracting scripts.

### Branching Strategy
- `main`: The default branch for the latest production release.
- `development`: Contains ongoing development work and new features.
- Additional branches may be created for new features and testing.


## Feature Requests and Bug Reports
Please use the [Issues](https://github.com/dan-snelson/Mac-Health-Check/issues) section to report bugs or request new features.

When reporting a bug, include as much detail as possible, including steps to reproduce the issue, expected behavior, and any relevant logs or screenshots.

## Invitation to Collaborate

[From Beneficiary to Maintainer](https://tonyyo11.github.io/posts/102406-DanKSnelson-OpenSource-Community/)