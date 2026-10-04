---
name: Deployment Flow
description: Rules for releasing and deploying Mac-Health-Check via any MDM (Self Service policy or Silent script), the Client-Side Cache LaunchDaemon, and the packaging helpers in Resources/. Emphasizes version alignment, five-mode regression, and safe release practices.
applyTo: "**/*.{zsh,md,yml,yaml}"
---

# Deployment Flow Instructions

`AGENTS.md` takes precedence. When this file and `Mac-Health-Check.zsh` disagree, the script wins.

**Priority Order**: 1. Version Alignment → 2. Five-Mode Regression → 3. Release Safety → 4. Failure Handling

## 1. Version Alignment

- `scriptVersion` in `Mac-Health-Check.zsh` is the canonical version.
- `VERSION.txt` is git-ignored and local-only (a release-helper marker); keep it equal to `scriptVersion` on your machine, but never expect it in a clone or commit it.
- The top `CHANGELOG.md` entry must match `scriptVersion` and shipped behavior.
- If `scriptVersion`, `VERSION.txt`, and `CHANGELOG.md` disagree, stop the release and fix them together. Updating `VERSION.txt` or preparing a release needs approval (see `AGENTS.md`).
- A `scriptVersion` change makes the next `Self Service` run a full run (`version_mismatch`) instead of a targeted recheck, and makes `Silent` + production skip the cached-upload shortcut until the client-side copy matches.

## 2. Five-Mode Regression

After any script or runtime change:

1. `zsh -n Mac-Health-Check.zsh` (zero errors).
2. `sudo zsh ./Mac-Health-Check.zsh "" "" "" "Development"` (Parameter 4 sets `operationMode`; there is no `--mode` flag). `Development` runs a curated subset only.
3. Repeat with `Debug`, `Test`, `Silent`, and `Self Service`; review every mode the change touches.
4. `Silent`: confirm the JSON report and Inspect assets are written and no swiftDialog UI appears. With `splunkOperationMode=production`, confirm reporting-first behavior.
5. `Self Service`: confirm the main dialog, the detached Inspect Summary, and cached replay within `inspectReplayMaximumAgeSeconds` (900 s).
6. Trigger at least one failing check and confirm a clear remediation subtitle and log line.

## 3. Release Safety Rules

- Deploy only `Self Service` or `Silent` to production; `Debug`, `Development`, and `Test` are for testing.
- Never leak `Debug` or `Development` behavior into production paths.
- Do not modify or rebuild `Resources/` artifacts without explicit approval.
- The Client-Side Cache (`/Library/Management/<RDNN>/MHC.zsh` plus LaunchDaemon) installs only in `Self Service`, `Debug`, or `Silent` with `splunkOperationMode=production`, never in `Test` or `Development`, and only from a root-owned script path. The nightly copy defaults to `Silent`, skips `jamf recon`, and never sends webhook messages.
- Test on a clean Mac or VM enrolled in the target MDM before promoting the policy.

## 4. Failure Handling

- **Version mismatch**: stop the release (Section 1).
- **Regression failure**: do not promote; fix the root cause, rerun the five-mode regression, and note the fix in `CHANGELOG.md`.
- **Silent Inspect asset failure**: the script logs a `warning` and continues; investigate it, but it does not fail the run. Report generation and (in production) HEC delivery decide `Silent` success.
- **Client-Side Cache install failure**: the script logs a `warning` and continues the current run; check the log for the reason (untrusted path, failed `zsh -n`, missing `Silent` default, or leftover `jamf recon` text).
- **Packaging issues** (`Resources/Makefile`, `createSelfExtracting.zsh`, `postInstall.zsh`): revert and verify against `Resources/README.md`.

## 5. Pre-Release Checklist

- [ ] `scriptVersion` == local `VERSION.txt` == top `CHANGELOG.md` entry
- [ ] Five-mode regression passed (`Self Service`, `Silent`, `Debug`, `Development`, `Test`)
- [ ] No `Debug`/`Development` defaults in production paths
- [ ] `README.md` and `Diagrams/` match current behavior
- [ ] `zsh -n` clean on every modified Zsh script

**Reference**: `AGENTS.md` for the release checklist; `zsh-coding.instructions.md` for mode rules.
