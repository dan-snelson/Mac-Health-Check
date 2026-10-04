---
name: Inspect Summary & Dialog Rules
description: Rules for the swiftDialog main dialog, the detached Inspect Summary (Preset 6), cached replay, and Silent-mode asset generation in Mac-Health-Check.zsh.
applyTo: "Mac-Health-Check.zsh"
---

# Inspect Summary & Dialog Instructions

`AGENTS.md` takes precedence. When this file and `Mac-Health-Check.zsh` disagree, the script wins.

**Priority Order**: 1. Silent Mode Safety → 2. Inspect Summary Generation → 3. Cached Replay → 4. Error Handling

## 1. Silent Mode Behavior

- `Silent` never launches swiftDialog: pre-flight skips the swiftDialog install/update check, no main dialog opens, and no detached Inspect Summary launches.
- Health checks still call `dialogUpdate` in `Silent`. `dialogUpdate` records list-item results (through `recordHealthCheckResult`) and skips only the write to the swiftDialog command file, so results still reach the JSON report, Splunk, and Inspect assets.
- Guard other UI-only work (completion countdown, Dock badge, title and icon changes in `quitScript`) with `[[ "${operationMode}" != "Silent" ]]`.
- `Silent` + `splunkOperationMode=production` is reporting-first: non-Splunk console output is suppressed and success means the local report was generated and HEC delivery succeeded.

## 2. Inspect Summary Generation

- Enabled when `inspectSummaryPreset="on"` (shipped default; anything other than `off` is treated as `on`).
- Runs in `quitScript` only after the JSON report was generated, and only in `Self Service` and `Silent`. `Debug`, `Development`, and `Test` do not generate Inspect assets.
- `generateInspectSummaryAssets` builds the Preset 6 config (`buildInspectConfigJSON`) and compliance plist, validates them, and writes root-owned, user-readable files to `/Library/Application Support/<reverseDomainNameNotation>/Inspect/` (`MacHealthCheck-Inspect-Config.json`, `MacHealthCheck-Inspect-Compliance.plist`). Per-user control files live under `Inspect/Users/<user>/`.
- `Self Service`: generate the assets, then `launchInspectSummary` starts a detached `Dialog.app/Contents/MacOS/dialogcli --inspect-mode` (`dialogBinary`) as the logged-in user. The main dialog then runs its normal completion countdown, so the summary appears while the countdown runs.
- `Silent`: write the assets without launching swiftDialog. These assets are not replayed by `Silent`; a later `Self Service` run may replay them.

## 3. Cached Replay

- `replayCachedInspectSummaryIfEligible` runs only in `Self Service`, only when the previous report was fully healthy with no reporting errors (targeted-recheck eligibility status `healthy`), and only with Inspect Summary enabled.
- Replay window: `inspectReplayMaximumAgeSeconds="900"` (15 minutes). There is no fallback default; a cached config at or above that age triggers a full run.
- The cached config must be readable, a root-owned regular file, valid JSON, a valid Preset 6 structure, and generated for the current user's Inspect directory. Any failure logs `info` or `warning` and runs the full health check. The cached file is **not** deleted; the next full run overwrites it.
- A successful replay launches the cached summary and exits `0` without running checks.

## 4. Error Handling

- Asset-generation failure: `Self Service` logs and continues with the standard completion countdown; `Silent` logs a `warning` and continues without UI. Neither is fatal.
- Detached launch without a valid PID: `warning` naming the launch log; replay falls back to a full run.
- swiftDialog: pre-flight in non-`Silent` modes requires `swiftDialogMinimumRequiredVersion` (`3.1.1.4997`) and installs or updates it; there is no separate Inspect-only version gate.
- Keep Inspect and dialog JSON valid; validate with `validateJson` before writing.

## 5. Post-Edit Checklist

- `zsh -n Mac-Health-Check.zsh`.
- `Silent`: report and Inspect assets written; no swiftDialog process; `/var/tmp/dialog.log` and the Dock-named app untouched.
- `Self Service`: main dialog, detached summary during the countdown, and replay within 15 minutes of a healthy run.
- `Debug`, `Development`, `Test`: no Inspect assets and no regression in the main dialog.

**Reference**: `AGENTS.md` for mode expectations; `zsh-coding.instructions.md` for the `dialogUpdate` and check lifecycle.
