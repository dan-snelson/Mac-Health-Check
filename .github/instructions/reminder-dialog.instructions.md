---
name: Reminder & Dialog Rules
description: Rules for Inspect Mode, client-side cache, nightly LaunchDaemon, and swiftDialog UX in Mac-Health-Check. Clearly separates Silent mode behavior from background artifact generation.
applyTo: "Mac-Health-Check.zsh"
---

# Reminder & Dialog Instructions for Mac-Health-Check

**Priority Order**: 1. Silent Mode Safety → 2. Cache Replay Rules → 3. Inspect Summary Generation → 4. Error Handling

## 1. Silent Mode Behavior (Highest Priority)

**Core Rule**: In Silent mode, **suppress all interactive dialog updates** (no `dialogUpdate` calls, no progress bars, no Dock badges, no user-facing swiftDialog windows).

**Exception for Critical Errors**: In Silent mode, **critical errors must still be logged** using `fatal` or `errorOut` so they appear in the script log and Splunk report. Do **not** attempt to show any dialog.

**Inspect Summary Generation (Allowed in Silent Mode)**:  
Even in Silent mode, **always generate** the Inspect Summary artifacts (JSON config + compliance plist). This is **background file generation**, not an interactive "dialog update". The Bento grid and Inspect Mode files must be written so `dialog --inspect-mode` can be used later.

## 2. Cache Replay Rules

**`inspectReplayMaximumAgeSeconds`**  
- **Purpose**: Maximum age (in seconds) of a cached Inspect Summary before it is considered stale and must be regenerated.  
- **Typical value**: 900 (15 minutes)  
- **Default if undefined or invalid**: Use **3600 seconds** (1 hour) as fallback.  
- **Rule**: Always check `inspectReplayMaximumAgeSeconds` before deciding to replay. If the variable is missing, empty, or not a positive integer, default to 3600.

**Cache Replay Logic**:
- If a valid cached Inspect Summary exists and is younger than `inspectReplayMaximumAgeSeconds`, replay it (in Self Service mode) or reuse the artifacts (in Silent mode).
- If cache is stale, missing, or invalid → perform full health check run and regenerate artifacts.

## 3. Inspect Summary Generation (Always Required)

- The Inspect Summary (Bento grid, remediation guide, quick actions) **must be generated** in both Self Service and Silent modes.
- Generation happens via `buildInspectConfigJSON`, `buildInspectCompliancePlistXML`, etc.
- In Silent mode: Write the files to disk but do **not** launch any dialog window.
- In Self Service mode: Optionally launch the Inspect Summary after the main dialog closes (if enabled).

## 4. Error Handling

- **Undefined or invalid `inspectReplayMaximumAgeSeconds`**: Default to 3600 seconds and log a warning.
- **Critical errors in Silent mode**: Log via `fatal` / `errorOut` + exit with non-zero code. Never attempt dialog UI.
- **Cache corruption**: If cached JSON or plist fails validation, delete the cache and fall back to full run + warning.
- **Missing swiftDialog for Inspect Mode**: If swiftDialog version is too old for `--inspect-mode`, log a warning and skip Inspect Summary generation.

## 5. Post-Edit Checklist

- Verify Silent mode produces JSON + plist files but no dialog windows.
- Verify Self Service mode shows both main dialog and optional Inspect Summary.
- Confirm cache replay respects `inspectReplayMaximumAgeSeconds` (or defaults to 3600).
- Test with `inspectReplayMaximumAgeSeconds` unset to ensure fallback works.

**Reference**: See `AGENTS.md` for overall mode expectations and `zsh-coding.instructions.md` for dialogUpdate patterns.