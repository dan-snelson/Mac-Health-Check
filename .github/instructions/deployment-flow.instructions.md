---
name: Deployment Flow
description: Rules for deploying Mac-Health-Check via Jamf Pro, Self Service policies, LaunchDaemon, and packaging. Emphasizes version alignment, testing discipline, and safe release practices.
applyTo: "**/*.{zsh,md,yml,yaml}"
---

# Deployment Flow Instructions

**Priority Order**: 1. Version Alignment → 2. Testing & Regression → 3. Release Safety → 4. Failure Handling

## 1. Version Alignment (Non-Negotiable)

- `scriptVersion` variable inside `Mac-Health-Check.zsh` **must** exactly match the content of `VERSION.txt` before any release or deployment.
- **If `scriptVersion` and `VERSION.txt` are not updated together**:
  - **Halt the release process immediately.**
  - Log a clear error: `"Version mismatch: scriptVersion and VERSION.txt are out of sync. Fix before proceeding."`
  - Notify the responsible team (via comment or commit message).
- Update `CHANGELOG.md` with every version change.

## 2. Testing & Full Regression (Required After Any Change)

**Definition of "Full Regression"**:
After any code change, you **must** validate the following in **both Self Service and Silent modes**:

1. Syntax check: `zsh -n Mac-Health-Check.zsh` (zero errors + review warnings)
2. Development mode test: `./Mac-Health-Check.zsh --mode Development`
3. Self Service mode: Full run with UI, verify all health checks complete successfully
4. Silent mode: Full run with no UI, verify JSON report + Inspect Summary artifacts are generated correctly
5. Cache replay test (if applicable): Confirm `inspectReplayMaximumAgeSeconds` behavior works as expected
6. Error handling: Trigger at least one failure path and confirm graceful degradation + logging

**If testing in Development mode fails**:
- Document the exact error
- Fix the root cause
- Re-run the full regression before proceeding

## 3. Release Safety Rules

- Never modify `Resources/` without explicit approval.
- Never leak Debug or Development mode behavior into production paths.
- Always align `scriptVersion`, `VERSION.txt`, and `CHANGELOG.md` together.
- Test on a clean macOS system (or VM) before promoting to production Jamf policy.

## 4. Error Handling During Deployment

- **Version mismatch**: Halt release (see Section 1).
- **Test failure**: Do not proceed to production. Fix, re-test, and document the resolution.
- **Silent mode artifact failure**: Treat as critical — the JSON and Inspect plist must always be generated even if the main run encounters issues.
- **LaunchDaemon or packaging issues**: Revert changes and notify the team.

## 5. Post-Edit / Pre-Release Checklist

- [ ] `scriptVersion` == content of `VERSION.txt`
- [ ] Full regression passed in both Self Service and Silent modes
- [ ] No Debug/Development strings or behavior in production code paths
- [ ] `CHANGELOG.md` updated
- [ ] Tested with `zsh -n` (zero errors)

**Reference**: See `AGENTS.md` for release checklist and `zsh-coding.instructions.md` for mode-specific rules.