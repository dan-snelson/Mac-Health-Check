# AGENTS.md

**Single source of truth for coding agents** (Claude Code, Cursor, Copilot, Aider, etc.).  
Takes precedence over `README.md`, `CLAUDE.md`, and similar instruction files.  
Claude Code loads it through the tracked one-line `CLAUDE.md` (`@AGENTS.md`); keep rules here, not there.

## Orchestration Contract
This file codifies project rules, boundaries, workflows, and repeatable skills. If same correction repeats, formalize it here instead of re-prompting it.

## Project Overview
macOS health and compliance reporting tool. Primary artifact: `Mac-Health-Check.zsh` (zsh + swiftDialog). Core flow stays MDM-agnostic; Jamf integration remains optional and isolated. Supported modes: **Self Service** (default production), **Silent**, **Debug**, **Development**, **Test**.

## Key Commands
- Validate syntax after **every** script edit: `zsh -n Mac-Health-Check.zsh`
- Fast iteration: `sudo zsh --no-rcs ./Mac-Health-Check.zsh "" "" "" "Development"` (Parameter 4 sets `operationMode`; no `--mode` flag)
- Full regression before release work or cross-mode changes: test `Self Service`, `Silent`, `Debug`, `Development`, and `Test`
- View canonical version: `grep -m1 '^scriptVersion=' Mac-Health-Check.zsh` (`VERSION.txt` is a git-ignored local mirror)

## Agent Workflow
- Start non-trivial changes in Plan mode or equivalent.
- In Plan mode, make no changes and propose no code until confidence is at least 95%; ask follow-up questions until then.
- Default user-facing communication mode: `$caveman full` (optional terse-reply skill, not shipped in this repo; ignore if unavailable), except for security warnings, irreversible actions, or clear user confusion.
- Treat context like a scalpel, not a net; provide only files, lines, and examples needed.
- Use surgical edits; reference exact functions, ranges, or list-item IDs instead of pasting large sections.
- After any edit to `Mac-Health-Check.zsh`, run `zsh -n` immediately, then validate all affected modes.
- Confirm this file is loaded before starting a session.
- Prefer batching related work into one well-scoped prompt.
- Never leak Debug or Development behavior into `Self Service` or `Silent`.
- Use codified Skills when they fit instead of re-describing the workflow.

## Skills
Invoke relevant skill name during planning.

### Add New Health Check Skill
1. Plan from nearby check template, including `humanReadableCheckName`, `dialogUpdate` calls, logging, and success/fail flow.
2. Implement only in `Mac-Health-Check.zsh`.
3. Update every affected MDM list-item array and matching `runConfiguredHealthCheck` call; add to curated Development subset (`developmentListitemJSON`) only when check belongs in fast iteration.
4. Update selector skill: `Skills/mac-health-check-selector/references/health-checks.md` (master table, templates) plus check ID map, owners, and `--list` output in `scripts/build-artifact.zsh`; unknown title makes every build exit `2`.
5. Validate in `Self Service`, `Silent`, `Debug`, `Development`, and `Test`.
6. Document change in `README.md` and `CHANGELOG.md`.

### Refactoring / Style Update Skill
1. Identify every required location with grep or equivalent.
2. Make minimal surgical edits only.
3. Run `zsh -n` immediately after edit.
4. Validate all affected modes.
5. Do not leak Debug or Development behavior into production paths.

### Release Preparation Skill
1. Confirm `scriptVersion`, `VERSION.txt`, and `CHANGELOG.md` stay aligned.
2. Update only files explicitly in scope.
3. Run full regression across all five modes.
4. Do not modify `Resources/` artifacts unless task is packaging refresh.

### Mac Health Check Selector Skill
1. Use `Skills/mac-health-check-selector/SKILL.md` when admin wants to choose, enable, or disable checks; ask MDM first.
2. Write MDM-specific, date-stamped copy plus sidecar `.md` to git-ignored `Artifacts/` per `references/artifact-procedure.md`; never edit source script.
3. Keep `Skills/mac-health-check-selector/SKILL.md`, `.../references/health-checks.md`, `.../references/artifact-procedure.md`, `.../scripts/build-artifact.zsh`, and `Artifacts/README.md` synchronized when checks, titles, arguments, MDM order, anchors, vendor `case` blocks, vendor-owned functions, `developmentListitemJSON`, external-check result parsing, or Client-Side Cache sanitizer change.

## Boundaries
**Always allowed without asking**
- Read any repository file.
- Run `zsh -n`, syntax checks, and single-mode tests.
- Make small targeted edits that follow rules below.

**Ask before doing**
- Modify packaging helpers or demo assets under `Resources/`.
- Add production dependencies or external checks.
- Change check ordering or primary dialog JSON structure.
- Change default operation mode, exit-code semantics, or logging/output contracts.
- Update `VERSION.txt` or prepare release.

**Never do**
- Hardcode secrets, API keys, organization-specific data, or credentials.
- Modify files outside current task scope without approval.
- Leak Debug or Development behavior into `Self Service` or `Silent`.
- Break MDM-agnostic behavior.

## Source of Truth
When files disagree, prefer:
1. `Mac-Health-Check.zsh` for implemented behavior, defaults, and supported modes.
2. `README.md`, `CHANGELOG.md`, and `Diagrams/` for current release documentation.
3. `scriptVersion` for canonical release marker (`VERSION.txt` is a git-ignored local mirror).
4. `Resources/projectPlan.md` for historical architecture context, not runtime truth.

## Mission and Scope
Mission: provide clear, actionable health and compliance guidance to end users in MDM Self Service while staying MDM-agnostic and easy for IT teams to extend.

In scope:
- macOS health and compliance reporting
- swiftDialog user experience
- logging and optional webhook notifications
- modular checks and organization-specific customization
- packaging and deployment helpers that ship or wrap main script

Out of scope:
- non-macOS support
- automatic remediation or enforcement as primary behavior
- replacing MDM or EDR platforms

## Implementation Priorities
1. Preserve MDM-agnostic core flow; keep Jamf-specific integrations isolated and intentional.
2. Keep user-facing output clear and remediation-focused across all five modes.
3. Favor safe incremental changes in `Mac-Health-Check.zsh` and related helpers.
4. Maintain compatibility with recent macOS versions, swiftDialog, and common MDM workflows.
5. Keep docs, diagrams, and version markers synchronized with actual behavior.

## Key Files
- `Mac-Health-Check.zsh`: main script, checks, mode branching, release history
- `README.md`, `CHANGELOG.md`, `Diagrams/`: current guidance, release notes, architecture references; `VERSION.txt` (git-ignored, local)
- `Resources/projectPlan.md`: historical 3.0.0 context only (its `3.0.0` headings are intentional); `Resources/README.md`, `Resources/Makefile`, `Resources/postInstall.zsh`, `Resources/createSelfExtracting.zsh`: packaging and distribution helpers; `.deployMacHealthCheck.zsh` is a git-ignored local release helper
- `external-checks/README.md` and `external-checks/`: optional integrations and examples

## Current Runtime Hotspots
- Inspect Summary is now primary post-run UX: with `inspectSummaryPreset="on"`, `Self Service` generates Preset 6 assets and launches detached summary; `Silent` writes same assets without launching swiftDialog.
- `Silent` plus `splunkOperationMode=production` is reporting-first: suppress non-Splunk console output, skip `jamf recon`, and treat success as local report generation plus HEC delivery succeeding.
- Client-Side Cache installs sanitized local copy at `/Library/Management/org.churchofjesuschrist/MHC.zsh`, rewrites default mode to `Silent`, and removes Jamf inventory submission from that cached path; installs only from a root-owned script in root-controlled directories (sticky `/var/tmp` parents allowed, so self-extracting wrappers qualify) in `Self Service`, `Debug`, or `Silent` + `production` (never `Test`/`Development`), before the cached-upload shortcut, and refuses a copy failing `zsh -n` or lacking the `Silent` default; its nightly LaunchDaemon run never sends webhooks.
- `Development` is intentionally curated, not representative of full suite; when changing checks or list items, verify whether `developmentListitemJSON` also needs update.

## Repository Rules
- `scriptVersion` and top `CHANGELOG.md` entry are release-state truth, not branch names.
- Keep local `VERSION.txt` (git-ignored) aligned with `scriptVersion`.
- `5.0.0` requires swiftDialog `3.1.1.4997` or newer (`swiftDialogMinimumRequiredVersion`); treat older version references as documentation debt unless task is explicitly historical.
- Check `git status` before editing shared docs or assets so unrelated local work is not overwritten.
- No built release artifacts are tracked under `Resources/` (`Resources/*.pkg` and `*_self-extracting-*.sh` are git-ignored); tracked demo assets and reference files there change only for explicit packaging or documentation refreshes.
- Prefer minimal targeted edits over broad rewrites.
- Keep naming and style consistent with existing script conventions.
- Avoid hidden behavior changes during refactors.
- If behavior changes, document it in `CHANGELOG.md` and relevant docs.
- Do not add new production dependencies without explicit approval.

## Scripting Style
These rules override ad-hoc prompting. Match established `Mac-Health-Check.zsh` style unless user explicitly asks otherwise.

1. Preserve sectioned structure and visual separators (`####################################################################################################` and `# # # ...`).
2. Keep descriptive verb-based function naming and declaration style such as `function checkXxx() { ... }` and `function updateScriptLog() { ... }`.
3. Use lower camelCase for globals and `local` variables.
4. Prefer `"${var}"` expansion and explicit quoting consistent with existing script patterns.
5. Route operational logging through `preFlight`, `notice`, `info`, `warning`, `errorOut`, and `fatal`.
6. Preserve health-check lifecycle:
   ```zsh
   function checkXxx() {
       local humanReadableCheckName="Human Readable Name"
       local footerStatusColor="${statusColorSuccess}"
       notice "Check ${humanReadableCheckName} …"
       dialogUpdate "icon: SF=checkmark.shield.fill,${organizationColorScheme}"
       dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
       dialogUpdate "progress: increment"
       dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"
       # --- check logic here ---
       if [[ condition ]]; then
           dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
           info "${humanReadableCheckName}: Enabled"
       else
           dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
           footerStatusColor="${statusColorFail}"
           errorOut "${humanReadableCheckName} (${1})"
           overallHealth+="${humanReadableCheckName}; "
       fi
       dialogUpdate "icon: SF=checkmark.shield.fill,weight=semibold,colour=${footerStatusColor}"
   }
   ```
   `dialogUpdate` takes one string and runs in every mode (it records report results; it only skips the swiftDialog write in `Silent`). Call checks through `runConfiguredHealthCheck "N" checkXxx` so targeted rechecks map indices.
   Use nearby checks as template for local vars, icons, inspect metadata, early returns, and warning-vs-fail handling.
7. Keep mode guards explicit: UI-only behavior stays out of `Silent`, while logging and non-UI checks still run there.
8. When changing check ordering or list items, review both primary dialog JSON and curated Development subset.
9. Keep remediation text concise, direct, and action-oriented in list item subtitles.
10. Preserve existing comment voice and contributor-attribution style in section headers and history updates.
Zsh and swiftDialog specifics:
- Dialog JSON must stay valid.
- Icon and asset paths must resolve in both `Self Service` and `Silent`.
- Prefer `local` variables and minimize globals.
- Keep user-facing strings concise and action-oriented.
- Use `set -euo pipefail` safety only when compatible with existing error handling.

## Mode Expectations
- `Self Service` is default production mode.
- `Silent` runs checks and logging without main dialog or non-essential UI follow-up such as detached inspect summaries; with `splunkOperationMode=production`, it is reporting-first and treats report delivery success as success even when findings exist.
- `Debug` stays obviously non-production and enables verbose troubleshooting; `Development` runs curated subset for fast iteration; `Test` is validation-only and must never become default or leak into production.

## Quality Bar
- Keep pre-flight behavior reliable across root, dependency, and environment checks.
- Keep dialog JSON generation valid and resilient; health checks should fail safely, using warning where possible and fatal only when required.
- Detached inspect summaries and Dock integration must degrade gracefully and never break `Silent`; Jamf-specific inventory and external-check paths must not regress non-Jamf vendors.
- Logging must stay structured and useful; user guidance must explain failure and next action.

## Required Validation
1. Run `zsh -n` on every modified Zsh script.
2. For script or runtime changes, review obvious regressions in every touched mode: `Self Service`, `Silent`, `Debug`, `Development`, `Test`.
3. For docs, diagrams, or `AGENTS.md`-only changes, review rendered Markdown, terminology, and version or behavior references for cross-file consistency.
4. Update `README.md`, `CHANGELOG.md`, `Diagrams/`, and related docs when behavior, configuration, screenshots, or check inventory changes; keep `VERSION.txt`, `scriptVersion`, and release notes aligned for release-affecting changes.
5. When touching packaging or deployment helpers, verify related docs in `Resources/README.md` and tracked demo assets.
6. Do not add new production dependencies without explicit approval.

## Release Checklist
Apply only for release prep.
1. Keep `scriptVersion` and `VERSION.txt` aligned.
2. Ensure top `CHANGELOG.md` entry matches shipped behavior and correct date.
3. Confirm `README.md` matches current defaults, supported modes, and user-facing checks.
4. Refresh relevant `Diagrams/*.md` references when execution flow, deployment flow, or check inventory changes.
5. Remove or clarify stale version references when they could mislead contributors.
6. Verify no Debug or Development defaults leaked into production paths.

## Maintenance
This file is versioned with project. When core style rules, validation requirements, or boundaries change, update `AGENTS.md` and note change in `CHANGELOG.md` under `Agent Experience` or `Internal`. Keep file near 200 lines for agent attention.
