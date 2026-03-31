# AGENTS.md

Guidance for coding agents working in this repository.

## Project Context

- Project: Mac Health Check
- Primary artifact: `Mac-Health-Check.zsh`
- Current repository version markers: `3.2.0` in `VERSION.txt` and `scriptVersion`
- Current objective: maintain and improve the production `3.2.x` release line while keeping behavior, docs, diagrams, and packaging resources aligned
- Historical reference plan: `Resources/projectPlan.md` documents the 3.0.0 rollout and architecture intent, but it lags the current implementation in places

## Source of Truth

When files disagree, use this order:

1. `Mac-Health-Check.zsh` for implemented behavior, defaults, and supported operation modes.
2. `README.md`, `CHANGELOG.md`, and `Diagrams/` for current release documentation.
3. `VERSION.txt` for the canonical release marker.
4. `Resources/projectPlan.md` for historical product and architecture context, not current runtime truth.

## Mission

Mac Health Check should provide clear, actionable device health and compliance information to end-users in MDM Self Service, while remaining MDM-agnostic and easy for IT teams to extend.

## Product Boundaries

### In Scope

- macOS health/compliance reporting and guidance
- swiftDialog-based user experience
- logging and optional webhook notifications
- modular checks and organization-specific customization
- packaging and deployment helpers that ship or wrap the main script

### Out of Scope

- non-macOS support
- automatic remediation/enforcement as a primary behavior
- replacing MDM/EDR platforms

## Implementation Priorities

1. Preserve MDM-agnostic behavior in the core flow, while keeping Jamf-specific integrations isolated and clearly intentional.
2. Keep user-facing output clear and remediation-focused across `Self Service`, `Silent`, `Debug`, `Development`, and `Test`.
3. Favor safe, incremental changes in `Mac-Health-Check.zsh` and related helper resources.
4. Maintain compatibility with recent macOS versions, swiftDialog, and common MDM workflows.
5. Keep documentation, diagrams, and version markers synchronized with actual behavior.

## Key Files

- `Mac-Health-Check.zsh`: main script, health-check logic, operation-mode branching, and release history
- `README.md`: current user/admin guidance, supported checks, and operation-mode behavior
- `CHANGELOG.md`: release notes and shipped behavior summary
- `VERSION.txt`: canonical version marker
- `Diagrams/`: execution flow, operation-mode, deployment, and health-check reference docs
- `Resources/projectPlan.md`: historical 3.0.0 planning context
- `Resources/README.md`, `Resources/Makefile`, `Resources/createSelfExtracting.zsh`, `.deployMacHealthCheck.zsh`: packaging and distribution helpers
- `external-checks/README.md` and `external-checks/`: optional integration checks and examples

## Repository Notes

- Some supporting docs still carry `3.0.0` headings or metadata. Treat those as documentation debt unless the task is explicitly historical.
- Tracked release artifacts exist under `Resources/`; do not rebuild or replace them unless the task specifically calls for a release/package refresh.
- Check `git status` before editing shared docs or assets so you do not overwrite unrelated local work.

## Scripting Style (Required)

Maintain the established style of `Mac-Health-Check.zsh` unless the user explicitly asks for a different style.

- Keep the sectioned structure and visual separators (`####################################################################################################` and `# # # ...`) for major script regions.
- Keep function naming and declaration style (`function checkXxx() { ... }`, `function updateScriptLog() { ... }`) with descriptive verb-based names.
- Continue using lower camelCase variable names for script globals and `local` variables inside functions.
- Prefer `"${var}"` style expansion and explicit quoting consistent with existing script patterns.
- Route operational logging through helper wrappers (`preFlight`, `notice`, `info`, `warning`, `errorOut`, `fatal`) instead of ad-hoc logging.
- Preserve the existing health-check function pattern: set `humanReadableCheckName`, `notice` the check start, perform initial `dialogUpdate` calls (icon/listitem/progress/progresstext), run the check logic, then emit status-specific `dialogUpdate` output plus matching log call.
- Keep mode-specific guards explicit: UI-only behaviors must stay out of `Silent`, while logging and non-UI checks must still work there.
- When changing health-check ordering or list items, review both the primary dialog JSON and the curated `Development` mode subset.
- Keep user-facing remediation text concise, direct, and action-oriented in list item subtitles.
- Preserve the script's existing comment voice and contributor-attribution style in section headers and history updates.

## Mode-Specific Expectations

- `Self Service` is the default production mode.
- `Silent` runs checks and logging without launching the main dialog or non-essential UI follow-up such as persistent failure notifications.
- `Debug` enables verbose troubleshooting behavior and should remain obviously non-production.
- `Development` intentionally runs a curated subset of checks and list items for faster iteration.
- `Test` is a special validation path and should not accidentally become the default or leak test-only behavior into production runs.

## Quality Bar

- Pre-flight behavior must remain reliable (root, dependency, and environment checks).
- Dialog JSON generation must stay valid and resilient.
- Health checks should fail safely: warnings where possible, fatal only when required.
- Failure notifications and Dock integration should degrade gracefully and must not break `Silent` mode.
- Jamf-specific inventory or external-check paths must not regress non-Jamf vendors.
- Logging should remain structured and useful for troubleshooting.
- User guidance should explain what failed and what to do next.

## Required Validation

1. Run `zsh -n` on modified Zsh scripts (required).
2. Review for obvious regressions in every operation mode touched by the change: `Self Service`, `Silent`, `Debug`, `Development`, and `Test`.
3. Update `README.md`, `CHANGELOG.md`, `Diagrams/`, and other affected docs when behavior, configuration, screenshots, or check inventory changes.
4. Keep `VERSION.txt`, `scriptVersion`, and release notes aligned when making release-affecting changes.
5. When touching packaging or deployment helpers, verify the related documentation in `Resources/README.md` and any intentionally tracked release artifacts.
6. Do not add new production dependencies without explicit user confirmation.

## Release Alignment Checklist

1. Keep `scriptVersion` and `VERSION.txt` aligned.
2. Ensure the top `CHANGELOG.md` entry reflects the shipped behavior and correct date.
3. Confirm `README.md` matches current defaults, supported operation modes, and user-facing checks.
4. Refresh relevant `Diagrams/*.md` references when execution flow, deployment flow, or check inventory changes.
5. Remove or clarify stale version references when they could mislead contributors.
6. Verify no debug- or development-only defaults leaked into production paths.

## Change Discipline

- Prefer minimal, targeted edits over broad rewrites.
- Keep naming and style consistent with existing script conventions.
- Avoid introducing hidden behavior changes when refactoring.
- If behavior changes, document it in `CHANGELOG.md` and the relevant docs.
