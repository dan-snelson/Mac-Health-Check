# AGENTS.md

Guidance for coding agents working in this repository.

## Project Context

- Project: Mac Health Check
- Primary artifact: `Mac-Health-Check.zsh`
- Current release objective: ship the official `3.0.0` release (promote from `3.0.0rc*` to production-ready documentation and behavior)
- Reference plan: `Resources/projectPlan.md`

## Mission

Mac Health Check should provide clear, actionable device health and compliance information to end-users in MDM Self Service, while remaining MDM-agnostic and easy for IT teams to extend.

## Product Boundaries

### In Scope

- macOS health/compliance reporting and guidance
- swiftDialog-based user experience
- logging and optional webhook notifications
- modular checks and organization-specific customization

### Out of Scope

- non-macOS support
- automatic remediation/enforcement as a primary behavior
- replacing MDM/EDR platforms

## Implementation Priorities

1. Preserve MDM-agnostic behavior.
2. Keep user-facing output clear and remediation-focused.
3. Favor safe, incremental changes in the main script.
4. Maintain compatibility with recent macOS versions and common MDM workflows.
5. Keep documentation in sync with actual behavior.

## Key Files

- `Mac-Health-Check.zsh`: main script and check logic
- `README.md`: user/admin guidance and configuration details
- `CHANGELOG.md`: release notes and version history
- `VERSION.txt`: canonical version marker
- `Resources/projectPlan.md`: architecture, constraints, and rollout plan
- `external-checks/`: optional integration checks

## Scripting Style (Required)

Maintain the established style of `Mac-Health-Check.zsh` unless the user explicitly asks for a different style.

- Keep sectioned structure and visual separators (`####################################################################################################` and `# # # ...`) for major script regions.
- Keep function naming and declaration style (`function checkXxx() { ... }`, `function updateScriptLog() { ... }`) with descriptive verb-based names.
- Continue using lower camelCase variable names for script globals and `local` variables inside functions.
- Prefer `"${var}"` style expansion and explicit quoting consistent with existing script patterns.
- Route operational logging through helper wrappers (`preFlight`, `notice`, `info`, `warning`, `errorOut`, `fatal`) instead of ad-hoc logging.
- Preserve the existing health-check function pattern: set `humanReadableCheckName`, `notice` the check start, perform initial `dialogUpdate` calls (icon/listitem/progress/progresstext), run the check logic, then emit status-specific `dialogUpdate` output plus matching log call.
- Keep user-facing remediation text concise, direct, and action-oriented in list item subtitles.
- Preserve the script's existing comment voice and contributor-attribution style in section headers/history updates.

## Quality Bar

- Pre-flight behavior must remain reliable (root, dependency, and environment checks).
- Dialog JSON generation must stay valid and resilient.
- Health checks should fail safely: warnings where possible, fatal only when required.
- Logging should remain structured and useful for troubleshooting.
- User guidance should explain what failed and what to do next.

## Required Validation

1. Run `zsh -n` on modified Zsh scripts (required).
2. Review for obvious regressions in operation modes (`Self Service`, `Silent`, `Debug`, `Test`, `Development` where applicable).
3. Update docs/changelog when behavior or configuration changes.
4. Do not add new production dependencies without explicit user confirmation.

## 3.0.0 Release Checklist

1. Set `VERSION.txt` to `3.0.0`.
2. Ensure `CHANGELOG.md` has accurate `3.0.0` final-release notes and date.
3. Remove or update stale release-candidate references in docs.
4. Confirm README content matches current script behavior and parameters.
5. Verify no debug/development-only defaults leaked into production paths.
6. Verify major user-facing checks and remediation messages are coherent.

## Change Discipline

- Prefer minimal, targeted edits over broad rewrites.
- Keep naming and style consistent with existing script conventions.
- Avoid introducing hidden behavior changes when refactoring.
- If behavior changes, document it in `CHANGELOG.md` and relevant docs.
