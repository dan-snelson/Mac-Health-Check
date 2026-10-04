---
name: Mac Health Check Zsh Conventions
description: File-specific rules for editing Mac-Health-Check.zsh. Covers syntax validation, mode isolation, the real health-check lifecycle, result recording, logging, and JSON safety.
applyTo: "Mac-Health-Check.zsh"
---

# Mac-Health-Check.zsh Instructions

`AGENTS.md` is the single source of truth and takes precedence over this file. When this file and `Mac-Health-Check.zsh` disagree, the script wins.

## 1. Non-Negotiable Rules

### 1.1 Syntax Validation
- After **every** edit, run `zsh -n Mac-Health-Check.zsh`. The edit is not complete until it returns zero errors.

### 1.2 Mode Isolation
- Never leak `Debug` or `Development` behavior into `Self Service` or `Silent`.
- Five modes, set by Parameter 4 (`operationMode`): `Self Service` (default), `Silent`, `Debug`, `Development`, `Test`. There is no `--mode` flag.
- `dialogUpdate` is safe to call in every mode. It records list-item results first, then writes to the swiftDialog command file only when `operationMode` is not `Silent`. Do **not** wrap result-bearing `dialogUpdate "listitem: …"` calls in a `Silent` guard; that drops the result from the JSON report, Splunk, and Inspect Summary.
- Guard UI-only work that is not a `dialogUpdate` (launching swiftDialog, Dock badges, countdowns) with `[[ "${operationMode}" != "Silent" ]]`.
- `anticipationDuration` is already `0` in `Silent`, so the `sleep` calls in the check template cost nothing there.

## 2. Core Conventions
- Health checks are `function checkXxx() { … }`; helpers use descriptive lower camelCase verbs.
- Quote expansions: `"${var}"`. Prefer `local` variables.
- Log only through `preFlight`, `notice`, `info`, `warning`, `errorOut`, and `fatal`. `warning` increments `errorCount`. `fatal` logs and **exits immediately** (`exit 1`); reserve it for pre-flight conditions the script cannot survive.
- Validate generated JSON with `validateJson` before use.
- Each MDM has a list-item array (`addigyMdmListitemJSON`, `filewaveMdmListitemJSON`, `fleetMdmListitemJSON`, `jamfProListitemJSON`, `jumpcloudMdmListitemJSON`, `kandjiMdmListitemJSON`, `microsoftMdmListitemJSON`, `mosyleListitemJSON`, `genericMdmListitemJSON`) and a matching branch of `runConfiguredHealthCheck` calls. `Development` uses `developmentListitemJSON` and direct calls.

## 3. Health Check Lifecycle (copied from `checkSIP`)

```zsh
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check New Feature Name
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkNewFeatureName() {

    local humanReadableCheckName="New Feature Name"
    local footerStatusColor="${statusColorSuccess}"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=checkmark.shield.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    if [[ compliant-condition ]]; then
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
        info "${humanReadableCheckName}: Enabled"
    else
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
        footerStatusColor="${statusColorFail}"
        errorOut "${humanReadableCheckName} (${1})"
        overallHealth+="${humanReadableCheckName}; "
    fi

    dialogUpdate "icon: SF=checkmark.shield.fill,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}
```

- `dialogUpdate` takes **one** string argument (`"icon: …"`, `"listitem: …"`, `"progress: …"`, `"progresstext: …"`).
- `${1}` is the list-item index. A terminal `listitem` status (`success`, `fail`, or `error`) calls `recordHealthCheckResult "${index}" "${dialogCommand}"`, which stores the status, `statustext`, and `subtitle` (remediation) for the report.
- Report status mapping: `success` → `healthy`, `fail` → `fail`, `error` → `warning`. Use `status: error` with `colour=${statusColorError}` and `warning` logging for warning-level findings (see `checkOS` and `checkExternalJamfPro`).
- A check that skips its `dialogUpdate` calls in some modes (for example `checkClockSkew` in `Silent`/`Test`) must call `recordHealthCheckResult "${1}" "${listitemCommand}"` itself.
- `overallHealth` is rebuilt from recorded results at exit; the `overallHealth+=` line keeps the in-run log consistent.

**Caller** (in each MDM branch): `runConfiguredHealthCheck "N" checkNewFeatureName`. `N` is the zero-based row index in that MDM's array, and the row icon is `SF=` (N+1, zero-padded) `.circle`. Extra arguments follow the function name, for example `runConfiguredHealthCheck "12" checkUserDirectorySizeItems "Desktop" "desktopcomputer.and.macbook" "Desktop"`. `runConfiguredHealthCheck` handles targeted rechecks and records a `Verification Error` when a targeted check records nothing.

## 4. Error Handling
- Fail health checks safely with `fail` or `error` list-item statuses; never `fatal` inside a check.
- `Silent` writes the JSON report and Inspect Summary assets without UI; asset-write failures log a `warning` and continue.
- Invalid Inspect replay cache → `info`/`warning` and a full run (the cache is not deleted).

## 5. After Editing
- `zsh -n Mac-Health-Check.zsh`, then `sudo zsh ./Mac-Health-Check.zsh "" "" "" "Development"`, then review every affected mode: `Self Service`, `Silent`, `Debug`, `Development`, `Test`.
- Adding or reordering a check: update every affected MDM array and branch, check `developmentListitemJSON`, and keep `Skills/mac-health-check-selector/` in sync (see `AGENTS.md`).
- Ask before modifying `Resources/`, defaults, check ordering, or release markers.
