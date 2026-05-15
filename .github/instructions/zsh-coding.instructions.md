---
name: Mac Health Check Zsh Conventions
description: File-specific rules and concrete templates for VS Code Copilot when editing Mac-Health-Check.zsh. Enforces syntax validation, mode isolation, function templates, logging discipline, and JSON safety with clear prioritization and reduced cognitive load.
applyTo: "Mac-Health-Check.zsh"
---

# Mac-Health-Check.zsh Custom Instructions for VS Code Copilot

**Context Requirement**: Before starting any editing session, ensure `AGENTS.md` is open in the editor **or** referenced in the active workspace so its rules take precedence.

## 1. Highest Priority Rules (Non-Negotiable — Read First)

### 1.1 Syntax Validation (Always First Step)
- **After EVERY edit** to `Mac-Health-Check.zsh`, immediately run `zsh -n Mac-Health-Check.zsh`.
- The edit is **not complete** until this returns **zero errors**.
- **If warnings appear**: Review each warning and confirm it does not affect runtime behavior or Silent mode safety.

### 1.2 Mode Isolation (Critical Safety Rule)
- **Never leak Debug or Development behavior** into Self Service or Silent modes.
- All UI updates and sleeps **MUST** be guarded with: `if [[ "${operationMode}" != "Silent" && "${operationMode}" != "Test" ]]; then ... fi`
- Test in **all five modes** before finishing.

### 1.3 Health Check Function Template (Mandatory)
- Every `check*` function **must** follow the exact template in Section 3.

## 2. Core Conventions
- Use `check` + PascalCase for health checks, lowerCamelCase for helpers.
- Always double-quote variables: `"${var}"`.
- Use only project logging functions (`notice`, `info`, `warning`, `errorOut`, etc.).
- Validate every JSON with `validateJson`.
- Add new checks to the correct `*_MdmListitemJSON` array.

## 3. Health Check Lifecycle Template

```zsh
function checkNewFeatureName() {
    local humanReadableCheckName="New Feature Name"
    local checkIndex="${1}"
    notice "Check ${humanReadableCheckName} …"
    if [[ "${operationMode}" != "Silent" && "${operationMode}" != "Test" ]]; then
        dialogUpdate "listitem: index: ${checkIndex}, status: wait, statustext: Checking …"
    fi
    # === your logic here ===
    local checkStatus="success"
    local statusText="Compliant"
    if [[ failure-condition ]]; then
        checkStatus="fail"
        statusText="Non-compliant: reason"
        overallHealth+="${humanReadableCheckName}; "
        errorOut "${humanReadableCheckName}: ${statusText}"
    else
        info "${humanReadableCheckName}: ${statusText}"
    fi
    if [[ "${operationMode}" != "Silent" && "${operationMode}" != "Test" ]]; then
        dialogUpdate "listitem: index: ${checkIndex}, status: ${checkStatus}, statustext: ${statusText}"
    fi
    recordHealthCheckResult "${checkIndex}" "${checkStatus}" "${statusText}" ""
    sleep $(( anticipationDuration / 2 ))
}
```

**Caller**: `checkNewFeatureName "${checkIndexByTitle[New Feature Name]}"`

## 4. Error Handling
- Pre-flight failures → `fatal` + `quitScript`
- Silent mode → no UI, still generate JSON + Inspect plist
- Cache invalid → fall back + warning
- `zsh -n` warnings → review and address (see 1.1)

## 5. Additional Guidance
- Post-edit: Run `zsh -n` → test Development → full Self Service + Silent regression
- Make **surgical** edits only
- Ask before modifying `Resources/`, defaults, or preparing releases
- Hotspots: Inspect Summary, client-side cache, Splunk, Development mode

**Stop when clear.** Reference `AGENTS.md` for broader rules.