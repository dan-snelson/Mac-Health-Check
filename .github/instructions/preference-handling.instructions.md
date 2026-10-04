---
name: Preference & Organization Handling
description: Rules for organization variables, script parameters, reporting secrets, MDM vendor detection, branding, and support text in Mac-Health-Check.zsh. Emphasizes graceful degradation and MDM independence.
applyTo: "Mac-Health-Check.zsh"
---

# Preference & Organization Handling Instructions

`AGENTS.md` takes precedence. When this file and `Mac-Health-Check.zsh` disagree, the script wins.

**Core Principle**: Organization-specific values must be easy to find, safe when empty, and never break MDM-agnostic behavior.

## 1. Organization Variables and Parameters

- Keep organization values in the existing configuration sections (Script Parameters, **Organization Variables**, and the support/help-message variables), not inside functions. Comment each one.
- Parameters: 4 `operationMode`, 5 webhook URL, 6 `splunkOperationMode` (`off` | `test` | `production`), 7 HEC URL, 8 HEC token, 9 index, 10 sourcetype, 11 force fresh run.
- `reverseDomainNameNotation` drives root-only state in `/Library/Management/<RDNN>/` (report, secrets, client-side copy) and user-readable Inspect assets in `/Library/Application Support/<RDNN>/Inspect/`.
- Color scheme follows the logged-in user's appearance (`organizationColorScheme`: light `#18181B/#4D4D56`, dark `#D1D5DC/#F5F5F5`).
- Never hardcode secrets, tokens, or real organization data in new code or docs; use placeholders.

## 2. Reporting Secrets

- The webhook URL and Splunk HEC token belong in root-only `MacHealthCheck-Secrets.plist` (`reportingSecretsPath`, root:wheel, mode 600).
- Values passed through Parameters 5 or 8 are rejected unless `allowParameterSecrets="true"` (not recommended); keep that log wording intact.

## 3. MDM Vendor Detection

- Detection is runtime-only: the enrolled `ServerURL` from `profiles list` is matched in `case "${serverURL}" in` (Addigy, Filewave, Fleet, Jamf Pro, JumpCloud, Kandji, Microsoft Intune, Mosyle). No match sets `mdmVendor="None"`.
- Each vendor sets `mdmVendorUuid` or `mdmProfileIdentifier` for the MDM Profile check. Jamf Pro additionally requires `/private/var/log/jamf.log`.
- An unknown vendor logs `warning "Unknown MDM vendor: ${mdmVendor}"`, merges `genericMdmListitemJSON`, and continues.
- Health checks, JSON reporting, Splunk, and Inspect Summary must work with the generic list. Keep vendor-specific code inside vendor `case` branches or vendor-owned functions.
- When vendor branches, list-item arrays, or vendor-owned functions change, keep `Skills/mac-health-check-selector/` in sync (see `AGENTS.md`).

## 4. Support Contact & User-Facing Text

- `supportLabel1`/`supportValue1` through `supportLabel6`/`supportValue6` are read in a loop; a pair shows only when both values are non-empty.
- Legacy `supportTeamPhone`, `supportTeamEmail`, `supportTeamWebsite`, and `supportKBURL` are used only when every dynamic label and value is empty.
- The first URL-like dynamic value (`http(s)://`, `slack://`, `msteams://`, `teams://`, `zoommtg://`, `mailto:`) becomes the info button.
- Keep remediation subtitles concise and action-oriented.

## 5. Post-Edit Checklist

- `zsh -n Mac-Health-Check.zsh`.
- Empty support pairs are skipped; an all-empty set falls back to the legacy fields.
- An unenrolled Mac (or unknown `serverURL`) logs `Unknown MDM vendor: None` and runs the generic list.
- No secrets or organization-specific values added.

**Reference**: `AGENTS.md` for boundaries; `zsh-coding.instructions.md` for naming and logging.
