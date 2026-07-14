---
name: Preference & Organization Handling
description: Rules for managing organization variables, MDM detection, branding, and user-facing text in Mac-Health-Check. Emphasizes clarity, graceful degradation, and MDM independence.
applyTo: "Mac-Health-Check.zsh"
---

# Preference & Organization Handling Instructions

**Core Principle**: Organization-specific values and MDM detection must be flexible, clearly documented, and never break the script when values are missing or unknown.

## 1. Organization Variables

- All organization-specific values (branding, colors, support contacts, thresholds, etc.) **must** be defined at the top of the script with clear comments.
- Use descriptive variable names (e.g., `organizationColorScheme`, `supportTeamName`, `allowedMinimumFreeDiskPercentage`).
- **Empty or invalid values**: 
  - For support contact pairs (`supportLabel1`/`supportValue1` through `supportLabel6`/`supportValue6`): **gracefully skip** any pair where either value is empty.
  - For thresholds and colors: Fall back to safe defaults (e.g., 10% disk space, system appearance-based color scheme).
  - Never hardcode secrets or sensitive data.

## 2. MDM Vendor Detection (Dynamic & Agnostic)

**Definition of Terms**:
- **Dynamic**: Detection occurs at runtime by querying the system (`profiles list`, `mdmVendorUuid`, etc.). It is **not** hardcoded at the top of the script.
- **MDM-agnostic**: The core health checks, reporting, and UI logic work independently of any specific MDM. Vendor-specific code is strictly optional and isolated.

**Rules**:
- Detection must use runtime commands (never static lists).
- Core functionality (health checks, JSON reporting, Inspect Summary) **must work** even if no MDM is detected.
- When an unknown or unsupported MDM is detected:
  - Log a clear warning: `"Unsupported MDM vendor detected: <vendor>. Falling back to generic behavior."`
  - Use the `genericMdmListitemJSON` list.
  - Continue execution without crashing.

## 3. Support Contact & User-Facing Text

- Dynamic support fields (`supportLabel1`–`supportLabel6`) must be processed in a loop that skips empty pairs.
- Legacy fallback fields (Telephone, Email, Website, KB Article) are only used if the dynamic fields are completely empty.
- All user-facing text (help message, remediation guidance, footer) must be constructed dynamically from available variables.

## 4. Error Handling

- **Missing or empty organization values**: Skip gracefully (especially support contacts). Never crash.
- **Unknown MDM vendor**: Log warning + fall back to generic list + continue.
- **Invalid color scheme or threshold values**: Apply safe defaults and log a warning.
- **Branding image failures** (missing icon path): Fall back to default swiftDialog icon.

## 5. Post-Edit Checklist

- Confirm support contact pairs are skipped when empty.
- Test with no MDM profile installed (should use generic list).
- Verify unknown MDM vendor produces a warning but does not break execution.
- Ensure all organization variables have clear comments explaining their purpose.

**Reference**: See `AGENTS.md` for boundaries and `zsh-coding.instructions.md` for variable naming conventions.