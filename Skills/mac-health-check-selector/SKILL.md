---
name: mac-health-check-selector
description: Interactively prompts a Mac Admin to select which health checks to enable or disable in Mac Health Check (dan-snelson/Mac-Health-Check). Use when customizing MHC list items, health-check functions, operationMode subsets, Development mode curated checks, external checks, or generating a tailored, validated, MDM-specific and date-stamped copy of Mac-Health-Check.zsh in Artifacts/ for Self Service, Silent, Debug, Development or Test modes. Triggers on phrases like "Mac Health Check checks", "which MHC checks", "customize MHC health checks", "select health checks for Mac Health Check", "MHC list items", or any request to choose or configure Mac Health Check compliance checks.
---

# Mac Health Check Selector

Guide a Mac Admin through choosing which Mac Health Check (MHC) health checks to show and run, then write an edited, MDM-specific, date-stamped copy of `Mac-Health-Check.zsh` into `Artifacts/`, plus a sidecar `.md` that records the selection and validation results.

Target: the `5.0.0b1` prerelease line and later. Full per-check data (exact list-item JSON, function arguments, shipped default order per MDM, artifact anchors) lives in `references/health-checks.md`. The write-and-validate procedure lives in `references/artifact-procedure.md`. Read both files before generating output. When it disagrees with the admin's copy of `Mac-Health-Check.zsh`, trust the script.

## Ground rules

- Ask the MDM question first, every time. Do not skip, merge, or bury it.
- Ask one step at a time. Wait for the answer before moving on.
- Use numbered lists and check IDs (such as `C1`, `M5`) so any reply like `C1-C8, H, M4, no A6` can be parsed without ambiguity.
- Be non-destructive. Never edit `Mac-Health-Check.zsh` in place; write only to `Artifacts/`. Never commit or deploy anything.
- Use placeholders for anything organization-specific: `<YOUR_ORG_NAME>`, `<YOUR_WEBHOOK_URL>`, `<YOUR_SPLUNK_HEC_URL>`, `<YOUR_SPLUNK_HEC_TOKEN>`, `<YOUR_POLICY_TRIGGER>`, `<YOUR_ORGANIZATION_NETWORK>`. Never invent real URLs, tokens, or branding.
- Keep user-facing subtitles short and action-oriented.
- Accept "defaults", "same as shipped", or "recommend for me" at any step; pick the shipped default and say so.

## Step 1 — Ask which MDM is in use

Send this question alone and wait:

> Which MDM manages these Macs? Reply with a number or type your own.
>
> 1. Jamf Pro
> 2. Fleet
> 3. JumpCloud
> 4. Microsoft Intune
> 5. Mosyle
> 6. Kandji / Iru
> 7. Addigy
> 8. Other / MDM-agnostic / custom (includes Filewave)

Map the answer to the script's names:

| Answer | `mdmVendor` | List-item array | Case branch label | Artifact slug |
|---|---|---|---|---|
| 1 | `Jamf Pro` | `jamfProListitemJSON` | `"Jamf Pro" )` | `jamf-pro` |
| 2 | `Fleet` | `fleetMdmListitemJSON` | `"Fleet" )` | `fleet` |
| 3 | `JumpCloud` | `jumpcloudMdmListitemJSON` | `"JumpCloud" )` | `jumpcloud` |
| 4 | `Microsoft Intune` | `microsoftMdmListitemJSON` | `"Microsoft Intune" )` | `microsoft-intune` |
| 5 | `Mosyle` | `mosyleListitemJSON` | `"Mosyle" )` | `mosyle` |
| 6 | `Kandji` | `kandjiMdmListitemJSON` | `"Kandji" )` | `kandji` |
| 7 | `Addigy` | `addigyMdmListitemJSON` | `"Addigy" )` | `addigy` |
| 8 (Filewave) | `Filewave` | `filewaveMdmListitemJSON` | `"Filewave" )` | `filewave` |
| 8 (other) | `None` | `genericMdmListitemJSON` | `* )` | `generic` |

MDM-specific notes to carry forward:

- **Jamf Pro** — only MDM with Jamf Pro Check-In, Jamf Pro Inventory, Jamf Hosts, Computer Inventory (`jamf recon`), and `checkExternalJamfPro` external checks. Entra ID Registration and Clock Skew ship in the Jamf Pro list. The script exits early if `/private/var/log/jamf.log` is missing.
- **Mosyle** — adds Mosyle Check-In and the Mosyle Self-Service app check.
- **Fleet / Intune** — add an MDM agent app presence check (Fleet Desktop / Microsoft Company Portal).
- **Kandji / Iru** — detected when `serverURL` contains `kandji`; an Iru-branded URL without that string falls to the generic branch. Ask the admin to confirm their server URL.
- **Addigy** — ships with a blank `mdmVendorUuid`; MDM Profile will not pass until the admin fills it in.
- **Other** — no MDM Profile or MDM Certificate Expiration by default, because no vendor profile or certificate name is known. Offer to add `mdmVendor`, `mdmVendorUuid` or `mdmProfileIdentifier`, and a certificate name if the admin knows them.

## Step 2 — Explain the purpose

After the MDM is known, say in two or three sentences:

> Mac Health Check runs modular checks and shows each one as a row in the swiftDialog window. For <MDM>, each row is defined in `<array name>`, and each row's check runs from a matching `runConfiguredHealthCheck` line in the `"<MDM>"` case branch. We'll pick which checks to keep. Then I'll write an edited copy of the script to `Artifacts/` with both parts in matching order, validate it, and record everything in a sidecar `.md`. Your `Mac-Health-Check.zsh` stays untouched.

## Step 3 — Present the checklist

Show the checklist below. Tailor it to the MDM from Step 1:

- Mark every check in that MDM's shipped default with `[default]` (see **Shipped default order per MDM** in the reference).
- Show `[Jamf Pro only]` items only for Jamf Pro. For other MDMs, list them once under "Not available for <MDM>" so the admin knows why they are missing.
- Mark external checks with `*`.

Ask: "Reply with IDs, ranges, or whole categories to enable (for example `C, H1-H6, M4, M8-M12, A1-A3`). Prefix with `no` to drop something. Or pick a preset in the next step."

**Core OS & Security (C)**
- C1 macOS Version
- C2 Available Updates (deferred, staged, and DDM-enforced)
- C3 System Integrity Protection (SIP)
- C4 Signed System Volume (SSV)
- C5 Firewall
- C6 FileVault Encryption
- C7 Gatekeeper / XProtect
- C8 Touch ID
- C9 Password Hint
- C10 AirDrop
- C11 AirPlay Receiver
- C12 Bluetooth Sharing
- C13 VPN Client

**Maintenance & Hygiene (H)**
- H1 Last Reboot / Uptime
- H2 Free Disk Space
- H3 Desktop Size and Item Count
- H4 Downloads Size and Item Count
- H5 Trash Size and Item Count
- H6 Memory Pressure (warning-only; 14-day JSON Lines history; warns on recurring pressure across 2 distinct days in 7)
- H7 Clock Skew (ships for Jamf Pro; runs on any MDM)

**MDM & Connectivity (M)**
- M1 `<MDM>` MDM Profile
- M2 Entra ID Registration (ships for Jamf Pro; reads Jamf AAD plist and Platform SSO — review before using elsewhere)
- M3 `<MDM>` MDM Certificate Expiration
- M4 Apple Push Notification service (APNs)
- M5 Jamf Pro Check-In `[Jamf Pro only]`
- M6 Jamf Pro Inventory `[Jamf Pro only]`
- M7 Mosyle Check-In `[Mosyle only]`
- M8 Apple Push Notification Hosts
- M9 Apple Device Management
- M10 Apple Software and Carrier Updates
- M11 Apple Certificate Validation
- M12 Apple Identity and Content Services
- M13 Jamf Hosts `[Jamf Pro only]`
- M14 Wi-Fi Strength
- M15 Network Quality Test (slowest check)

**Applications & Tools (A)**
- A1 App Auto-Patch
- A2 Homebrew Status
- A3 Electron Corner Mask
- A4 Organizationally required application (Microsoft Teams by default; ask for others)
- A5 MDM agent app (Fleet Desktop, Microsoft Company Portal, Mosyle Self-Service, or the Kandji app set)
- A6 BeyondTrust Privilege Management* `[Jamf Pro only]`
- A7 Cisco Umbrella* `[Jamf Pro only]`
- A8 CrowdStrike Falcon* `[Jamf Pro only]`
- A9 Palo Alto GlobalProtect* `[Jamf Pro only]`
- A10 Other `external-checks/` script* (Microsoft Defender, Microsoft Office 365, Nessus, Sophos, Splunk Universal Forwarder, Zscaler, printer install, and others) `[Jamf Pro only]`

**Follow-up Actions (F)**
- F1 Update Computer Inventory `[Jamf Pro only; always last]`

`*` = requires an external-check script deployed as a Jamf Pro policy with a custom trigger. On other MDMs, offer A4-style presence checks (`checkInternal`) or a new custom `checkXxx` function instead.

For A4, ask for each required app's path and display name. For A10, ask for the Jamf Pro policy trigger and the app path used for the icon.

## Step 4 — Ask for options

Ask these together as one numbered block. Accept partial answers and fill gaps with defaults.

> 1. **Preset** — pick one, or `Custom` to keep your Step 3 picks:
>    a. Full Self Service (shipped default for your MDM)
>    b. Silent / reporting only
>    c. Development curated subset
>    d. Minimal triage
>    e. Custom
> 2. **operationMode** (Script Parameter 4): `Self Service` (default), `Silent`, `Debug`, `Development`, or `Test`
> 3. **External checks** — include external-check scripts? (yes / no; Jamf Pro only)
> 4. **Targeted remediation verification** — keep automatic targeted rechecks in Self Service (default), or force full runs?

Preset definitions (resolve against the MDM's availability):

- **Full Self Service** — the MDM's shipped default order, unchanged.
- **Silent / reporting only** — Full minus M15 Network Quality Test (slow, uses bandwidth, no user watching). For Jamf Pro, also drop F1: reporting-first Silent skips `jamf recon`, and F1 without M15 breaks the Client-Side Cache copy (see Step 5b).
- **Development curated subset** — only the checks being worked on. Default: H7 Clock Skew, H6 Memory Pressure (the shipped subset). Ask which checks the admin is developing.
- **Minimal triage** — fast Tier 1 set: C1, C2, C5, C6, H1, H2, M1, M4, M14. Add M5 and M6 for Jamf Pro (no F1, because there is no M15), and M7 for Mosyle. Drop M1 for Other.
- **Custom** — exactly the Step 3 selection, reordered to follow the MDM's shipped order. If F1 is picked without M15, warn and ask: keep M15 directly before F1, or drop F1.

Explain operationMode effects when relevant:

- `Self Service`, `Silent`, and `Debug` use the MDM list-item array and case branch.
- `Silent` runs checks and logging with no main dialog and no detached Inspect summary; it still writes the Inspect config and compliance plist.
- `Debug` runs the same checks with `set -x` and a mode label in the title. Keep it out of production policies.
- `Development` ignores the MDM array and uses `developmentListitemJSON` plus direct check calls.
- `Test` uses the MDM array for rows but runs no real checks; every row is marked compliant. Never use it in production.

Explain targeted remediation verification:

- Applies only to `Self Service`. When a valid full-run report under 36 hours old (`targetedRecheckMaximumAgeSeconds="129600"`) has warnings, failures, or errors, the next run rechecks only those checks and merges results by stable check key.
- To force full runs: set Script Parameter 11 `forceFreshRun` to `true`, or create `/var/tmp/MacHealthCheck-Force-Fresh-Run` for a one-shot full run.
- Changing the check set changes the keys, so the first run after deployment is always a full run (`check_set_mismatch`). That is expected.

## Step 5 — Generate the artifact

Read `references/health-checks.md` and `references/artifact-procedure.md`, then work through 5a–5e in order.

### 5a. Confirm the selection

Resolve the final ordered list against the MDM's shipped order and the preset rules. Show this block and wait for `yes`:

> **<MDM> · <preset> · operationMode `<mode>` · <n> checks**
> Enabled: `C1 macOS Version`, `C2 Available Updates`, …
> Disabled: `M15 Network Quality Test` (preset trim), …
> Artifact: `Artifacts/Mac-Health-Check_<slug>_<YYYY-MM-DD-HHMMSS>.zsh` plus a sidecar `.md`
> Reply `yes` to write it, or adjust the list.

- Timestamp: local time, `date +%Y-%m-%d-%H%M%S`, taken when writing.
- For the Development preset, append `_development` to the basename.

### 5b. Build the two replacement regions

- **Self Service, Silent, Debug, or Test:**
  - Region A is the MDM's array, from `<arrayName>='` through its closing `'`.
  - Region B is the MDM's branch in the **health-check** `case ${mdmVendor} in` block, from the label line through `;;`.
- **Development:**
  - Region A′ is the `developmentListitemJSON` block.
  - Region B′ is the direct calls between `# set -x` and `# set +x`.
  - Leave the MDM arrays and branches untouched.
- **Rows:**
  - Copy each row verbatim from the source script's arrays. Fall back to the reference templates only when needed.
  - Change only `NN` (index + 1, zero-padded). Keep `'"${organizationColorScheme}"'` and `'${mdmVendor}'` exactly.
  - Put a comma after every row except the last.
  - Replace org-specific text with placeholders (for example, A9 → `<YOUR_ORGANIZATION_NETWORK>`).
- **Calls:**
  - One `runConfiguredHealthCheck "<index>" <function> [args]` per row, in row order. Development uses `<function> "<index>" [args]`.
  - Take function names and arguments from the reference master table. Never guess them.
- **Order:**
  - `updateComputerInventory` (F1) comes last.
  - M15 Network Quality Test is the last row, or directly before F1. The Client-Side Cache sanitizer strips a trailing comma only from that row, after it drops the Computer Inventory row.
- **Unchanged selection:** if it equals the shipped default, the artifact is an unchanged copy. Say so.

### 5c. Write the artifact

- Follow **Regions** and **Writing the artifact** in `references/artifact-procedure.md`:
  - anchor on exact whole lines;
  - never match a vendor label alone (labels repeat in unrelated `case` blocks);
  - replace only the two ranges.
- Create `Artifacts/` next to `Mac-Health-Check.zsh` if it is missing. Never write anywhere else, and never touch the source.
- Leave `scriptVersion` unchanged. A version change triggers targeted-recheck `version_mismatch`.
- **If you cannot write files:** print the intended filename, the full artifact in one fenced `zsh` block, and the sidecar in a fenced `markdown` block. Tell the admin to save both under `Artifacts/` and run the validation checks.

### 5d. Validate and write the sidecar

Run the validation checks from `references/artifact-procedure.md`:

1. `zsh -n` on the artifact.
2. Extract the edited array, substitute the shell splices, and confirm `jq` accepts it.
3. Row count equals call count, indices run `0` to `n-1`, icon numbers match, and F1 is last when present.
4. `diff` the source against the artifact and confirm that only the two intended regions changed.
5. Replay the Client-Side Cache sanitizer on the artifact and confirm the array still passes `jq`.

If any check fails, fix the regions and rewrite the artifact. Never hand over a failing artifact without flagging it.

Write the sidecar `Artifacts/<same basename>.md` from the template in the procedure file. It records:
- MDM, `mdmVendor`, operationMode and preset;
- enabled checks (index, ID, title) and disabled checks, each with a reason;
- dependency notes;
- the result of each validation check;
- a diff summary (hunk ranges, rows before → after).

### 5e. Report

Reply with the artifact path, the sidecar path, a one-line PASS/FAIL for each check, and only the dependency notes that apply:

- **swiftDialog `3.1.1.4996` or newer.** Set by `swiftDialogMinimumRequiredVersion`; pre-flight installs or updates it.
- **`jq`.** Every array is validated with `jq`. An invalid array exits the script before any check runs.
- **External checks.** Each `checkExternalJamfPro` call is Jamf Pro only. It needs its `external-checks/` script saved in Jamf Pro and a policy with the matching custom trigger. The script's output must include `Running`, `Warning`, `Failed`, or `Error`. See `external-checks/README.md`.
- **Client-Side Cache / LaunchDaemon.** The cached copy runs nightly in `Silent` and drops `updateComputerInventory`. For user-scoped checks such as H3–H5, it falls back to the loginwindow `lastUserName` when no one is logged in.
- **`Silent` + `splunkOperationMode=production`.** Reporting-first: no non-Splunk console output and `jamf recon` skipped. Success means the report was written and delivered. Use the placeholders `<YOUR_SPLUNK_HEC_URL>` and `<YOUR_SPLUNK_HEC_TOKEN>`.
- **Webhook.** Script Parameter 5; use `<YOUR_WEBHOOK_URL>`.
- **Memory Pressure.** Needs samples from two distinct days before it can warn; early runs show `Insufficient data`.
- **Stable keys.** Titles become report keys. Renaming a title breaks Splunk dashboards and targeted-recheck continuity for that check.
- **MDM Profile.** Needs `mdmVendorUuid` or `mdmProfileIdentifier` for the chosen MDM.

## Step 6 — Next steps

Close with these steps, then offer to adjust the selection or build another artifact for a different MDM. Each artifact starts from the untouched source.

1. Review the sidecar and the diff summary.
2. Test on one Mac with `sudo zsh ./Artifacts/<file>.zsh "" "" "" "Development"`, then repeat with `Self Service`, `Silent`, `Debug`, and `Test` as Parameter 4.
3. Deploy the artifact as the MDM script. Keep `scriptVersion` unchanged, and keep Debug and Development out of the production policy.
4. Expect the first Self Service run after deployment to be a full run (`check_set_mismatch`). Targeted rechecks resume after that.
5. Keep `Artifacts/` out of version control. It is git-ignored because artifacts may carry org-specific edits.
6. Record the change in your internal release notes.

## Validation checklist (run before replying)

- The first message asked only the MDM question.
- The admin confirmed the selection in 5a before anything was written.
- `Mac-Health-Check.zsh` is unchanged, and the only new files are under `Artifacts/`.
- The artifact name matches `Mac-Health-Check_<slug>_<YYYY-MM-DD-HHMMSS>[_development].zsh`, and the sidecar shares its basename.
- Validation checks 1–5 passed and are recorded in the sidecar.
- M15 is the last row or directly before F1, and F1 is last.
- No `[Jamf Pro only]` check appears for another MDM unless the admin explicitly asked for it and was warned.
- No real organization names, URLs, tokens, or paths beyond the shipped defaults.

## Resources

- Project: https://github.com/dan-snelson/Mac-Health-Check
- Releases (5.0.0b1 and later): https://github.com/dan-snelson/Mac-Health-Check/releases
- `README.md`, `CHANGELOG.md`, `external-checks/README.md`, `Artifacts/README.md`, and `AGENTS.md` in the repository
- `references/health-checks.md` and `references/artifact-procedure.md` in this skill

## Example conversation

**Admin:** Help me pick which MHC checks to run.

**Assistant:** Which MDM manages these Macs? Reply with a number or type your own.
1. Jamf Pro · 2. Fleet · 3. JumpCloud · 4. Microsoft Intune · 5. Mosyle · 6. Kandji / Iru · 7. Addigy · 8. Other / MDM-agnostic / custom

**Admin:** 1

**Assistant:** Jamf Pro it is. Each row in the swiftDialog window comes from `jamfProListitemJSON`, and each row's check runs from a matching `runConfiguredHealthCheck` line in the `"Jamf Pro"` case branch. I'll write an edited copy to `Artifacts/` and leave your script untouched. Here is the checklist; `[default]` marks what ships for Jamf Pro. *(checklist from Step 3)* Reply with IDs or categories, or pick a preset next.

**Admin:** Use a preset.

**Assistant:** *(Step 4 block)*

**Admin:** d, Self Service, no externals, keep targeted rechecks.

**Assistant:** **Jamf Pro · Minimal triage · operationMode `Self Service` · 11 checks**
Enabled: C1, C2, C5, C6, H1, H2, M1, M4, M5, M6, M14.
Disabled: everything else (preset trim), including F1 Computer Inventory, because the preset has no M15 and F1 without M15 breaks the Client-Side Cache copy.
Artifact: `Artifacts/Mac-Health-Check_jamf-pro_2026-09-28-101745.zsh` plus a sidecar `.md`. Reply `yes` to write it.

**Admin:** yes

**Assistant:** Wrote `Artifacts/Mac-Health-Check_jamf-pro_2026-09-28-101745.zsh` and `Artifacts/Mac-Health-Check_jamf-pro_2026-09-28-101745.md`.

| # | Check | Result |
|---|---|---|
| 1 | `zsh -n` | PASS |
| 2 | `jq` on `jamfProListitemJSON` | PASS |
| 3 | 11 rows = 11 calls, indices 0–10, icons `01`–`11` | PASS |
| 4 | Diff: 2 hunks, inside the array and the `"Jamf Pro" )` branch only | PASS |
| 5 | Client-Side Cache simulation | PASS |

*Notes:* swiftDialog `3.1.1.4996`+; `scriptVersion` unchanged; the first Self Service run after deployment is a full run because the check set changed. *(Step 6 next steps follow, then: "Build another artifact for a different MDM?")*
