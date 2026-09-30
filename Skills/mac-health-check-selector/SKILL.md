---
name: mac-health-check-selector
description: Interactively prompts a Mac Admin to select which health checks to enable or disable in Mac Health Check (dan-snelson/Mac-Health-Check). Use when customizing MHC list items, health-check functions, external checks, or generating a tailored, validated, MDM-specific and date-stamped copy of Mac-Health-Check.zsh in Artifacts/. Triggers on phrases like "Mac Health Check checks", "which MHC checks", "customize MHC health checks", "select health checks for Mac Health Check", "MHC list items", or any request to choose or configure Mac Health Check compliance checks.
---

# Mac Health Check Selector

Guide a Mac Admin through choosing which Mac Health Check (MHC) health checks to show and run, then write an edited, MDM-specific, date-stamped copy of `Mac-Health-Check.zsh` into `Artifacts/`, plus a sidecar `.md` that records the selection and validation results.

Target: the `5.0.0b3` prerelease line and later. Full per-check data (exact list-item JSON, function arguments, shipped default order per MDM, artifact anchors) lives in `references/health-checks.md`. The write-and-validate procedure lives in `references/artifact-procedure.md`. The tested build-and-validate helper is `scripts/build-artifact.zsh`. Read both reference files before generating output. When they disagree with the admin's copy of `Mac-Health-Check.zsh`, trust the script.

## Ground rules

- Ask the MDM question first, every time. Do not skip, merge, or bury it.
- Ask one step at a time. Wait for the answer before moving on.
- Use numbered lists and check IDs (such as `C1`, `M5`) so replies parse without ambiguity (see **Reply grammar**).
- Be non-destructive. Never edit `Mac-Health-Check.zsh` in place; write only to `Artifacts/`. Never commit or deploy anything.
- Use placeholders for anything organization-specific: `<YOUR_ORG_NAME>`, `<YOUR_WEBHOOK_URL>`, `<YOUR_SPLUNK_HEC_URL>`, `<YOUR_SPLUNK_HEC_TOKEN>`, `<YOUR_POLICY_TRIGGER>`, `<YOUR_ORGANIZATION_NETWORK>`. Never invent real URLs, tokens, or branding.
- Keep user-facing subtitles short and action-oriented.
- Accept "defaults", "same as shipped", or "recommend for me" at any step; pick the shipped default and say so.
- Change only which checks run. Every other setting keeps its `Mac-Health-Check.zsh` default (`operationMode`, `mdmVendorUuid`, external-check triggers, targeted remediation verification, `developmentListitemJSON`). Admins who want those changed edit the artifact manually.
- Leave only passing artifacts in `Artifacts/`. A build that fails validation is never written there.

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
> 8. Filewave
> 9. Other / MDM-agnostic / custom

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
| 8 | `Filewave` | `filewaveMdmListitemJSON` | `"Filewave" )` | `filewave` |
| 9 | `None` | `genericMdmListitemJSON` | `* )` | `generic` |

The helper prints each MDM by its display name (`Kandji / Iru`, `Other / MDM-agnostic` for `generic`); use the same names with the admin and in the sidecar.

MDM-specific notes to carry forward:

- **All MDMs** — the script picks its branch at runtime from the enrolled `serverURL`, not from the artifact name. An Intune artifact run on a Jamf Pro-enrolled Mac runs the unedited `"Jamf Pro" )` branch.
- **Jamf Pro** — only MDM with Jamf Pro Check-In, Jamf Pro Inventory, Jamf Hosts, Computer Inventory (`jamf recon`), and `checkExternalJamfPro` external checks. Entra ID Registration and Clock Skew ship in the Jamf Pro list. The script exits early if `/private/var/log/jamf.log` is missing.
- **Mosyle** — adds Mosyle Check-In and the Mosyle Self-Service app check.
- **Fleet / Intune** — add an MDM agent app presence check (Fleet Desktop / Microsoft Company Portal).
- **Kandji / Iru** — detected when `serverURL` contains `kandji`; an Iru-branded URL without that string falls to the generic branch. Ask the admin to confirm their server URL. Ships a six-app set (`A5a`–`A5f`) and no MDM Profile row.
- **Addigy** — ships with a blank `mdmVendorUuid`; MDM Profile will not pass until the admin fills it in manually.
- **Other** — no MDM Profile or MDM Certificate Expiration, because no vendor profile or certificate name is known. Admins who know them edit `mdmVendor`, `mdmVendorUuid` or `mdmProfileIdentifier`, and the certificate name manually. The generic branch also runs on unenrolled Macs, where M4 Apple Push Notification service fails.

## Step 2 — Explain the purpose

After the MDM is known, say in two or three sentences:

> Mac Health Check runs modular checks and shows each one as a row in the swiftDialog window. For <MDM>, each row is defined in `<array name>`, and each row's check runs from a matching `runConfiguredHealthCheck` line in the `"<MDM>"` case branch. We'll pick which checks to keep. Then I'll write an edited copy of the script to `Artifacts/` with both parts in matching order, validate it, and record everything in a sidecar `.md`. Your `Mac-Health-Check.zsh` stays untouched.

## Step 3 — Present the checklist

Show the checklist below, tailored to the MDM from Step 1:

- **`[off]`** marks each available check that is *not* in that MDM's shipped default (for example H7, M2, A4 on Intune). The off group is the smaller one for every MDM, so the list stays quiet. Say once above the list: "Unmarked checks are on by default; `[off]` checks are available but off." (See **Shipped default order per MDM** in the reference.)
- **A5** shows the concrete app for the chosen MDM: `A5 Fleet Desktop`, `A5 Microsoft Company Portal`, `A5 Mosyle Self-Service`, or for Kandji `A5a Microsoft One Drive`, `A5b Microsoft Outlook`, `A5c Company Portal`, `A5d Zoom`, `A5e Cortex`, `A5f Netskope`.
- **"Not available for <MDM>"** is one group at the end that lists, with a short reason:
  - Jamf Pro-only items (M5, M6, M13, A6–A10, F1) for every MDM except Jamf Pro;
  - other vendors' vendor-only items (M7 Mosyle Check-In unless Mosyle);
  - A5 when the MDM ships no agent app (Jamf Pro, JumpCloud, Addigy, Filewave, Other); offer an A4-style custom app instead;
  - M1 and M3 for Other.
- Mark external checks with `*`.

Ask: "Reply `defaults` to keep the shipped list, or change it: `H7 A4` adds, `no A3` removes, `only C, H1-H6, M4` picks exactly those."

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
- A4 Organizationally required application (Microsoft Teams unless the admin names another app)
- A5 MDM agent app (concrete name per MDM; see above)
- A6 BeyondTrust Privilege Management* `[Jamf Pro only]`
- A7 Cisco Umbrella* `[Jamf Pro only]`
- A8 CrowdStrike Falcon* `[Jamf Pro only]`
- A9 Palo Alto GlobalProtect* `[Jamf Pro only]`
- A10 Other `external-checks/` script* (Microsoft Defender, Microsoft Office 365, Nessus, Sophos, Splunk Universal Forwarder, Zscaler, printer install, and others) `[Jamf Pro only]`

**Follow-up Actions (F)**
- F1 Update Computer Inventory `[Jamf Pro only; always last]`

`*` = requires an external-check script deployed as a Jamf Pro policy with a custom trigger. On other MDMs, offer A4-style presence checks (`checkInternal`) or a new custom `checkXxx` function instead.

A4 defaults to Microsoft Teams (`/Applications/Microsoft Teams.app`). Do not ask about it up front; show it in 4a, and ask for the path and display name only when the admin names another app or asks to change it. For A10, ask for the Jamf Pro policy trigger and the app path used for the icon.

### Reply grammar

One rule set applies to every selection reply, in Step 3 and in 4a:

1. Tokens are case-insensitive and separated by commas or spaces. Duplicates are ignored.
2. **Base:** the current selection. In Step 3 that is the MDM's shipped default; in 4a it is the list being confirmed.
3. **Operations:**
   - A bare token adds to the base: `H7 A4` → defaults + H7 + A4.
   - `no <token>` removes: `no A3` on Intune → 33 − 1 = 32 checks.
   - `only <tokens>` replaces the base with exactly those tokens; later `no` tokens in the same reply still apply.
   - `defaults` resets the base to the shipped default: `defaults, no M15`.
4. **Tokens:**
   - An ID (`C5`, `A5c`). `A5` on Kandji means all six `A5a`–`A5f`.
   - A range (`H1-H6`) is inclusive and stays inside one category.
   - A category letter (`C`, `H`, `M`, `A`, `F`) means every *available* item in that category for the MDM.
5. An unknown ID → ask. A "Not available" ID → warn with the reason, and include it only if the admin confirms.
6. **Order:**
   - Default items keep the MDM's shipped order.
   - Available non-default additions go immediately before the first remaining M14, H6, or M15 (the tail every shipped default ends with), in master-table order (C, H, M, A). If none of those remain, append them.
   - F1 always comes last. If F1 is picked without M15, warn and ask: keep M15 directly before F1, or drop F1.

## Step 4 — Generate the artifact

Read `references/health-checks.md` and `references/artifact-procedure.md`, then work through 4a–4e in order.

### 4a. Confirm the selection

Resolve the final ordered list with **Reply grammar**. Show this block and wait for `yes`:

> **<MDM display name> · <n> checks**
> Enabled: C1 C2 C3 … M14 H6 M15 *(IDs only, in final order)*
> Changes vs shipped default: added `H7 Clock Skew`, `A4 Microsoft Teams`; removed `A3 Electron Corner Mask` *(or "none — unchanged copy of the source")*
> A4 → Microsoft Teams (`/Applications/Microsoft Teams.app`) *(only when A4 is enabled)*
> Artifact: `Artifacts/Mac-Health-Check_<slug>_<YYYY-MM-DD-HHMMSS>.zsh` plus a sidecar `.md` (timestamp set when written)
> All other settings keep `Mac-Health-Check.zsh` defaults; edit the artifact manually to change them.
> Reply `yes` to write it, or change it: `H7` adds, `no A3` removes, `only …` replaces.

- Enabled checks appear as IDs only. Give full titles only for checks added or removed against the shipped default. The helper's sidecar lists every disabled check with its reason, so 4a does not.
- Always show the `<YYYY-MM-DD-HHMMSS>` placeholder here. The helper takes the timestamp (local time, `date +%Y-%m-%d-%H%M%S`) when it writes the file.
- A reply other than `yes` is parsed with **Reply grammar** against the list shown; show the updated block and wait again.

### 4b. Build the selection

- Run `zsh Skills/mac-health-check-selector/scripts/build-artifact.zsh --list <slug>` from the repository root. It prints `index|raw title|call` for the MDM's shipped rows. If it differs from the reference's shipped default, trust the script and tell the admin.
- Pass the selection on stdin with `--selection -` and a here-doc, so no temporary file is left behind (see `references/artifact-procedure.md`). Use one line per check, in the 4a order:
  - `<ID>|<raw title>`, where the raw title is copied from `--list` output or the master table (for example `M1|'${mdmVendor}' MDM Profile`). The ID must match the master table; the helper exits `2` on a mismatch. The helper copies the row verbatim from the source, taking the chosen MDM's array first, then Jamf Pro, then the others. It pairs each row with the call at the same index, and prints `INFO borrowed row:` for each row taken from another MDM's array.
  - `<ID>|custom|<row fragment>|<call>` for A4 extra apps and A10. Use `SF=NN.circle` in the row, and take the call arguments from the master table. Never guess them.
- The helper renumbers `SF=NN.circle` and `runConfiguredHealthCheck "<index>"` from zero. It keeps `'"${organizationColorScheme}"'` and `'${mdmVendor}'` exactly, fixes commas, and replaces the A9 subtitle with `<YOUR_ORGANIZATION_NETWORK>`. Outside Jamf Pro, it swaps the Jamf-worded H7 Clock Skew subtitle for the vendor-neutral `Checks local clock offset against time.apple.com`.
- If the selection equals the shipped default, the artifact is an unchanged copy. Say so.
- Leave `developmentListitemJSON` and the direct Development calls untouched.

### 4c. Write and validate the artifact

- Run `zsh Skills/mac-health-check-selector/scripts/build-artifact.zsh --slug <slug> --selection <file>`. Validation checks 1–8 each print `PASS`, `FAIL`, `SKIP`, or `INFO`:
  1. `zsh -n` on the artifact.
  2. The edited array, with the shell splices substituted, passes `jq`.
  3. Alignment:
     - 3a: row count equals call count.
     - 3b: indices run `0` to `n-1`.
     - 3c: icons run `01` to `n`.
     - 3d: F1 is last or absent.
     - 3e: M15 is last, or directly before F1.
  4. `diff` hunks fall only inside the two regions.
  5. Client-Side Cache replay (5a–5c), using the sanitizer extracted live from `installClientSideScript`: `zsh -n`, `jq`, and no `jamf recon` text.
  6. `scriptVersion` is unchanged.
  7. The source is unchanged (SHA-256 before and after). `git diff --quiet` is reported as `INFO`.
  8. The artifact and sidecar paths are git-ignored.
- Exit codes:
  - **`0`:** the artifact and its complete sidecar `.md` are in `Artifacts/`.
  - **`1`:** at least one check failed. Nothing was written to `Artifacts/`, and the failed build stays in the printed work directory. Fix the selection (usually the order), then rerun; the rerun gets a new timestamp.
  - **`2`:** the selection file or the anchors are invalid. Fix it and rerun.
- **If you cannot run the helper:** follow the manual procedure in `references/artifact-procedure.md`. Each manual check prints `PASS`/`FAIL`, and the block exits non-zero on any failure.
- **If you cannot write files:** print the intended filename, the full artifact in one fenced `zsh` block, and the sidecar in a fenced `markdown` block. Tell the admin to save both under `Artifacts/` and run the helper, or the manual checks, on the saved file.

### 4d. Review the sidecar

On exit `0`, the helper has already written `Artifacts/<same basename>.md`. It contains the header, Enabled (index, ID, resolved title, report key), Disabled (every unselected check with its reason), report keys removed and added, tagged dependency notes, the validation table, the diff summary, and next steps. Titles are resolved (`Microsoft Intune MDM Profile`, not `'${mdmVendor}' MDM Profile`), and MDMs use display names.

Read it, and append only organization-specific notes the admin gave (for example a custom A4 app or a planned `vpnClientVendor` change). When the helper cannot run, write the sidecar by hand from the template in the procedure file.

### 4e. Report

Reply with the artifact path, the sidecar path, a one-line PASS/FAIL for each check, and the dependency notes that apply. The helper already picked them for the sidecar; repeat the non-`[all]` ones and any report-key or borrowed-row note. Each note's tag says when it applies:

| Tag | Applies when | Note |
|---|---|---|
| `[all]` | Always | swiftDialog `3.1.1.4997` or newer (`swiftDialogMinimumRequiredVersion`); pre-flight installs or updates it. |
| `[all]` | Always | `jq` validates every array; an invalid array exits before any check runs. |
| `[all]` | Always | Client-Side Cache / LaunchDaemon: the cached copy runs nightly in `Silent` and drops `updateComputerInventory`; H3–H5 fall back to the loginwindow `lastUserName`. |
| `[all]` | Always | `Silent` + `splunkOperationMode=production` is reporting-first; use `<YOUR_SPLUNK_HEC_URL>` and `<YOUR_SPLUNK_HEC_TOKEN>`. |
| `[all]` | Always | Secrets: `webhookURL` and `splunkHECToken` go in root-only `MacHealthCheck-Secrets.plist`; Parameters 5 and 8 are rejected unless `allowParameterSecrets="true"`. |
| `[all]` | Always | Runtime MDM detection: the edits run only on Macs the script detects as the chosen MDM; others run their own unedited branch. |
| `[all]` | Keys change | Report keys removed or added through `sanitizeCheckKey` (for example `electron_corner_mask`); Splunk dashboards and targeted-recheck continuity lose or gain them. M1 and M3 keys include the vendor (`microsoft_intune_mdm_profile`). |
| `[all]` | Borrowed rows | Rows copied from another MDM's array; review their subtitles. |
| `[C8]` | C8 enabled | Touch ID reports an error on Macs without Touch ID hardware (VMs, desktops without a Touch ID keyboard). |
| `[C13]` | C13 enabled | VPN Client follows `vpnClientVendor` (shipped `paloalto`) and `vpnClientDataType`; it fails when that client is absent. |
| `[H6]` | H6 enabled | Memory Pressure needs samples from two distinct days; early runs show `Insufficient data`. |
| `[vendor]` | M1 enabled | MDM Profile needs `mdmVendorUuid` or `mdmProfileIdentifier`. |
| `[Addigy]` | Addigy + M1 | `mdmVendorUuid` ships blank; fill it in. |
| `[Kandji]` | Kandji | Detection needs `serverURL` to contain `kandji`. |
| `[generic]` | Other | No MDM Profile or MDM Certificate Expiration; M4 fails on unenrolled Macs. |
| `[Jamf]` | Jamf Pro | Script exits early without `/private/var/log/jamf.log`. |
| `[Jamf]` | External checks | Each `checkExternalJamfPro` call needs its `external-checks/` script in Jamf Pro and a policy with the matching custom trigger; output must include `Running`, `Warning`, `Failed`, or `Error`. See `external-checks/README.md`. |
| `[Jamf]` | F1 enabled | `jamf recon` with a 90-second timeout; skipped in `Silent` + production; removed from the cached copy. |
| `[A9]` | A9 rebuilt | Subtitle now `<YOUR_ORGANIZATION_NETWORK>`; replace it before deploying. |
| `[A4]` | A4 enabled | Shows the `checkInternal` path and name; edit them if the required app differs. |

## Step 5 — Next steps

Close with these steps, then offer to adjust the selection or build another artifact for a different MDM. Each artifact starts from the untouched source.

1. Review the sidecar and the diff summary.
2. Test on one Mac **enrolled in the chosen MDM** (for Other / MDM-agnostic, a Mac whose `serverURL` matches no known MDM; an unenrolled Mac qualifies, and M4 then fails as expected):
   - Run `sudo zsh ./Artifacts/<file>.zsh "" "" "" "Self Service"`, then repeat with `Silent`, `Debug`, `Development`, and `Test` as Parameter 4.
   - `Development` runs the shipped `developmentListitemJSON` subset, not the selection.
   - Confirm that the dropped checks do not appear in the log and that the row count matches.
   - Non-`Silent` test runs install the artifact as the Mac's Client-Side Cache copy and LaunchDaemon. Re-run the production policy afterwards to restore them.
3. Deploy the artifact as the MDM script. Keep `scriptVersion` unchanged, and keep Debug and Development out of the production policy.
4. Expect the first Self Service run after deployment to be a full run (`check_set_mismatch`). Targeted rechecks resume after that.
5. Keep `Artifacts/` out of version control. It is git-ignored because artifacts may carry org-specific edits.
6. Record the change in your internal release notes.

## Validation checklist (run before replying)

- The first message asked only the MDM question.
- The reply was parsed with **Reply grammar**, and the admin confirmed the selection in 4a before anything was written.
- `Mac-Health-Check.zsh` is unchanged, and the only new files are under `Artifacts/`.
- The artifact name matches `Mac-Health-Check_<slug>_<YYYY-MM-DD-HHMMSS>.zsh`, and the sidecar shares its basename.
- Validation checks 1–8 printed `PASS` (or `SKIP` for 8 outside git), and the helper wrote the sidecar. No failed build remains in `Artifacts/`, and no selection file was left behind.
- M15 is the last row or directly before F1, and F1 is last.
- No "Not available" check appears for the MDM unless the admin explicitly asked for it and was warned.
- No real organization names, URLs, tokens, or paths beyond the shipped defaults.

## Resources

- Project: https://github.com/dan-snelson/Mac-Health-Check
- Releases (5.0.0b3 and later): https://github.com/dan-snelson/Mac-Health-Check/releases
- `README.md`, `CHANGELOG.md`, `external-checks/README.md`, `Artifacts/README.md`, and `AGENTS.md` in the repository
- `references/health-checks.md`, `references/artifact-procedure.md`, and `scripts/build-artifact.zsh` in this skill

## Example conversation

**Admin:** Help me pick which MHC checks to run.

**Assistant:** Which MDM manages these Macs? Reply with a number or type your own.
1. Jamf Pro · 2. Fleet · 3. JumpCloud · 4. Microsoft Intune · 5. Mosyle · 6. Kandji / Iru · 7. Addigy · 8. Filewave · 9. Other / MDM-agnostic / custom

**Admin:** 4

**Assistant:** Microsoft Intune it is. Each row in the swiftDialog window comes from `microsoftMdmListitemJSON`, and each row's check runs from a matching `runConfiguredHealthCheck` line in the `"Microsoft Intune"` case branch. I'll write an edited copy to `Artifacts/` and leave your script untouched. Unmarked checks are on by default (33 for Intune); `[off]` checks are available but off. *(checklist from Step 3, with `A5 Microsoft Company Portal`, `[off]` on H7, M2, and A4, and "Not available for Microsoft Intune: M5, M6, M13, A6–A10, F1 (Jamf Pro only); M7 (Mosyle only)")*

**Admin:** no A3

**Assistant:** **Microsoft Intune · 32 checks**
Enabled: C1 C2 A1 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C9 C10 C11 C12 M1 M3 M4 M8 M9 M10 M11 M12 A5 A2 M14 H6 M15
Changes vs shipped default: removed `A3 Electron Corner Mask`.
Artifact: `Artifacts/Mac-Health-Check_microsoft-intune_<YYYY-MM-DD-HHMMSS>.zsh` plus a sidecar `.md` (timestamp set when written).
All other settings keep `Mac-Health-Check.zsh` defaults; edit the artifact manually to change them. Reply `yes` to write it, or change it: `H7` adds, `no A3` removes, `only …` replaces.

**Admin:** yes

**Assistant:** Wrote `Artifacts/Mac-Health-Check_microsoft-intune_2026-09-28-105327.zsh` and its sidecar `Artifacts/Mac-Health-Check_microsoft-intune_2026-09-28-105327.md` (written by the helper).

| # | Check | Result |
|---|---|---|
| 1 | `zsh -n` | PASS |
| 2 | `jq` on `microsoftMdmListitemJSON` | PASS |
| 3 | 32 rows = 32 calls, indices 0–31, icons `01`–`32`, F1 absent, M15 last | PASS |
| 4 | Diff: 2 hunks, inside the array and the `"Microsoft Intune" )` branch only | PASS |
| 5 | Client-Side Cache simulation (`zsh -n`, `jq`, no `jamf recon`) | PASS |
| 6 | `scriptVersion` `5.0.0b3` unchanged | PASS |
| 7 | Source unchanged | PASS |
| 8 | Artifact and sidecar git-ignored | PASS |

*Notes:* `[all]` report key `electron_corner_mask` disappears from reports and dashboards; `[all]` test on an Intune-enrolled Mac, since a Jamf Pro-enrolled Mac runs the Jamf Pro branch; `[C8]` Touch ID errors on Macs without Touch ID hardware; `[C13]` set `vpnClientVendor` for your VPN client; the first Self Service run after deployment is a full run because the check set changed. *(Step 5 next steps follow, then: "Build another artifact for a different MDM?")*
