![GitHub release (latest by date)](https://img.shields.io/github/v/release/dan-snelson/Mac-Health-Check?display_name=tag) ![GitHub pre-release (latest by date)](https://img.shields.io/github/v/release/dan-snelson/Mac-Health-Check?display_name=tag&include_prereleases) ![GitHub issues](https://img.shields.io/github/issues-raw/dan-snelson/Mac-Health-Check) ![GitHub closed issues](https://img.shields.io/github/issues-closed-raw/dan-snelson/Mac-Health-Check) ![GitHub pull requests](https://img.shields.io/github/issues-pr-raw/dan-snelson/Mac-Health-Check) ![GitHub closed pull requests](https://img.shields.io/github/issues-pr-closed-raw/dan-snelson/Mac-Health-Check) [![swiftDialog](https://img.shields.io/badge/swiftDialog-Enabled-blue)](https://swiftdialog.app) [![Semgrep Security Scan](https://img.shields.io/badge/security%20scanned%20by-Semgrep-00C7B7?style=flat&logo=semgrep&logoColor=white)](https://semgrep.dev)

# Mac Health Check (5.0.0b6)

> Mac Health Check 5.0.0b6 adds a dedicated AI skill for easier Mac Admin customization, historical Memory Pressure warnings, targeted post-remediation verification, Jamf Pro clock-skew detection and macOS 27 compatibility improvements

<img src="images/MHC_5.0.0.png" alt="Mac Health Check Hero" width="800"/>

<table>
    <tr>
        <td><a href="images/MHC_5.0.0_second_run.png"><img src="images/MHC_5.0.0_second_run.png" alt="Main Dialog" width="320"></a>Targeted Post-remediation Verification</td>
        <td><a href="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.15.03%E2%80%AFPM.png"><img src="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.15.03%E2%80%AFPM.png" alt="Results Overview" width="320"></a>Results Overview</td>
        <td><a href="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.15.58%E2%80%AFPM.png"><img src="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.15.58%E2%80%AFPM.png" alt="Security Status" width="320"></a>Security Status</td>
        <td><a href="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.02%E2%80%AFPM.png"><img src="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.02%E2%80%AFPM.png" alt="AirDrop Detail Sheet" width="320"></a>AirDrop Detail Sheet</td>
        <td><a href="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.19%E2%80%AFPM.png"><img src="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.19%E2%80%AFPM.png" alt="Bluetooth Sharing Detail Sheet" width="320"></a>Bluetooth Sharing Detail Sheet</td>
    </tr>
    <tr>
        <td><a href="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.31%E2%80%AFPM.png"><img src="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.31%E2%80%AFPM.png" alt="Maintenance Status" width="320"></a>Maintenance Status</td>
        <td><a href="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.36%E2%80%AFPM.png"><img src="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.36%E2%80%AFPM.png" alt="App Auto-Patch Detail Sheet" width="320"></a>App Auto-Patch Detail Sheet</td>
        <td><a href="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.49%E2%80%AFPM.png"><img src="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.49%E2%80%AFPM.png" alt="Applications Status" width="320"></a>Applications Status</td>
        <td><a href="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.57%E2%80%AFPM.png"><img src="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.16.57%E2%80%AFPM.png" alt="Homebrew Status Detail Sheet" width="320"></a>Homebrew Status Detail Sheet</td>
        <td><a href="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.17.56%E2%80%AFPM.png"><img src="Resources/MacHealthCheck-Inspect-Mode/Screenshot%202026-06-23%20at%205.17.56%E2%80%AFPM.png" alt="Next Steps" width="320"></a>Next Steps</td>
    </tr>
</table>

## Overview

Mac Health Check provides a practical, MDM-agnostic, user-friendly approach to surfacing Mac compliance information directly to end-users via an MDM's Self Service.

Built using the open-source utility [swiftDialog](https://github.com/swiftDialog/swiftDialog/wiki), the solution acts as a “heads-up display” that presents real-time system health and policy compliance status in a clear and interactive format.

Deployment of Mac Health Check involves configuring organizational defaults, embedding the script in your MDM, creating a policy to run it on demand and testing to ensure proper output and behavior.

Administrators can customize the user interface using swiftDialog’s visual capabilities, making the experience both informative and approachable.

<a href="https://www.youtube.com/watch?v=rDPoYlSSEtQ&t=36s" target="_blank"><img src="images/Mac_Health_Check Presentation.png" alt="Rocketman Tech December 2025 Meetup" width="600"/><br />Rocketman Tech December 2025 Meetup</a> (05-Dec-2025)



## Use Cases

Mac Health Check is particularly valuable in IT support workflows, serving as an initial triage point for Tier 1 support by confirming network access, credentials, and MDM connectivity, while also acting as a verification tool for Tier 2 teams both during and after remediation efforts.

### Enterprise Reporting

The tool logs results for review, writes a structured JSON health report locally, can optionally forward that report to Splunk HEC, and continues to avoid altering device configuration. In `Self Service`, `5.0.0b6` launches a detached swiftDialog Inspect Mode `preset6` guided summary built from finalized results plus a live compliance plist for swiftDialog `3.1.1.4997` compliance findings. When a valid full-run baseline less than 36 hours old contains warnings, failures, or errors, the next `Self Service` run automatically rechecks only those findings, merges the new results into the prior full report by stable check key, and records per-check timestamps. Healthy reruns within 15 minutes can still replay the cached summary without re-running health checks. Full `Silent` health-check runs generate the same Inspect Mode config and compliance plist artifacts without launching swiftDialog.

- Structured JSON health report generated at the end of every run
- Local report saved to `/Library/Management/org.churchofjesuschrist/MacHealthCheck-Report.json` by default with `600` permissions
- Beginning in `5.0.0b6`, persistent runtime state (canonical report and lock, Inspect config and compliance plist, SOFA and `networkQuality` caches) lives in root-owned `/Library/Management/org.churchofjesuschrist` instead of world-writable `/var/tmp`; cached reports are trusted only when they are root-owned regular files, and root-owned pre-`5.0.0` leftovers in `/var/tmp` are removed automatically
- Splunk HEC tokens and webhook URLs are passed to `curl` through `--config -` on stdin, so they never appear in the `curl` child's arguments, and `Debug` mode's `set -x` tracing starts after parameter parsing and is suppressed inside secret-handling functions
- Webhook deliveries fail on HTTP errors: Slack and Microsoft Teams responses other than `2xx` are logged with their HTTP status, `5xx` and connection failures are retried up to three times, and a failed delivery is logged as a warning without changing report status or exit codes
- Script Parameters 5 and 8 remain visible to any local user (via `ps`) for as long as the root script runs, so beginning in `5.0.0b6` the script rejects a Splunk HEC token or webhook URL supplied only through those parameters (logged as `[ERROR]`; Splunk HEC delivery and webhook messages are skipped, so `Silent` + `splunkOperationMode=production` exits `1`). Deploy them in the root-only secrets file `/Library/Management/org.churchofjesuschrist/MacHealthCheck-Secrets.plist` (keys `splunkHECToken` and `webhookURL`; `root:wheel`, mode `600`, for example from a package payload) and leave Parameters 5 and 8 blank; set `allowParameterSecrets="true"` in the script only as a temporary, not-recommended legacy opt-in. Secrets-file values take precedence over the parameters, an untrusted secrets file is ignored with a warning, and each run logs which source was used. Rotate any token previously passed as a parameter, and restrict the HEC token to the Mac Health Check index and sourcetype
- Optional Splunk HEC delivery through Parameters 6-11 without changing the existing `operationMode` contract
- Parameters 9 and 10 set the HEC `index` and `sourcetype`; Parameter 11 forces a fresh run by bypassing `Self Service` targeting/replay or Jamf `Silent` cached upload
- `splunkOperationMode=off` disables HEC delivery explicitly while still preserving local JSON report generation
- `splunkOperationMode=test` preserves local report generation while intentionally skipping network transmission
- Only `splunkOperationMode=production` (case-insensitive) enables Splunk HEC delivery; beginning in `5.0.0b6`, any unrecognized value (for example, a typo) falls back to `test` and logs `[ERROR]`, so it never uploads compliance data
- Beginning in `4.0.0`, non-`Silent` runs and full Jamf production runs install a client-side copy at `/Library/Management/org.churchofjesuschrist/MHC.zsh` plus a `org.churchofjesuschrist.MHC` LaunchDaemon that refreshes the local report across a deterministic 00:53-01:53 window centered on 1:23 a.m.
- The LaunchDaemon sets `launchDaemonRun=true`; the client-side script then derives a stable per-Mac jitter from hardware UUID, logs the jitter through MHC-prefixed logging, and routes daemon stdout/stderr to `/dev/null` to avoid duplicate client-log lines.
- When a LaunchDaemon-triggered refresh runs with no active GUI user, Mac Health Check falls back to `/Library/Preferences/com.apple.loginwindow.plist` `lastUserName` for user-scoped checks.
- Jamf Pro `Silent` + `splunkOperationMode=production` runs upload the cached report without re-running checks when the client-side script version matches and `/Library/Management/org.churchofjesuschrist/MacHealthCheck-Report.json` is valid and less than 36 hours old

<img src="images/MHC_4_Splunk_Dashboard.png" alt="Splunk Dashboard" width="800"/>

See: [Resources/Splunk-Dashboard-Reference.md](Resources/Splunk-Dashboard-Reference.md) for copy/paste Splunk SPL, Simple XML, and Dashboard Studio starter examples.

### End-user Reporting

The `inspectSummaryPreset` is now an `on` / `off` toggle: `on` generates the Preset 6 inspect-summary assets, launches the summary in `Self Service`, and enables healthy-result cached replay; `off` disables asset generation, launch, and replay. Unresolved findings take precedence over replay and trigger targeted verification when the canonical report is eligible.

The current `5.0.0b6` release targets swiftDialog `3.1.1.4997` or newer so `Self Service` can use the PR #684 Preset 6 spacing and highlight refinements. Older compatible swiftDialog builds retain their prior visual treatment. PR #684 also tolerates quoted scalar values from MDM templating tools; Mac Health Check continues to emit native JSON numbers and booleans.

User-facing report:

```zsh
dialog --inspect-mode --inspect-config "/Library/Application Support/org.churchofjesuschrist/Inspect/MacHealthCheck-Inspect-Config.json"
```

Terminal summary of most recent health issues:

```zsh
sudo jq -r '
"",
"Mac Health Check 4: Recent Warnings & Failures",
"",
"Hostname: \(.metadata.hostname) (\(.metadata.localHostName))",
"Timestamp: \(.metadata.timestamp)",
"Overall Status: \(.summary.overallStatus)",
"Healthy: \(.summary.healthyCount) | Warning: \(.summary.warningCount) | Fail: \(.summary.failCount) | Error: \(.summary.errorCount)",
"",
(.checks[]
| select(.status != "healthy")
| "- \(.name): \(if (.rawValue? | type) != "string" or .rawValue == "" then .message else .rawValue end)"),
""
' /Library/Management/org.churchofjesuschrist/MacHealthCheck-Report.json
```

### Step Zero for Tier 1

- User has a working Internet connection
- User knows their directory credentials
- Mac can execute policies
- Validates Network Access Controls

### Step Ninety-nine for Tier 2

- Initial assessment for support sessions
- Easily confirms remediation efforts
- Provides peace-of-mind for end-users

### Silent Mode

- Silently performs all health checks and logs results
- No dialog is presented to the end-user
- Ideal for background compliance reporting
- Complements existing MDM compliance frameworks
- Full `Silent` health-check runs generate `/Library/Application Support/org.churchofjesuschrist/Inspect/MacHealthCheck-Inspect-Config.json` and `/Library/Application Support/org.churchofjesuschrist/Inspect/MacHealthCheck-Inspect-Compliance.plist` without launching swiftDialog
- When combined with `splunkOperationMode=production`, suppresses non-Splunk stdout/stderr noise in Jamf policy logs while continuing to write the full run to `${scriptLog}`
- In that same `Silent` + `splunkOperationMode=production` combination, `updateComputerInventory()` logs a skip message and does not run `jamf recon`
- Client-Side Cache uses a local LaunchDaemon copy to refresh `/Library/Management/org.churchofjesuschrist/MacHealthCheck-Report.json` nightly without storing Splunk HEC secrets client-side
- LaunchDaemon-triggered refreshes use the active console user when present, and otherwise fall back to loginwindow `lastUserName` for user-scoped checks
- Jamf Pro can then run `Silent` + `splunkOperationMode=production` to upload the cached report only when the client and server script versions match

#### Uninstall

```zsh
#!/bin/zsh --no-rcs

launchDaemonLabel="org.churchofjesuschrist.MHC"
launchDaemonPath="/Library/LaunchDaemons/${launchDaemonLabel}.plist"
organizationDirectory="/Library/Management/org.churchofjesuschrist"
inspectAssetsDirectory="/Library/Application Support/org.churchofjesuschrist/Inspect"

# Stop/unload daemon:
/bin/launchctl bootout system "${launchDaemonPath}" 2>/dev/null || true
/bin/launchctl disable "system/${launchDaemonLabel}" 2>/dev/null || true

# Remove Client-Side Cache assets:
/bin/rm -fv "${launchDaemonPath}"
# Also removes root-only Memory Pressure history and its lock file.
/bin/rm -rfv "${organizationDirectory}"

# Remove Inspect assets and per-user Inspect control files:
/bin/rm -rfv "${inspectAssetsDirectory}"

# (The report, SOFA cache and networkQuality cache all live under
# "${organizationDirectory}" and are removed above.)

# Optional pre-5.0.0 cached/report artifacts:
/bin/rm -fv /var/tmp/MacHealthCheck-Report.json
/bin/rm -fv /var/tmp/MacHealthCheck-Inspect-Config.json
/bin/rm -fv /var/tmp/MacHealthCheck-Inspect-Compliance.plist
/bin/rm -fv /var/tmp/MacHealthCheck-Inspect-Summary.log

# Optional log removal:
/bin/rm -fv /var/log/org.churchofjesuschrist.log
```

### Dock Integration

- Non-`Silent` modes launch swiftDialog with `--showdockicon` and `--dockicon`
- `dockIcon` is configurable and supports `default`, local paths, `file://` paths and `http(s)` URLs
- Mac Health Check copies `Dialog.app` to `/Library/Application Support/Dialog/${humanReadableScriptName}.app` and launches `dialogcli` from that bundle so Dock hover text matches the script name
- `dockiconbadge` shows the number of remaining checks, decreases after each completed check and is removed when checks complete
- If dock icon setup fails, Mac Health Check logs a warning and falls back to `/Library/Application Support/Dialog/Dialog.app/Contents/MacOS/dialogcli`
- Beginning in `5.0.0b6`, the root script calls swiftDialog, Jamf Pro (`/usr/local/jamf/bin/jamf`) and `jq` through root-owned absolute paths and removes `/usr/local/bin` from `PATH`, because Homebrew can make that directory user-writable

## Features
The following health checks and information reporting are included in version `5.0.0b6`, which operates in `Self Service` mode by default. (Change `operationMode` to `Debug`, `Development` or `Test` when getting ready to deploy in production.)

> Mac Health Check version `5.0.0b6` retains secure JSON report generation and optional Splunk HEC delivery, Client-Side Cache nightly report caching for Jamf Pro Splunk uploads, Inspect Mode summary assets for swiftDialog `3.1.1.4997` PR #684 refinements, `Quick Actions`, a conditional `Remediation Guide`, status-aware 12-point bento-grid spacing, full `Silent` Inspect asset generation without launching UI, healthy-result 15-minute cached summary replay, `Wi-Fi Strength`, and warning-only final dialog handling via `Computer Needs Attention`, while adding targeted remediation rechecks, Jamf Pro clock skew detection, historical Memory Pressure warnings, and improved macOS 27 compatibility, Bluetooth Sharing, staged-update, uptime, and detached-summary behavior.



### Health Checks

1. macOS Version
1. Available Updates (including deferred, staged, and DDM-enforced updates)
1. System Integrity Protection
1. Signed System Volume (SSV)
1. Firewall
1. FileVault Encryption
1. Gatekeeper / XProtect
1. Touch ID
1. Password Hint
1. AirDrop
1. AirPlay Receiver
1. Bluetooth Sharing
1. VPN Client
1. Last Reboot
1. Free Disk Space
1. User's Directory Size and Item Count
    - Desktop
    - Downloads
    - Trash
1. MDM Profile
1. Entra ID Registration
1. MDM Certificate Expiration
1. Apple Push Notification service
1. Jamf Pro Check-in
1. Jamf Pro Inventory
1. :new: Clock Skew
1. Extended Network Checks
    - Apple Push Notification Hosts
    - Apple Device Management
    - Apple Software and Carrier Updates
    - Apple Certificate Validation
    - Apple Identity and Content Services
    - Jamf Hosts
1. Wi-Fi Strength
1. App Auto-Patch
1. Homebrew Status
1. Electron Corner Mask [🔗](https://avarayr.github.io/shamelectron/)
1. Organizationally required Applications (i.e., Microsoft Teams)
1. BeyondTrust Privilege Management*
1. Cisco Umbrella*
1. CrowdStrike Falcon*
1. Palo Alto GlobalProtect*
1. :new: Memory Pressure
1. Network Quality Test
1. Update Computer Inventory**

*Requires [external check](/external-checks/README.md)
**Requires Jamf Pro

Jamf Pro runs check `Clock Skew` with `/usr/bin/sntp -n 1 -t 3 time.apple.com` before inventory submission. The command queries one DNS record with a 3-second SNTP timeout inside the existing 5-second outer timeout. Offsets greater than 5 minutes are flagged because they can prevent Jamf Pro inventory submission and other time-sensitive services from working correctly.

`Memory Pressure` records one sample whenever its check executes, including full health-check runs, nightly `Silent` Client-Side Cache refreshes, and targeted rechecks of an existing memory-pressure warning. It warns only when yellow or red pressure was observed on at least two distinct local calendar days within the previous seven days. A single critical reading, repeated runs on one day, low free-memory percentage, and swap use alone do not trigger a warning. Fewer than two days with valid pressure levels, an unavailable current pressure level, or a history write failure produce `Insufficient data` without changing the run's exit code. Cached Splunk uploads, healthy Inspect replay, and synthetic `Test` runs do not collect a sample.

History defaults to `${organizationDirectory}/MacHealthCheck-MemoryPressure-History.jsonl`, owned by root with `600` permissions. Each JSON Lines record contains ISO8601 and epoch timestamps, local sample date, hostname, script version, pressure level, free-memory percentage, and used swap in human-readable and byte forms. `memoryPressureHistoryPath`, `memoryPressureHistoryRetentionDays` (default `14`), `memoryPressureLookbackDays` (default `7`), and `memoryPressureRequiredAdverseDays` (default `2`) are configurable in `Mac-Health-Check.zsh`. Invalid or unavailable readings stay unknown; history failures affect only this check. The JSON report and Inspect summary use stable check key `memoryPressure`.

Jamf Pro inventory submission is a final follow-up action. In full Jamf Pro runs, `updateComputerInventory()` now surfaces failed or timed-out `jamf recon` submissions to the end-user, and times out that submission after `90` seconds.

### Information Reporting

<img src="images/MHC_3.2.0_Helpmessage.png" alt="In progress" width="800"/>

#### JSON / Splunk Reporting
- Generates a structured JSON health report at the end of every run
- Saves the report locally to `/Library/Management/org.churchofjesuschrist/MacHealthCheck-Report.json` by default with `600` permissions
- Keeps `/Library/Management/org.churchofjesuschrist/MacHealthCheck-Report.json` as the canonical root-only report artifact
- Adds `identity.entraIDRegistration` with `status`, `method`, `lastUser`, `lastUserHome`, and `details`
- Supports optional Splunk HEC delivery through Parameters 6-11 without changing the existing `operationMode` contract
- Wraps the finalized report as `{sourcetype, index, event}` when posting to Splunk HEC
- Supports `splunkOperationMode=off` to disable HEC delivery explicitly while still preserving local JSON report generation
- Preserves local report generation in `splunkOperationMode=test` while intentionally skipping network transmission
- Treats any unrecognized `splunkOperationMode` value as `test` (logged as `[ERROR]`); only an explicit `production` enables HEC delivery
- `Silent` plus `splunkOperationMode=production` mirrors only `Splunk Reporting:` lines to stdout; all other run output stays in `${scriptLog}`, and final exit returns success when local report generation plus HEC delivery both succeed, regardless of recorded health findings
- That `Silent` plus `splunkOperationMode=production` path also skips final Jamf Pro inventory submission while logging the skip to `${scriptLog}`
- Client-Side Cache avoids a full Jamf Pro health-check run when the client-side script at `/Library/Management/org.churchofjesuschrist/MHC.zsh` matches the server-side version and the cached JSON report is valid and fresh
- The client-side nightly run defaults to `operationMode="Silent"` and `splunkOperationMode="test"` so it updates the local report without sending to production Splunk, and its LaunchDaemon routes stdout/stderr to `/dev/null` so MHC-prefixed log writes are not duplicated
- Requires `jq` for JSON validation and formatting, with local report generation and Splunk payload assembly stopping at pre-flight if `jq` is unavailable; `/usr/bin/jq` (macOS 15 and later) is preferred, and `/usr/local/bin/jq` or `/opt/homebrew/bin/jq` is used only when the binary and every parent directory are root-owned and not group- or world-writable (a user-owned Homebrew `jq` is rejected)
- `Test` and `Development` runs write their local report to `/Library/Management/org.churchofjesuschrist/MacHealthCheck-Report-<mode>.json` instead of the canonical report, skip Splunk HEC delivery, and do not install the Client-Side Cache copy, so synthetic or curated results never replace production data; cached uploads and `Self Service` targeted rechecks also reject canonical reports whose `metadata.operationMode` is not `Self Service` or `Silent`
- Includes copy/paste Splunk SPL, Simple XML, and Dashboard Studio starter examples in [Resources/Splunk-Dashboard-Reference.md](Resources/Splunk-Dashboard-Reference.md)

#### Inspect Mode Summary
- `Self Service` and full `Silent` health-check runs now generate `/Library/Application Support/org.churchofjesuschrist/Inspect/MacHealthCheck-Inspect-Config.json` directly from finalized in-memory results
- `Self Service` and full `Silent` health-check runs also generate `/Library/Application Support/org.churchofjesuschrist/Inspect/MacHealthCheck-Inspect-Compliance.plist`, which feeds `plistSources`, `compliance-summary`, `findings-list` and live-bound bento-grid popovers
- The generated config includes `/Library/Application Support/org.churchofjesuschrist/Inspect/Users/<user>/MacHealthCheck-Inspect.trigger`, `/Library/Application Support/org.churchofjesuschrist/Inspect/Users/<user>/MacHealthCheck-Inspect.ready` and `/Library/Application Support/org.churchofjesuschrist/Inspect/Users/<user>/MacHealthCheck-Inspect-Result.json` control paths for Inspect Mode workflows
- `Self Service` automatically rechecks non-healthy `.checks[].key` values when the canonical report has a matching device, MDM vendor, script version and full-run baseline less than 36 hours old
- Targeted dialogs display contiguous check numbers immediately, while Inspect presents the authoritative Mac Health Check status separately from swiftDialog's weighted `Compliance Score`
- Jamf Pro targeted rechecks also run `Computer Inventory` so verified remediation reaches the server; nightly Client-Side Cache reports (which omit `Computer Inventory`) remain valid targeted-recheck and replay baselines
- Targeted rechecks send Slack or Microsoft Teams webhook messages only when at least one rechecked status differs from the previous report
- Targeted results replace only matching check records, preserve untouched results, add `checkedAt` / `checkedAtEpoch`, and expose `metadata.runScope`, full-run baseline fields and `summary.recheckedCount`
- Targeted writes use a shared report lock and rebase onto compatible concurrent report updates so newer full-report data is not overwritten
- Targeted writes cannot extend the 36-hour age of their underlying full-run baseline; missing, stale, malformed or incompatible reports fall back to all checks
- Parameter 11 `forceFreshRun=true` and `/var/tmp/MacHealthCheck-Force-Fresh-Run` bypass targeted verification and cached replay for a full `Self Service` run; the trigger file is honored only when root-owned (for example, `sudo touch /var/tmp/MacHealthCheck-Force-Fresh-Run`), and a trigger created by any other user is ignored and removed
- `Silent`, `Debug`, `Development` and `Test` retain their existing execution behavior; targeted selection is confined to `Self Service`
- Unhealthy runs now surface `Quick Actions Recommended` in `Overview`, add a conditional `Remediation Guide` step immediately after `Overview`, and keep `Unhealthy` as the audit-detail step
- Category bento-grid cards now use status-aware backgrounds so unhealthy checks stand out more clearly in Preset 6, and `Available Updates` now expands across two columns when action is required
- Plist-backed bento cells now emit FR #667 detail-sheet fields (`severity`, `explanation`, `remediation`, `actionButtonText`, `actionURL`) so warning and failure cards can explain why action is needed and link directly to next steps
- Normal `Self Service` runs launch the detached, always-on-top, moveable, minimisable swiftDialog Inspect Mode `preset6` guided summary after report generation while retaining the existing 60-second main-dialog countdown
- `Silent` runs never launch swiftDialog; they only write Inspect Mode config assets for later review
- The detached summary now separates recorded results into `Unhealthy` and `Healthy` sections and omits either section when no checks exist in that bucket
- Re-running `zsh Mac-Health-Check.zsh` with a healthy report within `inspectReplayMaximumAgeSeconds` (i.e., 15 minutes), replays the cached inspect summary immediately and skips the health checks plus the main dialog countdown
- `inspectSummaryPreset="on"` enables Preset 6 asset generation, `Self Service` launch and healthy-result cached replay; set it to `off` to disable all three
- Unhealthy `Self Service` runs now rely on the final unhealthy main-dialog state plus the detached inspect summary after report generation, without a separate pseudo-alert notification
- If inspect-summary asset generation or launch fails, Mac Health Check falls back to the existing `completionTimer` countdown path
- Targets swiftDialog `3.1.1.4997` or newer for PR #684 rendering; older compatible builds retain their prior Preset 6 appearance

Example Preset 6 JSON fragments used by generated inspect assets:

```json
{
  "key": "available_updates",
  "displayName": "Available Updates",
  "category": "Maintenance",
  "isCritical": true,
  "severity": "warning",
  "explanation": "A macOS update is ready for this Mac. Installing current updates helps keep this Mac secure and aligned with Church standards.",
  "remediation": "1. Open **System Settings**.\n2. Select **General > Software Update**.\n3. Install **macOS 26.5 (19-May-2026)**.\n4. Restart your Mac if prompted.\n5. Run **Mac Health Check** again.",
  "actionButtonText": "Open Software Update",
  "actionURL": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"
}
```

```json
{
  "id": "support_resources",
  "column": 0,
  "row": 0,
  "columnSpan": 3,
  "title": "Help & Support",
  "subtitle": "Action Recommended",
  "sfSymbol": "person.crop.circle.badge.questionmark",
  "contentType": "mixed",
  "detailOverlay": {
    "title": "Help & Support",
    "subtitle": "Action Recommended",
    "icon": "SF=person.crop.circle.badge.questionmark",
    "content": [
      {
        "type": "info",
        "content": "Use these support options if you need help completing recommended steps."
      }
    ],
    "showSystemInfo": false,
    "showProgressInfo": false,
    "closeButtonText": "Close"
  }
}
```

#### IT Support
- Dynamic `supportLabel1` / `supportValue1` through `supportLabel6` / `supportValue6`
- Empty Label / Value pairs are skipped automatically
- Legacy fallback still works when all dynamic pairs are empty:
  - Telephone (`supportTeamPhone`)
  - Email (`supportTeamEmail`)
  - Website (`supportTeamWebsite`)
  - Knowledge Base Article (`supportKBURL`)
- Info button target now uses the first URL-like dynamic support value; if none is found, it falls back to legacy Knowledge Base values

#### User Information
- Full Name
- User Name
- User ID
- Volume Owners
- Secure Token
- Location Services
- Microsoft OneDrive Sync Date
- Platform Single Sign-on Extension

#### Computer Information
- macOS version (build)
- System Memory
- System Storage
- Dialog version
- Script version
- Computer Name
- Serial Number
- Wi-Fi SSID
- Wi-FI IP Address
- VPN IP Address

#### Jamf Pro Information**
- Site

***[Payload Variables for Configuration Profiles](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-11.18.0/page/Computer_Configuration_Profiles.html#ariaid-title2)

### Policy Log Reporting

```
MHC (4.0.0): 2026-05-09 03:43:13 - [NOTICE] WARNING: 'localadmin' IS A MEMBER OF 'admin';
User: macOS Server Administrator (localadmin) [503] staff everyone localaccounts _appserverusr 
admin _appserveradm com.apple.sharepoint.group.4 com.apple.sharepoint.group.3
com.apple.sharepoint.group.1 _appstore _lpadmin _lpoperator _developer _analyticsusers
com.apple.access_ftp com.apple.access_screensharing com.apple.access_ssh com.apple.access_remote_ae
com.apple.sharepoint.group.2; Bootstrap Token supported on server: YES;
Bootstrap Token escrowed to server: YES; sudo Check: /etc/sudoers: parsed OK;
sudoers: root  ALL = (ALL) ALL %admin  ALL = (ALL) ALL ; Platform SSOe: localadmin NOT logged in;
Location Services: Enabled; SSH: On; Microsoft OneDrive Sync Date: Not Configured;
Time Machine Backup Date: Not configured; localadmin's Desktop Size: 160M for 116 item(s);
localadmin's Trash Size: 1.8M for 3 item(s); Battery Cycle Count: 0; Wi-Fi: Liahona;
Ethernet IP address: 17.113.201.250; VPN IP: 17.113.201.250; 
Network Time Server: time.apple.com; Jamf Pro Computer ID: 007; Site: Servers
```

1. Warning when logged-in user is a member of `admin`
1. Deferred Software Updates
1. Logged-In User Group Membership
1. Security Mode
1. DEP-allowed MDM Control
1. Activation Lock
1. Bootstrap Token
1. sudoers
1. Kerberos SSOe
1. Location Services
1. SSH
1. Time Machine
1. Battery Cycle Count
1. Network Time Server
1. Jamf Pro Computer ID



## Support

<a href="https://slack.com/app_redirect?channel=C0977DRT7UY" target="_blank"><img src="images/qr-code-Slack-mac-health-check.png" alt="Mac Admins Slack #mac-health-check Channel" width="300"/></a>

Community-supplied, best-effort support is available on the [Mac Admins Slack](https://www.macadmins.org/) (free, registration required) [#mac-health-check Channel](https://slack.com/app_redirect?channel=C0977DRT7UY), or you can open an [issue](https://github.com/dan-snelson/Mac-Health-Check/issues).



## Deployment

<a href="https://snelson.us/mhc" target="_blank"><img src="images/Deployment.png" alt="Deployment" width="600"/></a><br />
Deployment of Mac Health Check involves configuring organizational defaults, uploading the script to your MDM server, creating a policy to run it on demand and testing to ensure proper output and behavior.

<a href="https://snelson.us/mhc" target="_blank">Continue reading …</a>

### :new: Choosing Health Checks with an AI Assistant

[`Skills/mac-health-check-selector`](Skills/mac-health-check-selector/SKILL.md) is an AI-agnostic skill for choosing which checks to enable. It asks which MDM you use, presents a categorized checklist, and, after you confirm, writes an edited, MDM-specific, date-stamped copy, `Mac-Health-Check_<mdm-slug>_<YYYY-MM-DD-HHMMSS>.zsh`, with a sidecar `.md` that records the selection. Both files go to `Artifacts/` next to the source `Mac-Health-Check.zsh` by default; the helper's `--out-dir <dir>` overrides that, but the target must still be git-ignored (validation check 8). Only the MDM's list-item array and its matching `runConfiguredHealthCheck` branch change; `operationMode`, `developmentListitemJSON`, and every other setting keep their `Mac-Health-Check.zsh` defaults, so edit the artifact manually to change them. The skill builds and validates each artifact with its tested helper, `Skills/mac-health-check-selector/scripts/build-artifact.zsh`. The helper prints an explicit PASS or FAIL for `zsh -n`, `jq`, row-to-call alignment (including M15 and F1 order), diff scope, a Client-Side Cache simulation, `scriptVersion`, an unchanged source, and git-ignored output. It exits non-zero on any failure, and a failed build never lands in the output folder. Before deploying, test the artifact in all five modes on one Mac enrolled in the chosen MDM. `Mac-Health-Check.zsh` itself is never modified, and `Artifacts/` is git-ignored (see [`Artifacts/README.md`](Artifacts/README.md)).

#### Step-by-step

1. **Get the repository.** Clone `dan-snelson/Mac-Health-Check` or download a `5.0.0b6`+ release. The skill reads `Mac-Health-Check.zsh` from the same folder tree.
1. **Open the repository root in an AI assistant that can read and write local files and run shell commands** (for example, Claude Code, Codex CLI, Cursor, or GitHub Copilot agent mode). Without file access, the skill prints the artifact and sidecar as code blocks for you to save under `Artifacts/` yourself.
1. **Load the skill.** Prompt: `Read Skills/mac-health-check-selector/SKILL.md and follow it to help me choose Mac Health Check checks.` Assistants that honor `AGENTS.md` pick it up automatically.
   - Claude Code (optional): `mkdir -pv .claude/skills && ln -s ../../Skills/mac-health-check-selector .claude/skills/mac-health-check-selector`, then run `/mac-health-check-selector`.
1. **Answer the MDM question** (`1`–`9`; Filewave is `8`, Other / MDM-agnostic is `9`). Kandji / Iru admins: confirm your server URL, because only URLs containing `kandji` are detected.
1. **Pick checks** from the categorized checklist with IDs, ranges, or categories. Every reply changes the current list: `H7 A4` adds, `no A3` removes, `only C, H1-H6, M4` picks exactly those, and `defaults` resets. Unmarked checks are on by default, `[off]` checks are available but off, and `*` marks external checks (Jamf Pro only). A4 uses Microsoft Teams unless you name another app.
1. **Review the confirmation summary** (MDM, enabled check IDs, changes against the shipped default, artifact name), then reply `yes`, or adjust with the same grammar. Nothing is written before you confirm.
1. **Check the results.** The assistant reports the artifact path, the sidecar `.md` path, PASS/FAIL for validation checks 1–8, and the report keys the change removes or adds (for example, `electron_corner_mask`). The helper writes the complete sidecar, including every disabled check with its reason and the dependency notes that apply. Only passing artifacts are written to `Artifacts/` (the default output folder).
1. **Adjust other settings manually** (for example, `operationMode` or external-check triggers) in the artifact if needed, then re-run `zsh -n` on it.
1. **Test on one Mac enrolled in the chosen MDM** in all five modes:
   `sudo zsh ./Artifacts/<file>.zsh "" "" "" "Self Service"`, then repeat with `Silent`, `Debug`, `Development`, and `Test` as Parameter 4. `Development` runs the shipped `developmentListitemJSON` subset, not your selection. The script picks its MDM branch from the enrolled server URL, so a Mac enrolled in a different MDM runs that MDM's unedited checks. `Test` and `Development` runs never touch the canonical report or the Client-Side Cache copy. `Self Service` and `Debug` runs replace the Client-Side Cache copy and LaunchDaemon only when the running script is a root-owned file in root-controlled directories, so a copy run from a user-owned checkout logs `install skipped`; re-run your production policy afterwards.
1. **Deploy** the artifact as your MDM script. Keep `Debug` and `Development` out of production policies, and expect the first Self Service run to be a full run (`check_set_mismatch`).
1. **Keep artifacts out of version control** (`Artifacts/` is git-ignored), and build a fresh artifact after each Mac Health Check upgrade or for each additional MDM.



## Operation Mode: Development

A new "Development" Operation Mode has been added to aid in developing Health Checks, allowing quick runs against a small curated subset instead of the full suite.

When `operationMode` is set to `Development`, `5.0.0b6` uses a dedicated `developmentListitemJSON` for `Clock Skew` and `Memory Pressure` instead of running the entire suite.

```zsh
####################################################################################################
#
# Program
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Generate dialogJSONFile based on Operation Mode and MDM Vendor
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${operationMode}" == "Development" ]]; then
    
    notice "Operation Mode is ${operationMode}; using ${operationMode} dialogJSONFile template."

    # Development List Items

    developmentListitemJSON='
    [
        {"title" : "Clock Skew", "subtitle" : "Checks local clock offset against time.apple.com", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Memory Pressure", "subtitle" : "Reviews memory pressure across recent days", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
    ]
    '
    # Validate developmentListitemJSON is valid JSON
    if ! validateJson "${developmentListitemJSON}"; then
        echo "Error: developmentListitemJSON is invalid JSON"
        echo "$developmentListitemJSON"
        exit 1
    else
        combinedJSON=$( mergeDialogAndListItems "${mainDialogJSON}" "${developmentListitemJSON}" )
    fi

else
```

Additionally, the matching Health Check functions are executed:

```zsh
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Generate Health Checks based on Operation Mode and MDM Vendor (where "n" represents the listitem order)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${operationMode}" == "Development" ]]; then
    
    # Operation Mode: Development
    notice "Operation Mode is ${operationMode}; using ${operationMode}-specific Health Check."
    dialogUpdate "title: ${humanReadableScriptName} (${scriptVersion})<br>Operation Mode: ${operationMode}"
    set -x
    checkClockSkew "0"
    set +x
    checkMemoryPressure "1"

else
```
