# Mac Health Check: Health Check Reference

This text-only reference documents the key configurable defaults and runtime inventory for Mac Health Check `4.0.0b18`. No diagram is included; use [03-health-check-categories.md](03-health-check-categories.md) for a visual overview.

---

## 4.0.0b18 Runtime Notes

- `operationMode` is documented for the `4.0.0b18` release as `Self Service` by default, with `Silent`, `Debug`, `Development`, and `Test` also supported.
- `Self Service` runs now generate a readable inspect-summary config, launch a detached moveable swiftDialog Inspect Mode Preset 6 guided summary after the canonical report is written, separate recorded results into `Unhealthy` and `Healthy` sections, and retain the normal main-dialog completion countdown during full runs.
- Re-running in `Self Service` can replay the cached inspect summary after pre-flight and Client-Side Cache installation when the handoff assets are still valid and younger than `inspectReplayMaximumAgeSeconds`.
- `Development` mode currently runs only `checkWiFiStrength()` instead of the full vendor-specific suite.
- `inspectSummaryPreset` is an `on` / `off` toggle: `on` enables the fixed Preset 6 inspect summary and cached replay, while `off` disables both behaviors entirely.
- Non-`Silent` runs now distinguish warning-only results from failures in the final main-dialog state. In `Self Service` with `inspectSummaryPreset="on"`, the detached inspect summary remains the post-run issue-detail surface.
- Pre-flight requires swiftDialog `3.1.0.4976` or newer.
- When `enableDockIntegration` is `true`, non-`Silent` runs show a Dock icon with a decreasing `dockiconbadge` count.
- Client-Side Cache installs a client-side script at `/Library/Management/org.churchofjesuschrist/MHC.zsh` and a `org.churchofjesuschrist.MHC` LaunchDaemon for nightly `Silent` report refreshes.
- The LaunchDaemon plist is validated before loading, does not include `RunAtLoad`, uses `launchDaemonRun=true`, and relies on deterministic per-Mac jitter so clients run across 00:53-01:53 instead of all starting at the 1:23 a.m. nominal target.
- LaunchDaemon-triggered refreshes use loginwindow `lastUserName` for user-scoped checks when no GUI user is active.
- Jamf Pro `Silent` + `splunkOperationMode=production` uploads cached JSON only when client/server versions match and the report is valid and younger than 36 hours; otherwise it runs the full health check and installs or refreshes the Client-Side Cache assets.
- `checkAvailableSoftwareUpdates()` includes deferred and DDM-enforced OS update handling.
- `checkFreeDiskSpace()` prefers Finder-aligned available capacity and falls back to `diskutil info /` when needed.
- `checkWiFiStrength()` uses `wdutil info` when available, falls back to the legacy `airport` binary, and treats Wi-Fi-inactive / Ethernet-primary systems as a non-failure skip.
- `checkHomebrewStatus()` compares the installed Homebrew release and local outdated package counts without auto-updating Homebrew metadata.
- Help and support content is built dynamically from `supportLabelN` / `supportValueN` pairs, with legacy support fields used as a fallback.
- `updateComputerInventory()` is the final Jamf Pro-specific check in the Jamf Pro check set.

---

## Organization Defaults Reference

Core UI and behavior defaults live in the **Organization Variables** section of `Mac-Health-Check.zsh`. Support contact values live later in the **IT Support Variables** section.

| Variable | Default Value | Description | Valid Values |
|---|---|---|---|
| `humanReadableScriptName` | `"Mac Health Check"` | Display name shown in the dialog title | Any string |
| `organizationScriptName` | `"MHC"` | Short identifier used in log entries | Any short string |
| `reverseDomainNameNotation` | `"org.churchofjesuschrist"` | Reverse-domain base used for management paths and LaunchDaemon labels | Reverse-domain string |
| `organizationDirectory` | `"/Library/Management/${reverseDomainNameNotation}"` | Client-Side Cache script directory | Local root-owned directory |
| `clientSideScriptPath` | `"${organizationDirectory}/${organizationScriptName}.zsh"` | Client-Side Cache script path | Local root-owned Zsh script |
| `launchDaemonLabel` | `"${reverseDomainNameNotation}.${organizationScriptName}"` | LaunchDaemon label for nightly client-side report refresh | LaunchDaemon label |
| `launchDaemonPath` | `"/Library/LaunchDaemons/${launchDaemonLabel}.plist"` | LaunchDaemon plist path | `/Library/LaunchDaemons/*.plist` |
| `clientSideJitterEnabled` | `"true"` | Enables deterministic per-Mac LaunchDaemon jitter | `true` \| `false` |
| `clientSideMaxJitterSeconds` | `"1800"` | Maximum signed jitter around 1:23 a.m.; LaunchDaemon wakes at window start and script sleeps a non-negative derived delay | Integer seconds |
| `clientSideMaximumCacheAgeSeconds` | `"129600"` | Maximum cached report age before Jamf falls back to a full health check | Integer seconds |
| `organizationSelfServiceMarketingName` | `"Workforce App Store"` | Your MDM Self Service portal name | Any string |
| `organizationBoilerplateComplianceMessage` | `"Meets organizational standards"` | Subtitle shown for passing checks | Any string |
| `organizationBrandingBannerURL` | Freepik sample URL | Banner image displayed at the top of the dialog | HTTPS URL or local path |
| `organizationOverlayiconURL` | `"/System/Library/CoreServices/Apple Diagnostics.app"` | Icon overlaid on the dialog banner; local paths and `file://` targets are used in place, while remote URLs download to a script-managed temporary file that is removed at exit | App path \| local path \| `file://` path \| `http(s)` URL |
| `enableDockIntegration` | `"true"` | Show a Dock icon with countdown badge in non-`Silent` modes | `true` \| `false` |
| `dockIcon` | Jamf Cloud icon URL | Icon source for Dock integration | `default` \| local path \| `file://` path \| `http(s)` URL |
| `organizationDefaultsDomain` | `"org.churchofjesuschrist.external"` | Defaults domain shared with external check policies | Reverse-domain string |
| `organizationColorScheme` | `"weight=semibold,colour1=#2E5B91,colour2=#4291C8"` | SF Symbol color scheme for list item icons | swiftDialog color string |
| `kerberosRealm` | `""` (blank) | Kerberos realm for SSO checks; leave blank to disable | REALM string or `""` |
| `organizationFirewall` | `"socketfilterfw"` | Firewall type to evaluate | `socketfilterfw` \| `pf` |
| `vpnClientVendor` | `"paloalto"` | VPN client to check; set to `none` to skip VPN check | `none` \| `paloalto` \| `cisco` \| `tailscale` |
| `vpnClientDataType` | `"extended"` | Level of VPN status detail to collect | `basic` \| `extended` |
| `anticipationDuration` | `"2"` (or `"0"` in Silent mode) | Pause between checks, in seconds | Any integer string |
| `previousMinorOS` | `"2"` | Number of older minor macOS releases considered compliant | Integer string (`"0"`–`"5"`) |
| `allowedMinimumFreeDiskPercentage` | `"10"` | Free disk space below this percentage triggers an error | Integer string |
| `allowedMaximumDirectoryPercentage` | `"5"` | User directory (Desktop/Downloads/Trash) above this percentage of total disk triggers a warning | Integer string |
| `networkQualityTestMaximumAge` | `"1H"` | Maximum age of a cached network quality result before re-running | `date -v-` suffix: `y`, `m`, `w`, `d`, `H`, `M`, `S` |
| `allowedUptimeMinutes` | `"10080"` | Uptime above this threshold triggers an alert (10,080 min = 7 days) | Integer string |
| `excessiveUptimeAlertStyle` | `"warning"` | Severity when uptime exceeds `allowedUptimeMinutes` | `warning` \| `error` |
| `completionTimer` | `"60"` | Seconds before the fallback final dialog countdown auto-closes | Integer string |

---

## IT Support Variables Reference

The support/help experience uses both legacy support fields and dynamic `supportLabelN` / `supportValueN` pairs.

| Variable | Default Value | Description |
|---|---|---|
| `supportTeamName` | `"IT Support"` | Heading shown in the help message |
| `supportTeamPhone` | `"+1 (801) 555-1212"` | Legacy telephone fallback |
| `supportTeamEmail` | `"rescue@domain.org"` | Legacy email fallback |
| `supportTeamWebsite` | `"https://support.domain.org"` | Legacy website fallback and failure-notification support target |
| `supportKB` | `"KB8675309"` | Knowledge base identifier used to build the legacy KB link |
| `supportLabel1`–`supportLabel6` | Mixed defaults / blanks | Dynamic support labels shown in the help message |
| `supportValue1`–`supportValue6` | Mixed defaults / blanks | Matching dynamic support values; empty pairs are skipped |

**4.0.0b18 behavior notes**

- If all `supportLabelN` / `supportValueN` pairs are blank, the script falls back to the legacy `supportTeam*` and KB values.
- The first URL-like `supportValueN` becomes the Info button action in the dialog.
- Help content also includes `Volume Owners`, `Secure Token`, `Location Services`, `Microsoft OneDrive Sync Date`, and `Platform SSOe`.

---

## Health Check Inventory

The table below lists every health check function, its human-readable name, and whether it is included in each MDM vendor's check set.

**Legend:** ✅ Included · — Not included

| Category | Function | Human-Readable Name | Addigy | Filewave | Fleet | Jamf Pro | JumpCloud | Kandji | Intune | Mosyle | Generic |
|---|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| System | `checkOS()` | macOS Version | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| System | `checkAvailableSoftwareUpdates()` | Available Updates | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| System | `checkSIP()` | System Integrity Protection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| System | `checkSSV()` | Signed System Volume | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| System | `checkGatekeeperXProtect()` | Gatekeeper / XProtect | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| System | `checkFirewall()` | Firewall | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| System | `checkFileVault()` | FileVault | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| User | `checkTouchID()` | Touch ID | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| User | `checkAirDropSettings()` | AirDrop | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ |
| User | `checkAirPlayReceiver()` | AirPlay Receiver | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ |
| User | `checkBluetoothSharing()` | Bluetooth Sharing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| User | `checkPasswordHint()` | Password Hint | ✅ | ✅ | ✅ | — | ✅ | — | ✅ | ✅ | ✅ |
| User | `checkVPN()` | VPN Client | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| User | `checkUptime()` | Last Reboot | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Disk | `checkFreeDiskSpace()` | Free Disk Space | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Disk | `checkUserDirectorySizeItems()` | Desktop Size and Item Count | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Disk | `checkUserDirectorySizeItems()` | Downloads Size and Item Count | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Disk | `checkUserDirectorySizeItems()` | Trash Size and Item Count | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| MDM | `checkMdmProfile()` | MDM Profile | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | — |
| MDM | `checkAPNs()` | Apple Push Notification service | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| MDM | `checkMdmCertificateExpiration()` | MDM Certificate Expiration | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| MDM | `checkJamfProCheckIn()` | Jamf Pro Check-In | — | — | — | ✅ | — | — | — | — | — |
| MDM | `checkJamfProInventory()` | Jamf Pro Inventory | — | — | — | ✅ | — | — | — | — | — |
| MDM | `checkMosyleCheckIn()` | Mosyle Check-In | — | — | — | — | — | — | — | ✅ | — |
| Network | `checkNetworkHosts()` | Apple Push Notification Hosts | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network | `checkNetworkHosts()` | Apple Device Management | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network | `checkNetworkHosts()` | Apple Software and Carrier Updates | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network | `checkNetworkHosts()` | Apple Certificate Validation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network | `checkNetworkHosts()` | Apple Identity and Content Services | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network | `checkNetworkHosts()` | Jamf Hosts | — | — | — | ✅ | — | — | — | — | — |
| Network | `checkWiFiStrength()` | Wi-Fi Strength | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network | `checkNetworkQuality()` | Network Quality Test | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Apps | `checkAppAutoPatch()` | App Auto-Patch | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | — |
| Apps | `checkHomebrewStatus()` | Homebrew Status | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ |
| Apps | `checkElectronCornerMask()` | Electron Corner Mask | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ |
| Apps | `checkInternal()` | Microsoft Teams | ✅ | — | ✅ | ✅ | ✅ | ✅ | — | — | — |
| Apps | `checkInternal()` | Microsoft One Drive | — | — | — | — | — | ✅ | — | — | — |
| Apps | `checkInternal()` | Microsoft Outlook | — | — | — | — | — | ✅ | — | — | — |
| Apps | `checkInternal()` | Company Portal | — | — | — | — | — | ✅ | — | — | — |
| Apps | `checkInternal()` | Microsoft Company Portal | — | — | — | — | — | — | ✅ | — | — |
| Apps | `checkInternal()` | Zoom | — | — | — | — | — | ✅ | — | — | — |
| Apps | `checkInternal()` | Cortex | — | — | — | — | — | ✅ | — | — | — |
| Apps | `checkInternal()` | Netskope | — | — | — | — | — | ✅ | — | — | — |
| Apps | `checkInternal()` | Fleet Desktop | — | — | ✅ | — | — | — | — | — | — |
| Apps | `checkInternal()` | Self-Service | — | — | — | — | — | — | — | ✅ | — |
| External | `checkExternalJamfPro()` | BeyondTrust Privilege Management | — | — | — | ✅ | — | — | — | — | — |
| External | `checkExternalJamfPro()` | Cisco Umbrella | — | — | — | ✅ | — | — | — | — | — |
| External | `checkExternalJamfPro()` | CrowdStrike Falcon | — | — | — | ✅ | — | — | — | — | — |
| External | `checkExternalJamfPro()` | Palo Alto GlobalProtect | — | — | — | ✅ | — | — | — | — | — |
| Inventory | `updateComputerInventory()` | Computer Inventory | — | — | — | ✅ | — | — | — | — | — |

---

## Check Set Sizes by MDM Vendor

| MDM Vendor | Total Checks |
|---|---|
| Jamf Pro | 39 |
| Mosyle | 33 |
| Addigy | 32 |
| Filewave | 31 |
| Fleet | 32 |
| JumpCloud | 32 |
| Kandji | 31 |
| Microsoft Intune | 32 |
| Generic / None | 28 |

> **Note:** `checkNetworkHosts()` is called once per host group; the five Apple host groups plus the Jamf-specific host group each count as one check. `checkUserDirectorySizeItems()` is called three times (Desktop, Downloads, Trash) and each counts as one check.

---

## External Checks Reference

External checks require separate MDM policies using the scripts in the `external-checks/` directory. They are currently only invoked in the **Jamf Pro** check set.

| Trigger Name | Tool | Required App Path | Plugin Script |
|---|---|---|---|
| `symvBeyondTrustPMfM` | BeyondTrust Privileged Access Management | `/Applications/PrivilegeManagement.app` | `BeyondTrust Privileged Access Management.bash` |
| `symvCiscoUmbrella` | Cisco Umbrella | `/Applications/Cisco/Cisco Secure Client.app` | `Cisco Umbrella.bash` |
| `symvCrowdStrikeFalcon` | CrowdStrike Falcon | `/Applications/Falcon.app` | `CrowdStrike Falcon Status.bash` |
| `symvGlobalProtect` | Palo Alto GlobalProtect | `/Applications/GlobalProtect.app` | `Palo Alto Networks GlobalProtect Status.bash` |

Each external check policy writes results to `organizationDefaultsDomain` using three keys: `checkStatus`, `checkType` (`fail` / `success` / `error`), and `checkExtended`. The main script reads these keys after invoking the policy trigger.

---

## Script Parameters

| Parameter | Variable | Default | Description |
|---|---|---|---|
| 4 | `operationMode` | `Self Service` | Operation mode: `Self Service`, `Silent`, `Debug`, `Development`, `Test` |
| 5 | `webhookURL` | (blank) | Microsoft Teams or Slack webhook URL for unhealthy-run summaries; leave blank to disable |
| 6 | `splunkOperationMode` | `test` | Reporting mode: `off` disables HEC delivery, `production` posts to Splunk when configured, and `test` skips transmission while still generating the JSON report |
| 7 | `splunkHECURL` | (blank) | Splunk HTTP Event Collector URL; leave blank to disable transmission |
| 8 | `splunkHECToken` | (blank) | Splunk HEC token; never logged by the script |
| 9 | `splunkHECIndex` | (blank) | Optional Splunk HEC index value included in the transmission wrapper payload |
| 10 | `splunkHECSourcetype` | (blank) | Optional Splunk HEC sourcetype value included in the transmission wrapper payload |
| 11 | `reportDebug` | `false` | Enables pretty-printed local JSON and verbose sanitized reporting output |
