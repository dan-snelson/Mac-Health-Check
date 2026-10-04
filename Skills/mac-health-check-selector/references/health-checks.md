# Mac Health Check — Health Check Reference

Companion reference for the `mac-health-check-selector` skill. Derived from `Mac-Health-Check.zsh` `5.0.0`. When this file and the script disagree, the script wins. `scripts/build-artifact.zsh --list <slug>` prints the script's current rows and calls for any MDM.

## How the pieces fit

Each MDM has two coupled structures in `Mac-Health-Check.zsh`:

1. A list-item array, such as `jamfProListitemJSON='[ … ]'`, which defines the rows swiftDialog shows.
2. A matching branch in the `case ${mdmVendor} in` block under **Generate Health Checks based on Operation Mode and MDM Vendor**, made of `runConfiguredHealthCheck "<index>" <function> [args …]` lines.

Rules that keep them aligned:

- Index `n` in `runConfiguredHealthCheck "n"` is the zero-based position of the matching row in the list-item array.
- The row icon is `SF=NN.circle`, where `NN` is `n + 1`, zero-padded to two digits (`01`, `02`, … `42`).
- The last array element has no trailing comma.
- The row `title`, after `'${mdmVendor}'` expands at runtime, becomes the stable report key through `sanitizeCheckKey` (lowercase, non-alphanumerics → `_`, doubled `_` collapsed once, one leading and trailing `_` trimmed). `Memory Pressure` is special-cased to `memoryPressure`. Renaming or dropping a title renames or drops its key.
  - Examples: `Electron Corner Mask` → `electron_corner_mask`; `Gatekeeper / XProtect` → `gatekeeper__xprotect`; M1 on Intune → `microsoft_intune_mdm_profile`.
  - `scripts/build-artifact.zsh` loads `sanitizeCheckKey` from the source script and lists the keys removed or added for each artifact.
- `Development` mode ignores the MDM arrays. It uses `developmentListitemJSON` and calls check functions directly (for example `checkClockSkew "0"`), without `runConfiguredHealthCheck`.
- `Test` mode uses the MDM array but runs no real checks; it walks every row and marks it compliant.

## Script-to-selector MDM map

| # | Selector choice (display name) | `mdmVendor` value | List-item array | `serverURL` match | Profile lookup |
|---|---|---|---|---|---|
| 1 | Jamf Pro | `Jamf Pro` | `jamfProListitemJSON` | `*jamf*` or `*jss*` | `mdmVendorUuid` |
| 2 | Fleet | `Fleet` | `fleetMdmListitemJSON` | `*fleet*` | `mdmVendorUuid` |
| 3 | JumpCloud | `JumpCloud` | `jumpcloudMdmListitemJSON` | `*jumpcloud*` | `mdmProfileIdentifier` |
| 4 | Microsoft Intune | `Microsoft Intune` | `microsoftMdmListitemJSON` | `*microsoft*` | `mdmVendorUuid` |
| 5 | Mosyle | `Mosyle` | `mosyleListitemJSON` | `*mosyle*` | `mdmProfileIdentifier` |
| 6 | Kandji / Iru | `Kandji` | `kandjiMdmListitemJSON` | `*kandji*` | `mdmProfileIdentifier` |
| 7 | Addigy | `Addigy` | `addigyMdmListitemJSON` | `*addigy*` | `mdmVendorUuid` (blank by default) |
| 8 | Filewave | `Filewave` | `filewaveMdmListitemJSON` | `*filewave*` | `mdmProfileIdentifier` |
| 9 | Other / MDM-agnostic | `None` (falls to `*`) | `genericMdmListitemJSON` | no match, or not enrolled | none |

The display name is what the helper prints and what the sidecar uses; `mdmVendor` is the script value.

Notes:

- An Iru-branded server URL that does not contain `kandji` falls through to the generic branch; add a pattern to the `case "${serverURL}" in` block if needed.
- Addigy ships with `mdmVendorUuid=""`; the MDM Profile check needs a UUID or identifier to pass.
- The generic branch omits MDM Profile and MDM Certificate Expiration because no vendor profile or certificate name is known. It also runs on unenrolled Macs (logged as `Unknown MDM vendor: None`), where M4 Apple Push Notification service warns (`APNs active; no MDM response`) or fails.

## Artifact anchors per MDM

Used by `references/artifact-procedure.md`.

- **Region A** runs from the array start line (column 1) through the next line that is exactly `'`.
- **Region B** runs from the branch label line (12 spaces) through the next `                ;;`. It sits inside the first `        case ${mdmVendor} in` after the header `# Generate Health Checks based on Operation Mode and MDM Vendor`.
- This file lists no line numbers because they drift with every release. Always anchor on the text. `zsh scripts/build-artifact.zsh --list <slug>` prints the live ranges.
- Rows follow the script's `case "${serverURL}" in` detection order, with the generic fallback last.

| Slug | Region A start line | Region B label line | Detection pattern (`case "${serverURL}" in`) |
|---|---|---|---|
| `addigy` | `addigyMdmListitemJSON='` | `"Addigy" )` | `*addigy* )` |
| `filewave` | `filewaveMdmListitemJSON='` | `"Filewave" )` | `*filewave* )` |
| `fleet` | `fleetMdmListitemJSON='` | `"Fleet" )` | `*fleet* )` |
| `jamf-pro` | `jamfProListitemJSON='` | `"Jamf Pro" )` | `*jamf* \| *jss* )` |
| `jumpcloud` | `jumpcloudMdmListitemJSON='` | `"JumpCloud" )` | `*jumpcloud* )` |
| `kandji` | `kandjiMdmListitemJSON='` | `"Kandji" )` | `*kandji* )` |
| `microsoft-intune` | `microsoftMdmListitemJSON='` | `"Microsoft Intune" )` | `*microsoft* )` |
| `mosyle` | `mosyleListitemJSON='` | `"Mosyle" )` | `*mosyle* )` |
| `generic` | `genericMdmListitemJSON='` | `* )` | `* )` (never pruned) |

Pitfalls:

- Array names are inconsistent. Most end in `MdmListitemJSON`, but Jamf Pro is `jamfProListitemJSON` and Mosyle is `mosyleListitemJSON`.
- Kandji's Cortex and Netskope rows carry trailing whitespace after `},`. Strip trailing whitespace before handling commas.
- Vendor labels also appear in other `case` blocks: configuration, help message, report JSON, webhooks, `quitScript`, MDM certificate names, and dialog JSON merging. Never anchor on the label alone.
- Every shipped MDM region pairs row `i` with call `i` and holds only `runConfiguredHealthCheck` lines; the helper stops with exit `2` if that stops being true.

Vendor `case` blocks pruned by `--prune-other-mdms` (anchor on the `case` line, never on line numbers):

- `case "${serverURL}" in` (detection), then each `case ${mdmVendor} in` / `case "${mdmVendor}" in`: Configuration Profile Variables (Jamf Pro only), help message (Jamf Pro only), `buildMacHealthReportJSON` (Jamf Pro, Mosyle), webhook `computerMdmURL` (Jamf Pro, Mosyle, `* )`), quit notice (Jamf Pro only), `checkMdmCertificateExpiration` (all, `* )`), dialog JSON merging (one-liners, all, `* )`), and the health-check block (Region B).
- A new vendor label in any of these blocks must be added to the helper's `slugVendor` / `slugDetect` maps; otherwise pruning stops with exit `2`.

### Vendor-owned symbols

Removed by `--prune-other-mdms` only when the owner is pruned and no selected call still names the symbol.

| Symbol | Owner | Kind | Called by |
|---|---|---|---|
| `checkJamfProCheckIn` | Jamf Pro | function | M5 |
| `checkJamfProInventory` | Jamf Pro | function | M6 |
| `checkExternalJamfPro` | Jamf Pro | function | A6–A10 |
| `updateComputerInventory` | Jamf Pro | function | F1 |
| `jamfHosts` | Jamf Pro | array | M13 (`checkNetworkHosts "Jamf Hosts"`) |
| `checkMosyleCheckIn` | Mosyle | function | M7 |

`checkEntraIDRegistration` (M2) and `checkClockSkew` (H7) ship only for Jamf Pro but run on any MDM, so they are never pruned.

Client-Side Cache constraint:

- `installClientSideScript` removes the `Computer Inventory` row and strips a trailing comma only from the `Network Quality Test` row.
- M15 must therefore be the last row, or sit directly before F1. Otherwise the cached nightly copy has invalid JSON.

## Master check table

Legend — **Avail**: `All` = safe on any MDM; `Jamf` = Jamf Pro only; `Vendor` = needs a known `mdmVendor`; `Ext` = needs an external-check script plus a Jamf Pro policy trigger. In **Notes**, "warning" (or "warns") means the row shows the dialog `error` status, which the JSON report records as `warning`.

`scripts/build-artifact.zsh` carries the same ID-to-title map (including Kandji `A5a`–`A5f`) and restricted-availability list; update both when a check, title, or availability changes.

### Core OS & Security (C)

| ID | Title | Call | Avail | Notes |
|---|---|---|---|---|
| C1 | macOS Version | `checkOS` | All | Current and previous major releases are compliant |
| C2 | Available Updates | `checkAvailableSoftwareUpdates` | All | Covers deferred, staged, and DDM-enforced updates |
| C3 | System Integrity Protection | `checkSIP` | All | |
| C4 | Signed System Volume | `checkSSV` | All | |
| C5 | Firewall | `checkFirewall` | All | Honors `organizationFirewall` |
| C6 | FileVault Encryption | `checkFileVault` | All | |
| C7 | Gatekeeper / XProtect | `checkGatekeeperXProtect` | All | |
| C8 | Touch ID | `checkTouchID` | All | Reports `error` when Touch ID hardware is absent (VMs, desktops without a Touch ID keyboard) |
| C9 | Password Hint | `checkPasswordHint` | All | Not in Jamf Pro or Kandji defaults |
| C10 | AirDrop | `checkAirDropSettings` | All | Not in Kandji default |
| C11 | AirPlay Receiver | `checkAirPlayReceiver` | All | Not in Kandji default; macOS 27 missing-key aware |
| C12 | Bluetooth Sharing | `checkBluetoothSharing` | All | macOS 27 missing-domain aware |
| C13 | VPN Client | `checkVPN` | All | Honors `vpnClientVendor` (shipped `paloalto`) and `vpnClientDataType`; fails when that client is absent |

### Maintenance & Hygiene (H)

| ID | Title | Call | Avail | Notes |
|---|---|---|---|---|
| H1 | Last Reboot | `checkUptime` | All | |
| H2 | Free Disk Space | `checkFreeDiskSpace` | All | |
| H3 | Desktop Size and Item Count | `checkUserDirectorySizeItems "Desktop" "desktopcomputer.and.macbook" "Desktop"` | All | User-scoped |
| H4 | Downloads Size and Item Count | `checkUserDirectorySizeItems "Downloads" "folder.fill.badge.plus" "Downloads"` | All | Kandji default uses icon `arrow.down.circle.fill` |
| H5 | Trash Size and Item Count | `checkUserDirectorySizeItems ".Trash" "trash.fill" "Trash"` | All | User-scoped |
| H6 | Memory Pressure | `checkMemoryPressure` | All | Warning-only; root-only 14-day JSON Lines history; warns when yellow/red pressure appears on 2 distinct days within 7 days |
| H7 | Clock Skew | `checkClockSkew` | All (Jamf default) | Queries `time.apple.com` with `sntp` (NTP, UDP 123); skew over 300 seconds fails; blocked NTP or no reply reports `Unable to determine` (warning). Hides dialog updates in `Silent` and `Test`. Outside Jamf Pro the helper uses the neutral subtitle below |

### MDM & Connectivity (M)

| ID | Title | Call | Avail | Notes |
|---|---|---|---|---|
| M1 | `'${mdmVendor}' MDM Profile` | `checkMdmProfile` | Vendor | Needs `mdmVendorUuid` or `mdmProfileIdentifier` |
| M2 | Entra ID Registration | `checkEntraIDRegistration` | Jamf default | Reads the JamfAAD plist, Platform SSO (through Jamf Conditional Access), and the user's legacy MS-ORGANIZATION-ACCESS certificate. With none present it passes as `Not Applicable`. Without the JamfAAD plist (the norm on non-Jamf MDMs), that certificate reports `Partial` (warning); review before using elsewhere |
| M3 | `'${mdmVendor}' MDM Certificate Expiration` | `checkMdmCertificateExpiration` | Vendor | Certificate name mapped per vendor |
| M4 | Apple Push Notification service | `checkAPNs` | All | Reads 24 hours of logs from processes under `/System/` or `/usr/libexec/` only. Passes on a ManagedClient MDM response (HTTP 200); fails with `MDM identity error` when error -25304 is newer than the last MDM response; warns (`APNs active; no MDM response`) on `apsd` courier activity without an MDM response; fails when neither appears |
| M5 | Jamf Pro Check-In | `checkJamfProCheckIn` | Jamf | Reads `jamf.log` |
| M6 | Jamf Pro Inventory | `checkJamfProInventory` | Jamf | |
| M7 | Mosyle Check-In | `checkMosyleCheckIn` | Mosyle only | |
| M8 | Apple Push Notification Hosts | `checkNetworkHosts "Apple Push Notification Hosts" "${pushHosts[@]}"` | All | |
| M9 | Apple Device Management | `checkNetworkHosts "Apple Device Management" "${deviceMgmtHosts[@]}"` | All | |
| M10 | Apple Software and Carrier Updates | `checkNetworkHosts "Apple Software and Carrier Updates" "${updateHosts[@]}"` | All | |
| M11 | Apple Certificate Validation | `checkNetworkHosts "Apple Certificate Validation" "${certHosts[@]}"` | All | |
| M12 | Apple Identity and Content Services | `checkNetworkHosts "Apple Identity and Content Services" "${idAssocHosts[@]}"` | All | |
| M13 | Jamf Hosts | `checkNetworkHosts "Jamf Hosts" "${jamfHosts[@]}"` | Jamf | |
| M14 | Wi-Fi Strength | `checkWiFiStrength` | All | |
| M15 | Network Quality Test | `checkNetworkQuality` | All | Slowest check; runs `networkQuality` |

### Applications & Tools (A)

| ID | Title | Call | Avail | Notes |
|---|---|---|---|---|
| A1 | App Auto-Patch | `checkAppAutoPatch` | All | Expects App Auto-Patch installed; reads the 4.x system log, then the 3.x root log, and the per-user log only when neither exists; fails when no log exists |
| A2 | Homebrew Status | `checkHomebrewStatus` | All | Passes when Homebrew is absent |
| A3 | Electron Corner Mask | `checkElectronCornerMask` | All | macOS 26 GPU slowdown detection |
| A4 | Microsoft Teams | `checkInternal "/Applications/Microsoft Teams.app" "/Applications/Microsoft Teams.app" "Microsoft Teams"` | All | Template for any required app |
| A5 | MDM agent app | `checkInternal "<appPath>" "<iconPath>" "<displayName>"` | Vendor | See **MDM agent apps** below |
| A6 | BeyondTrust Privilege Management | `checkExternalJamfPro "symvBeyondTrustPMfM" "/Applications/PrivilegeManagement.app"` | Ext | |
| A7 | Cisco Umbrella | `checkExternalJamfPro "symvCiscoUmbrella" "/Applications/Cisco/Cisco Secure Client.app"` | Ext | |
| A8 | CrowdStrike Falcon | `checkExternalJamfPro "symvCrowdStrikeFalcon" "/Applications/Falcon.app"` | Ext | |
| A9 | Palo Alto GlobalProtect | `checkExternalJamfPro "symvGlobalProtect" "/Applications/GlobalProtect.app"` | Ext | Disconnected reports as warning |
| A10 | Other external check | `checkExternalJamfPro "<customTrigger>" "<appPath>"` | Ext | Scripts in `external-checks/` |

`checkInternal` arguments: `<file or app to test for>` `<icon path>` `<display name>`. It verifies presence only.

`checkExternalJamfPro` arguments: `<Jamf Pro policy custom trigger>` `<app path for icon>`. It is Jamf Pro-only. On other MDMs, use `checkInternal` for presence or write a new `checkXxx` function. It runs `jamf policy -event <trigger>` and sets the row in this order:

1. **Timeout:** a policy still running after `externalCheckTimeoutSeconds` (default `120`) is stopped and reports `Timed Out`.
2. **Defaults domain:** when the script wrote `checkType`, `checkStatus`, and `checkExtended` to `organizationDefaultsDomain` (the Microsoft Defender Check and TenableNessusAgent-Alternate samples), `checkType` sets the status (`success`, `warning`, `fail`, or `error`; anything else is `error`) and `checkStatus` the status text. Keywords are not matched.
3. **Keywords:** otherwise the policy's `Script result:` (or `<result>`) text is matched case-insensitively: `Failed` or `Not Running` (fail), then `Running` (pass), then `Warning`. `Error`, `Not Installed`, and unmatched output show `Error`.

`Timed Out`, `Warning`, and `Error` rows use the dialog `error` status, which the JSON report records as `warning`.

Scripts shipped in `external-checks/`: BeyondTrust Privileged Access Management, Check Printer Install, Cisco Umbrella, CrowdStrike Falcon Status, Microsoft Defender Check, Microsoft Office 365, Nessus Agent Status, Palo Alto Networks GlobalProtect Status, Sophos Endpoint RTS, Splunk Universal Forwarder Check, TenableNessusAgent-Alternate, Zscaler Tunnel Status.

### Follow-up Actions (F)

| ID | Title | Call | Avail | Notes |
|---|---|---|---|---|
| F1 | Computer Inventory | `updateComputerInventory` | Jamf | Runs `jamf recon` with 90-second timeout; must be last; skipped in `Silent` + `splunkOperationMode=production`; removed from Client-Side Cache copy |

### MDM agent apps (A5 and friends)

Show A5 in the checklist with the concrete title for the chosen MDM. Jamf Pro, JumpCloud, Addigy, Filewave, and Other ship no agent app; list A5 under "Not available" and offer an A4-style custom app instead.

| MDM | ID | Title | `checkInternal` args |
|---|---|---|---|
| Fleet | A5 | Fleet Desktop | `"/opt/orbit/bin/desktop/macos/stable/Fleet Desktop.app" "/opt/orbit/bin/desktop/macos/stable/Fleet Desktop.app" "Fleet Desktop"` |
| Microsoft Intune | A5 | Microsoft Company Portal | `"/Applications/Company Portal.app" "/Applications/Company Portal.app" "Microsoft Company Portal"` |
| Mosyle | A5 | `'${mdmVendor}' Self-Service` | `"/Applications/Self-Service.app" "/Applications/Self-Service.app" "Self-Service"` |
| Kandji / Iru | A5a | Microsoft One Drive | `"/Applications/OneDrive.app" …` |
| Kandji / Iru | A5b | Microsoft Outlook | `"/Applications/Microsoft Outlook.app" …` |
| Kandji / Iru | A5c | Company Portal | `"/Applications/Company Portal.app" …` |
| Kandji / Iru | A5d | Zoom | `"/Applications/zoom.us.app" …` |
| Kandji / Iru | A5e | Cortex | `"/Applications/Cortex XDR.app" …` |
| Kandji / Iru | A5f | Netskope | `"/Applications/Netskope Client.app" …` |

Kandji rows repeat the path as the icon, then the display name. On Kandji, `A5` in a reply means all six.

## List-item JSON templates

Replace `NN` with `index + 1`, zero-padded. Keep the shell-quote splices exactly: `'"${organizationColorScheme}"'` and `'${mdmVendor}'`. These are fragments inside a single-quoted zsh string, not standalone JSON.

```text
C1  {"title" : "macOS Version", "subtitle" : "Organizational standards are the current and immediately previous versions of macOS", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C2  {"title" : "Available Updates", "subtitle" : "Keep your Mac up-to-date to ensure its security and performance", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C3  {"title" : "System Integrity Protection", "subtitle" : "System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C4  {"title" : "Signed System Volume", "subtitle" : "Signed System Volume (SSV) ensures macOS is booted from a signed, cryptographically protected volume.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C5  {"title" : "Firewall", "subtitle" : "The built-in macOS firewall helps protect your Mac from unauthorized access.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C6  {"title" : "FileVault Encryption", "subtitle" : "FileVault is built-in to macOS and provides full-disk encryption to help prevent unauthorized access to your Mac", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C7  {"title" : "Gatekeeper / XProtect", "subtitle" : "Prevents the execution of Apple-identified malware and adware.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C8  {"title" : "Touch ID", "subtitle" : "Touch ID provides secure biometric authentication for unlock your Mac and authorize third-party apps.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C9  {"title" : "Password Hint", "subtitle" : "Ensure no password hint is set for better security", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C10 {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C11 {"title" : "AirPlay Receiver", "subtitle" : "Ensure AirPlay Receiver is disabled when not needed", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C12 {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
C13 {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
H1  {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
H2  {"title" : "Free Disk Space", "subtitle" : "Checks for the amount of free disk space on your Mac’s boot volume", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
H3  {"title" : "Desktop Size and Item Count", "subtitle" : "Checks the size and item count of the Desktop", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
H4  {"title" : "Downloads Size and Item Count", "subtitle" : "Checks the size and item count of the Downloads folder", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
H5  {"title" : "Trash Size and Item Count", "subtitle" : "Checks the size and item count of the Trash", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
H6  {"title" : "Memory Pressure", "subtitle" : "Reviews memory pressure across recent days", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
H7  {"title" : "Clock Skew", "subtitle" : "Checks local clock offset against time.apple.com", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
M1  {"title" : "'${mdmVendor}' MDM Profile", "subtitle" : "The presence of the '${mdmVendor}' MDM profile helps ensure your Mac is enrolled", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
M2  {"title" : "Entra ID Registration", "subtitle" : "Checks Microsoft Entra registration for current user context", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
M3  {"title" : "'${mdmVendor}' MDM Certificate Expiration", "subtitle" : "Validate the expiration date of the '${mdmVendor}' MDM certificate", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
M4  {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
M5  {"title" : "Jamf Pro Check-In", "subtitle" : "Your Mac should check-in with the Jamf Pro MDM server multiple times each day", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
M6  {"title" : "Jamf Pro Inventory", "subtitle" : "Your Mac should submit its inventory to the Jamf Pro MDM server daily", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
M7  {"title" : "Mosyle Check-In", "subtitle" : "Your Mac should check-in with the Mosyle MDM server multiple times each day", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.4}
M8  {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=NN.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5}
M9  {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=NN.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5}
M10 {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=NN.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5}
M11 {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=NN.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5}
M12 {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=NN.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5}
M13 {"title" : "Jamf Hosts","subtitle":"Test connectivity to Jamf Pro cloud and on-prem endpoints","icon":"SF=NN.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5}
M14 {"title" : "Wi-Fi Strength", "subtitle" : "Checks current Wi-Fi signal strength and gives a simple quality rating.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
M15 {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A1  {"title" : "App Auto-Patch", "subtitle" : "Keep your apps up-to-date to ensure their security and performance", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A2  {"title" : "Homebrew Status", "subtitle" : "If installed, compares the latest Homebrew release and any outdated packages", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A3  {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A4  {"title" : "Microsoft Teams", "subtitle" : "The hub for teamwork in Microsoft 365.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A5  {"title" : "Fleet Desktop", "subtitle" : "Visibility into the security posture of your Mac.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A5  {"title" : "Microsoft Company Portal", "subtitle" : "Securely access and manage corporate apps, resources, and devices via Intune.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A5  {"title" : "'${mdmVendor}' Self-Service", "subtitle" : "Your one-stop shop for all things '${mdmVendor}'.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A5  {"title" : "Microsoft One Drive", "subtitle" : "Microsoft cloud storage for your important files.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A5  {"title" : "Microsoft Outlook", "subtitle" : "Email and Calendar from Microsoft.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A5  {"title" : "Company Portal", "subtitle" : "Required for Platform Single Sign-On.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A5  {"title" : "Zoom", "subtitle" : "Web Conferencing Tool.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A5  {"title" : "Cortex", "subtitle" : "Cortex Security Software.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A5  {"title" : "Netskope", "subtitle" : "Netskope Connection Software.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A6  {"title" : "BeyondTrust Privilege Management", "subtitle" : "Privilege Management for Mac pairs powerful least-privilege management and application control", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A7  {"title" : "Cisco Umbrella", "subtitle" : "Cisco Umbrella combines multiple security functions so you can extend data protection anywhere.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A8  {"title" : "CrowdStrike Falcon", "subtitle" : "Technology, intelligence, and expertise come together in CrowdStrike Falcon to deliver security that works.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A9  {"title" : "Palo Alto GlobalProtect", "subtitle" : "Virtual Private Network (VPN) connection to <YOUR_ORGANIZATION_NETWORK>", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A10 {"title" : "<Display Name>", "subtitle" : "<One short, action-oriented sentence>", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
F1  {"title" : "Computer Inventory", "subtitle" : "The listing of your Mac’s apps and settings", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
```

The shipped A9 subtitle names one organization's network; the template uses a placeholder instead. The shipped Jamf Pro H7 subtitle ends "before Jamf Pro inventory submission"; the template and every non-Jamf artifact use the vendor-neutral subtitle (the same one `developmentListitemJSON` uses). The Kandji A5 rows are the Kandji app set (OneDrive, Outlook, Company Portal, Zoom, Cortex, Netskope). For Kandji, `checkUserDirectorySizeItems "Downloads"` uses the icon `arrow.down.circle.fill`.

When building an artifact, copy rows verbatim from the chosen MDM's array in the source first. Use these templates only as a fallback.

## Shipped default order per MDM

Each list is the shipped order, index `0` first. Use it as the default selection (`defaults`) for that MDM. Verified against `5.0.0` with `scripts/build-artifact.zsh --list <slug>`; rerun it each session and trust the script if they differ.

Every list ends with `M14 H6 M15` (plus `F1` for Jamf Pro). Available non-default additions go immediately before the first remaining item of that tail (see **Reply grammar** in `SKILL.md`).

- **Jamf Pro (42):** C1 C2 C3 C4 C5 C6 C7 C8 C10 C11 C12 C13 H1 H2 H3 H4 H5 M1 M2 M3 M4 M5 M6 H7 M8 M9 M10 M11 M12 M13 A1 A2 A3 A4 A6 A7 A8 A9 M14 H6 M15 F1
- **Fleet (33):** C1 C2 A1 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C9 C10 C11 C12 M1 M3 M4 M8 M9 M10 M11 M12 A5(Fleet Desktop) A2 A3 M14 H6 M15
- **JumpCloud (33):** C1 C2 A1 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C9 C10 C11 C12 M1 M3 M4 M8 M9 M10 M11 M12 A4 A2 A3 M14 H6 M15
- **Microsoft Intune (33):** C1 C2 A1 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C9 C10 C11 C12 M1 M3 M4 M8 M9 M10 M11 M12 A5(Microsoft Company Portal) A2 A3 M14 H6 M15
- **Mosyle (34):** C1 C2 A1 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C9 C10 C11 C12 M1 M3 M4 M7 M8 M9 M10 M11 M12 A5(Self-Service) A2 A3 M14 H6 M15
- **Kandji / Iru (32):** C1 C2 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C12 M3 M4 M8 M9 M10 M11 M12 A4 A5a A5b A5c A5d A5e A5f M14 H6 M15
- **Addigy (33):** same as JumpCloud
- **Filewave (32):** same as JumpCloud without A4
- **Generic / Other (29):** C1 C2 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C9 C10 C11 C12 M4 M8 M9 M10 M11 M12 A2 A3 M14 H6 M15

## Development curated subset

Shipped `developmentListitemJSON` (inside `if [[ "${operationMode}" == "Development" ]]`):

```zsh
    developmentListitemJSON='
    [
        {"title" : "Clock Skew", "subtitle" : "Checks local clock offset against time.apple.com", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Memory Pressure", "subtitle" : "Reviews memory pressure across recent days", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
    ]
    '
```

Matching calls:

```zsh
    checkClockSkew "0"
    checkMemoryPressure "1"
    checkAPNs "2"
```

Development is for fast iteration on the checks being changed, not a representative run. Artifacts leave this subset untouched; admins edit it manually.
