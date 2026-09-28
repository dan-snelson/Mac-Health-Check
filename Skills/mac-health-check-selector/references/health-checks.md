# Mac Health Check — Health Check Reference

Companion reference for the `mac-health-check-selector` skill. Derived from `Mac-Health-Check.zsh` `5.0.0b1`. When this file and the script disagree, the script wins.

## How the pieces fit

Each MDM has two coupled structures in `Mac-Health-Check.zsh`:

1. A list-item array, such as `jamfProListitemJSON='[ … ]'`, which defines the rows swiftDialog shows.
2. A matching branch in the `case ${mdmVendor} in` block under **Generate Health Checks based on Operation Mode and MDM Vendor**, made of `runConfiguredHealthCheck "<index>" <function> [args …]` lines.

Rules that keep them aligned:

- Index `n` in `runConfiguredHealthCheck "n"` is the zero-based position of the matching row in the list-item array.
- The row icon is `SF=NN.circle`, where `NN` is `n + 1`, zero-padded to two digits (`01`, `02`, … `42`).
- The last array element has no trailing comma.
- The row `title` becomes the stable report key through `sanitizeCheckKey` (lowercase, non-alphanumerics → `_`). `Memory Pressure` is special-cased to `memoryPressure`. Renaming a title renames its key.
- `Development` mode ignores the MDM arrays. It uses `developmentListitemJSON` and calls check functions directly (for example `checkClockSkew "0"`), without `runConfiguredHealthCheck`.
- `Test` mode uses the MDM array but runs no real checks; it walks every row and marks it compliant.

## Script-to-selector MDM map

| Selector choice | `mdmVendor` value | List-item array | `serverURL` match | Profile lookup |
|---|---|---|---|---|
| Jamf Pro | `Jamf Pro` | `jamfProListitemJSON` | `*jamf*` or `*jss*` | `mdmVendorUuid` |
| Fleet | `Fleet` | `fleetMdmListitemJSON` | `*fleet*` | `mdmVendorUuid` |
| JumpCloud | `JumpCloud` | `jumpcloudMdmListitemJSON` | `*jumpcloud*` | `mdmProfileIdentifier` |
| Microsoft Intune | `Microsoft Intune` | `microsoftMdmListitemJSON` | `*microsoft*` | `mdmVendorUuid` |
| Mosyle | `Mosyle` | `mosyleListitemJSON` | `*mosyle*` | `mdmProfileIdentifier` |
| Kandji / Iru | `Kandji` | `kandjiMdmListitemJSON` | `*kandji*` | `mdmProfileIdentifier` |
| Addigy | `Addigy` | `addigyMdmListitemJSON` | `*addigy*` | `mdmVendorUuid` (blank by default) |
| Filewave | `Filewave` | `filewaveMdmListitemJSON` | `*filewave*` | `mdmProfileIdentifier` |
| Other / MDM-agnostic | `None` (falls to `*`) | `genericMdmListitemJSON` | no match | none |

Notes:

- An Iru-branded server URL that does not contain `kandji` falls through to the generic branch; add a pattern to the `case "${serverURL}" in` block if needed.
- Addigy ships with `mdmVendorUuid=""`; the MDM Profile check needs a UUID or identifier to pass.
- The generic branch omits MDM Profile and MDM Certificate Expiration because no vendor profile or certificate name is known.

## Master check table

Legend — **Avail**: `All` = safe on any MDM; `Jamf` = Jamf Pro only; `Vendor` = needs a known `mdmVendor`; `Ext` = needs an external-check script plus a Jamf Pro policy trigger.

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
| C8 | Touch ID | `checkTouchID` | All | |
| C9 | Password Hint | `checkPasswordHint` | All | Not in Jamf Pro or Kandji defaults |
| C10 | AirDrop | `checkAirDropSettings` | All | Not in Kandji or generic defaults |
| C11 | AirPlay Receiver | `checkAirPlayReceiver` | All | macOS 27 missing-key aware |
| C12 | Bluetooth Sharing | `checkBluetoothSharing` | All | macOS 27 missing-domain aware |
| C13 | VPN Client | `checkVPN` | All | Honors organization VPN settings |

### Maintenance & Hygiene (H)

| ID | Title | Call | Avail | Notes |
|---|---|---|---|---|
| H1 | Last Reboot | `checkUptime` | All | |
| H2 | Free Disk Space | `checkFreeDiskSpace` | All | |
| H3 | Desktop Size and Item Count | `checkUserDirectorySizeItems "Desktop" "desktopcomputer.and.macbook" "Desktop"` | All | User-scoped |
| H4 | Downloads Size and Item Count | `checkUserDirectorySizeItems "Downloads" "folder.fill.badge.plus" "Downloads"` | All | Kandji default uses icon `arrow.down.circle.fill` |
| H5 | Trash Size and Item Count | `checkUserDirectorySizeItems ".Trash" "trash.fill" "Trash"` | All | User-scoped |
| H6 | Memory Pressure | `checkMemoryPressure` | All | Warning-only; root-only 14-day JSON Lines history; warns when yellow/red pressure appears on 2 distinct days within 7 days |
| H7 | Clock Skew | `checkClockSkew` | All (Jamf default) | Flags skew over 5 minutes against `time.apple.com`; hides dialog updates in `Silent` and `Test` |

### MDM & Connectivity (M)

| ID | Title | Call | Avail | Notes |
|---|---|---|---|---|
| M1 | `'${mdmVendor}' MDM Profile` | `checkMdmProfile` | Vendor | Needs `mdmVendorUuid` or `mdmProfileIdentifier` |
| M2 | Entra ID Registration | `checkEntraIDRegistration` | Jamf default | Reads Jamf AAD plist, Platform SSO, and legacy certificate; review before using elsewhere |
| M3 | `'${mdmVendor}' MDM Certificate Expiration` | `checkMdmCertificateExpiration` | Vendor | Certificate name mapped per vendor |
| M4 | Apple Push Notification service | `checkAPNs` | All | |
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
| A1 | App Auto-Patch | `checkAppAutoPatch` | All | Expects App Auto-Patch installed |
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

`checkExternalJamfPro` arguments: `<Jamf Pro policy custom trigger>` `<app path for icon>`. It runs `jamf policy -event <trigger>` and reads `Running`, `Warning`, `Failed`, or `Error` from output. It is Jamf Pro-only. On other MDMs, use `checkInternal` for presence or write a new `checkXxx` function.

Scripts shipped in `external-checks/`: BeyondTrust Privileged Access Management, Check Printer Install, Cisco Umbrella, CrowdStrike Falcon Status, Microsoft Defender Check, Microsoft Office 365, Nessus Agent Status, Palo Alto Networks GlobalProtect Status, Sophos Endpoint RTS, Splunk Universal Forwarder Check, TenableNessusAgent-Alternate, Zscaler Tunnel Status.

### Follow-up Actions (F)

| ID | Title | Call | Avail | Notes |
|---|---|---|---|---|
| F1 | Computer Inventory | `updateComputerInventory` | Jamf | Runs `jamf recon` with 90-second timeout; must be last; skipped in `Silent` + `splunkOperationMode=production`; removed from Client-Side Cache copy |

### MDM agent apps (A5 and friends)

| MDM | Title | `checkInternal` args |
|---|---|---|
| Fleet | Fleet Desktop | `"/opt/orbit/bin/desktop/macos/stable/Fleet Desktop.app" "/opt/orbit/bin/desktop/macos/stable/Fleet Desktop.app" "Fleet Desktop"` |
| Microsoft Intune | Microsoft Company Portal | `"/Applications/Company Portal.app" "/Applications/Company Portal.app" "Microsoft Company Portal"` |
| Mosyle | `'${mdmVendor}' Self-Service` | `"/Applications/Self-Service.app" "/Applications/Self-Service.app" "Self-Service"` |
| Kandji / Iru | Microsoft One Drive, Microsoft Outlook, Company Portal, Zoom, Cortex, Netskope | `"/Applications/OneDrive.app" …`, `"/Applications/Microsoft Outlook.app" …`, `"/Applications/Company Portal.app" …`, `"/Applications/zoom.us.app" …`, `"/Applications/Cortex XDR.app" …`, `"/Applications/Netskope Client.app" …` (path repeated as icon, then display name) |

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
H7  {"title" : "Clock Skew", "subtitle" : "Checks local clock offset against time.apple.com before Jamf Pro inventory submission", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
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
A6  {"title" : "BeyondTrust Privilege Management", "subtitle" : "Privilege Management for Mac pairs powerful least-privilege management and application control", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A7  {"title" : "Cisco Umbrella", "subtitle" : "Cisco Umbrella combines multiple security functions so you can extend data protection anywhere.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A8  {"title" : "CrowdStrike Falcon", "subtitle" : "Technology, intelligence, and expertise come together in CrowdStrike Falcon to deliver security that works.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A9  {"title" : "Palo Alto GlobalProtect", "subtitle" : "Virtual Private Network (VPN) connection to <YOUR_ORGANIZATION_NETWORK>", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
A10 {"title" : "<Display Name>", "subtitle" : "<One short, action-oriented sentence>", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
F1  {"title" : "Computer Inventory", "subtitle" : "The listing of your Mac’s apps and settings", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
```

The shipped A9 subtitle names one organization's network; the template uses a placeholder instead.

## Shipped default order per MDM

Each list is the shipped order, index `0` first. Use it as the **Full Self Service** preset for that MDM.

- **Jamf Pro (42):** C1 C2 C3 C4 C5 C6 C7 C8 C10 C11 C12 C13 H1 H2 H3 H4 H5 M1 M2 M3 M4 M5 M6 H7 M8 M9 M10 M11 M12 M13 A1 A2 A3 A4 A6 A7 A8 A9 M14 H6 M15 F1
- **Fleet (33):** C1 C2 A1 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C9 C10 C11 C12 M1 M3 M4 M8 M9 M10 M11 M12 A5(Fleet Desktop) A2 A3 M14 H6 M15
- **JumpCloud (33):** C1 C2 A1 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C9 C10 C11 C12 M1 M3 M4 M8 M9 M10 M11 M12 A4 A2 A3 M14 H6 M15
- **Microsoft Intune (33):** C1 C2 A1 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C9 C10 C11 C12 M1 M3 M4 M8 M9 M10 M11 M12 A5(Microsoft Company Portal) A2 A3 M14 H6 M15
- **Mosyle (34):** C1 C2 A1 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C9 C10 C11 C12 M1 M3 M4 M7 M8 M9 M10 M11 M12 A5(Self-Service) A2 A3 M14 H6 M15
- **Kandji / Iru (32):** C1 C2 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C12 M3 M4 M8 M9 M10 M11 M12 A4 then Kandji app set (OneDrive, Outlook, Company Portal, Zoom, Cortex, Netskope) M14 H6 M15
- **Addigy (33):** same as JumpCloud
- **Filewave (32):** same as JumpCloud without A4
- **Generic / Other (29):** C1 C2 C3 C4 C5 C6 C7 C8 C13 H1 H2 H3 H4 H5 C9 C10 C11 C12 M4 M8 M9 M10 M11 M12 A2 A3 M14 H6 M15

## Development curated subset

Shipped `developmentListitemJSON` (inside `if [[ "${operationMode}" == "Development" ]]`):

```zsh
    developmentListitemJSON='
    [
        {"title" : "Clock Skew", "subtitle" : "Checks local clock offset against time.apple.com", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Memory Pressure", "subtitle" : "Reviews memory pressure across recent days", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
    ]
    '
```

Matching calls:

```zsh
    checkClockSkew "0"
    checkMemoryPressure "1"
```

Development is for fast iteration on the checks being changed, not a representative run.
