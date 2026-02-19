# Mac Health Check: Health Check Reference

This text-only reference documents all configurable organization defaults and all health checks available in Mac Health Check. No diagram is included — use [03-health-check-categories.md](03-health-check-categories.md) for a visual overview.

---

## Organization Defaults Reference

All variables are located in `Mac-Health-Check.zsh`, lines 90–172. Edit these before uploading the script to your MDM.

| Variable | Default Value | Description | Valid Values |
|---|---|---|---|
| `humanReadableScriptName` | `"Mac Health Check"` | Display name shown in the dialog title | Any string |
| `organizationScriptName` | `"MHC"` | Short identifier used in log entries | Any short string |
| `organizationSelfServiceMarketingName` | `"Workforce App Store"` | Your MDM Self Service portal name | Any string |
| `organizationBoilerplateComplianceMessage` | `"Meets organizational standards"` | Subtitle shown for passing checks | Any string |
| `organizationBrandingBannerURL` | Freepik sample URL | Banner image displayed at the top of the dialog | HTTPS URL or local path |
| `organizationOverlayiconURL` | `"/System/Library/CoreServices/Apple Diagnostics.app"` | Icon overlaid on the dialog banner | App path, HTTPS URL, or `none` |
| `enableDockIntegration` | `"true"` | Show a Dock icon with countdown badge in non-Silent modes | `true` \| `false` |
| `dockIcon` | Jamf Cloud icon URL | URL or path for the Dock badge icon | HTTPS URL or local path |
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
| `completionTimer` | `"60"` | Seconds before the final dialog auto-closes | Integer string |

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
| User | `checkAirDropSettings()` | AirDrop | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| User | `checkAirPlayReceiver()` | AirPlay Receiver | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| User | `checkBluetoothSharing()` | Bluetooth Sharing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| User | `checkPasswordHint()` | Password Hint | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ | ✅ | ✅ |
| User | `checkVPN()` | VPN Client | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| User | `checkUptime()` | Last Reboot | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Disk | `checkFreeDiskSpace()` | Free Disk Space | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Disk | `checkUserDirectorySizeItems()` | Desktop Size | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Disk | `checkUserDirectorySizeItems()` | Downloads Size | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Disk | `checkUserDirectorySizeItems()` | Trash Size | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| MDM | `checkMdmProfile()` | MDM Profile | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| MDM | `checkAPNs()` | Apple Push Notification service | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| MDM | `checkMdmCertificateExpiration()` | MDM Certificate Expiration | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| MDM | `checkJamfProCheckIn()` | Last Jamf Pro Check-in | — | — | — | ✅ | — | — | — | — | — |
| MDM | `checkJamfProInventory()` | Last Jamf Pro Inventory | — | — | — | ✅ | — | — | — | — | — |
| MDM | `checkMosyleCheckIn()` | Last Mosyle Check-in | — | — | — | — | — | — | — | ✅ | — |
| Network | `checkNetworkHosts()` | Apple Push Notification Hosts | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network | `checkNetworkHosts()` | Apple Device Management | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network | `checkNetworkHosts()` | Apple Software & Carrier Updates | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network | `checkNetworkHosts()` | Apple Certificate Validation | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network | `checkNetworkHosts()` | Apple Identity & Content Services | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network | `checkNetworkHosts()` | Jamf Hosts | — | — | — | ✅ | — | — | — | — | — |
| Network | `checkNetworkQuality()` | Network Quality Test | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Apps | `checkAppAutoPatch()` | App Auto-Patch | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Apps | `checkElectronCornerMask()` | Electron Corner Mask | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Apps | `checkInternal()` | Microsoft Teams | ✅ | — | ✅ | ✅ | ✅ | ✅ | — | — | — |
| Apps | `checkInternal()` | Microsoft Company Portal | — | — | — | — | — | — | ✅ | — | — |
| Apps | `checkInternal()` | Fleet Desktop | — | — | ✅ | — | — | — | — | — | — |
| Apps | `checkInternal()` | Self-Service | — | — | — | — | — | — | — | ✅ | — |
| External | `checkExternalJamfPro()` | BeyondTrust PAM | — | — | — | ✅ | — | — | — | — | — |
| External | `checkExternalJamfPro()` | Cisco Umbrella | — | — | — | ✅ | — | — | — | — | — |
| External | `checkExternalJamfPro()` | CrowdStrike Falcon | — | — | — | ✅ | — | — | — | — | — |
| External | `checkExternalJamfPro()` | Palo Alto GlobalProtect | — | — | — | ✅ | — | — | — | — | — |
| Inventory | `updateComputerInventory()` | Computer Inventory | — | — | — | ✅ | — | — | — | — | — |

---

## Check Set Sizes by MDM Vendor

| MDM Vendor | Total Checks |
|---|---|
| Jamf Pro | 37 |
| Mosyle | 31 |
| Addigy | 30 |
| Filewave | 29 |
| Fleet | 30 |
| JumpCloud | 30 |
| Kandji | 30 |
| Microsoft Intune | 30 |
| Generic / None | 26 |

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
| 5 | `webhookURL` | (blank) | Microsoft Teams or Slack webhook URL for failure notifications; leave blank to disable |
