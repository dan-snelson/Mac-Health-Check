# Mac Health Check: Health Check Categories

This diagram shows all Mac Health Check health checks organized by category. Each check is listed with its function name and the human-readable label shown in the swiftDialog interface.

```mermaid
graph LR
    MHC["Mac Health Check<br>Health Checks"]

    subgraph System["🖥️ System"]
        S1["checkOS()<br>macOS Version"]
        S2["checkAvailableSoftwareUpdates()<br>Available Updates"]
        S3["checkSIP()<br>System Integrity Protection"]
        S4["checkSSV()<br>Signed System Volume"]
        S5["checkGatekeeperXProtect()<br>Gatekeeper / XProtect"]
        S6["checkFirewall()<br>Firewall"]
        S7["checkFileVault()<br>FileVault"]

        style S1 fill:#e1f5ff
        style S2 fill:#e1f5ff
        style S3 fill:#e1f5ff
        style S4 fill:#e1f5ff
        style S5 fill:#e1f5ff
        style S6 fill:#e1f5ff
        style S7 fill:#e1f5ff
    end

    subgraph User["👤 User"]
        U1["checkTouchID()<br>Touch ID"]
        U2["checkAirDropSettings()<br>AirDrop"]
        U3["checkAirPlayReceiver()<br>AirPlay Receiver"]
        U4["checkBluetoothSharing()<br>Bluetooth Sharing"]
        U5["checkPasswordHint()<br>Password Hint"]
        U6["checkVPN()<br>VPN Client"]
        U7["checkUptime()<br>Last Reboot"]

        style U1 fill:#f3e5f5
        style U2 fill:#f3e5f5
        style U3 fill:#f3e5f5
        style U4 fill:#f3e5f5
        style U5 fill:#f3e5f5
        style U6 fill:#f3e5f5
        style U7 fill:#f3e5f5
    end

    subgraph Disk["💾 Disk"]
        D1["checkFreeDiskSpace()<br>Free Disk Space"]
        D2["checkUserDirectorySizeItems()<br>Desktop Size"]
        D3["checkUserDirectorySizeItems()<br>Downloads Size"]
        D4["checkUserDirectorySizeItems()<br>Trash Size"]

        style D1 fill:#fff4e6
        style D2 fill:#fff4e6
        style D3 fill:#fff4e6
        style D4 fill:#fff4e6
    end

    subgraph MDMChecks["📱 MDM"]
        M1["checkMdmProfile()<br>MDM Profile"]
        M2["checkAPNs()<br>Apple Push Notification service"]
        M3["checkMdmCertificateExpiration()<br>MDM Certificate Expiration"]
        M4["checkJamfProCheckIn()<br>Last Jamf Pro Check-in"]
        M5["checkJamfProInventory()<br>Last Jamf Pro Inventory"]
        M6["checkMosyleCheckIn()<br>Last Mosyle Check-in"]

        style M1 fill:#b2dfdb
        style M2 fill:#b2dfdb
        style M3 fill:#b2dfdb
        style M4 fill:#b2dfdb
        style M5 fill:#b2dfdb
        style M6 fill:#b2dfdb
    end

    subgraph Network["🌐 Network"]
        N1["checkNetworkHosts()<br>Apple Push Notification Hosts"]
        N2["checkNetworkHosts()<br>Apple Device Management"]
        N3["checkNetworkHosts()<br>Apple Software & Carrier Updates"]
        N4["checkNetworkHosts()<br>Apple Certificate Validation"]
        N5["checkNetworkHosts()<br>Apple Identity & Content Services"]
        N6["checkNetworkHosts()<br>Jamf Hosts"]
        N7["checkNetworkQuality()<br>Network Quality Test"]

        style N1 fill:#c8e6c9
        style N2 fill:#c8e6c9
        style N3 fill:#c8e6c9
        style N4 fill:#c8e6c9
        style N5 fill:#c8e6c9
        style N6 fill:#c8e6c9
        style N7 fill:#c8e6c9
    end

    subgraph Apps["📦 Apps"]
        A1["checkAppAutoPatch()<br>App Auto-Patch"]
        A2["checkElectronCornerMask()<br>Electron Corner Mask"]
        A3["checkInternal()<br>Required App Presence<br>(MDM vendor–specific)"]

        style A1 fill:#ffecb3
        style A2 fill:#ffecb3
        style A3 fill:#ffecb3
    end

    subgraph External["🔌 External"]
        E1["checkExternalJamfPro()<br>BeyondTrust PAM"]
        E2["checkExternalJamfPro()<br>Cisco Umbrella"]
        E3["checkExternalJamfPro()<br>CrowdStrike Falcon"]
        E4["checkExternalJamfPro()<br>Palo Alto GlobalProtect"]

        style E1 fill:#ffcdd2
        style E2 fill:#ffcdd2
        style E3 fill:#ffcdd2
        style E4 fill:#ffcdd2
    end

    MHC --> System
    MHC --> User
    MHC --> Disk
    MHC --> MDMChecks
    MHC --> Network
    MHC --> Apps
    MHC --> External

    style MHC fill:#e1f5ff

    classDef default font-size:11px
```

---

## Category Descriptions

### System
Core macOS security and compliance checks that every deployment should include. These checks verify OS version compliance, pending software updates, kernel-level security features (SIP, SSV), application security controls (Gatekeeper, XProtect), network firewall status, and disk encryption.

| Function | Human-Readable Name | Notes |
|---|---|---|
| `checkOS()` | macOS Version | Compliant if within `previousMinorOS` versions of latest release |
| `checkAvailableSoftwareUpdates()` | Available Updates | Reports count of pending macOS/app updates |
| `checkSIP()` | System Integrity Protection | Checks `csrutil status` |
| `checkSSV()` | Signed System Volume | Checks `csrutil authenticated-root status` |
| `checkGatekeeperXProtect()` | Gatekeeper / XProtect | Validates Gatekeeper status and XProtect version/date |
| `checkFirewall()` | Firewall | Supports `socketfilterfw` (default) or `pf` via `organizationFirewall` |
| `checkFileVault()` | FileVault | Checks FileVault encryption status |

### User
Per-user settings and behavior checks. Some checks (e.g., `checkPasswordHint()`) are MDM vendor–specific and may not appear in all deployments.

| Function | Human-Readable Name | Notes |
|---|---|---|
| `checkTouchID()` | Touch ID | Reports enrolled fingerprints |
| `checkAirDropSettings()` | AirDrop | Warns on "Everyone" setting |
| `checkAirPlayReceiver()` | AirPlay Receiver | Warns if enabled without restriction |
| `checkBluetoothSharing()` | Bluetooth Sharing | Warns if Bluetooth Sharing is enabled |
| `checkPasswordHint()` | Password Hint | Warns if a password hint is set |
| `checkVPN()` | VPN Client | Controlled by `vpnClientVendor`; skipped if `none` |
| `checkUptime()` | Last Reboot | Warns/errors if uptime exceeds `allowedUptimeMinutes` (default: 10,080 min / 7 days) |

### Disk
Storage checks. Thresholds are configurable via organization defaults.

| Function | Human-Readable Name | Notes |
|---|---|---|
| `checkFreeDiskSpace()` | Free Disk Space | Errors if below `allowedMinimumFreeDiskPercentage` (default: 10%) |
| `checkUserDirectorySizeItems()` | Desktop / Downloads / Trash Size | Warns if any user directory exceeds `allowedMaximumDirectoryPercentage` (default: 5%) |

### MDM
MDM connectivity and certificate health checks. Vendor-specific checks (Jamf Pro check-in/inventory, Mosyle check-in) appear only in the matching vendor's check set.

| Function | Human-Readable Name | Notes |
|---|---|---|
| `checkMdmProfile()` | MDM Profile | Verifies MDM enrollment profile is present |
| `checkAPNs()` | Apple Push Notification service | Validates APNs connectivity |
| `checkMdmCertificateExpiration()` | MDM Certificate Expiration | Warns 30 days before expiration |
| `checkJamfProCheckIn()` | Last Jamf Pro Check-in | Jamf Pro only |
| `checkJamfProInventory()` | Last Jamf Pro Inventory | Jamf Pro only |
| `checkMosyleCheckIn()` | Last Mosyle Check-in | Mosyle only |

### Network
Validates reachability to Apple infrastructure and (for Jamf Pro) Jamf Cloud hosts. `checkNetworkQuality()` runs an `networkQuality` speed test, caching results for up to `networkQualityTestMaximumAge` (default: 1 hour) to avoid repeated tests.

### Apps
Application-specific checks. `checkInternal()` validates the presence of an MDM vendor–specific companion app (e.g., Company Portal for Intune, Self-Service.app for Mosyle). `checkAppAutoPatch()` validates the App Auto-Patch patching agent.

### External
Optional plugin checks for third-party security tools. These require separate MDM policies from the `external-checks/` directory and use a shared defaults domain (`organizationDefaultsDomain`) to pass results to the main script. Available only in Jamf Pro deployments.

| Trigger | Tool | Required App |
|---|---|---|
| `symvBeyondTrustPMfM` | BeyondTrust Privileged Access Management | `PrivilegeManagement.app` |
| `symvCiscoUmbrella` | Cisco Umbrella | `Cisco Secure Client.app` |
| `symvCrowdStrikeFalcon` | CrowdStrike Falcon | `Falcon.app` |
| `symvGlobalProtect` | Palo Alto GlobalProtect | `GlobalProtect.app` |
