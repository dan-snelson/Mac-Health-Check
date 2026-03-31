# Mac Health Check: System Architecture

This diagram shows the `3.2.0` Mac Health Check ecosystem, from administrator customization through MDM deployment, client-side execution, user interaction, and results output.

```mermaid
graph TB
    subgraph Admin["⚙️ Administrator Configuration"]
        SCRIPT["Mac-Health-Check.zsh<br>Core script (4,900+ lines)"]
        ORGVARS["Organization + Support Defaults<br>Branding, Dock, thresholds,<br>VPN / firewall, support links"]
        EXTCHECKS["external-checks/<br>Optional third-party plugins<br>(BeyondTrust, CrowdStrike, etc.)"]
        RESOURCES["Resources/<br>Build utilities & Makefile"]

        SCRIPT --> ORGVARS
        SCRIPT -.->|optional| EXTCHECKS

        style SCRIPT fill:#e1f5ff
        style ORGVARS fill:#f3e5f5
        style EXTCHECKS fill:#e1f5ff
        style RESOURCES fill:#e1f5ff
    end

    subgraph MDM["📦 MDM Deployment"]
        MDMSERVER["MDM Server<br>Jamf Pro / Kandji / Intune<br>Mosyle / JumpCloud / Addigy<br>Filewave / Fleet"]
        POLICY["On-Demand Policy<br>Self Service trigger"]
        SILENT["Scheduled Policy<br>Silent / recurring (optional)"]
        PARAM4["Parameter 4:<br>operationMode"]
        PARAM5["Parameter 5:<br>webhookURL"]

        SCRIPT -->|Upload script| MDMSERVER
        EXTCHECKS -->|Upload as separate policies| MDMSERVER
        MDMSERVER --> POLICY
        MDMSERVER -.->|optional| SILENT
        MDMSERVER --> PARAM4
        MDMSERVER -.->|optional| PARAM5

        style MDMSERVER fill:#ffecb3
        style POLICY fill:#c8e6c9
        style SILENT fill:#c8e6c9
        style PARAM4 fill:#f3e5f5
        style PARAM5 fill:#f3e5f5
    end

    subgraph Client["💻 Client Mac"]
        TRIGGER["Policy Trigger<br>User via Self Service<br>or scheduled run"]
        PREFLIGHT["Pre-flight Checks<br>• Running as root?<br>• swiftDialog ≥ 3.0.1.4955 installed?<br>• jq installed?<br>• Kill existing Dialog instances"]
        MDMDETECT["MDM Vendor Detection<br>Auto-detect from installed profiles:<br>Jamf Pro / Kandji / Intune / Mosyle<br>JumpCloud / Addigy / Filewave / Fleet"]
        CHECKLIST["Check Set Selection<br>Vendor-specific list<br>(26–37 checks)"]

        POLICY -->|Executes script| TRIGGER
        SILENT -.->|Executes script| TRIGGER
        TRIGGER --> PREFLIGHT
        PREFLIGHT --> MDMDETECT
        MDMDETECT -->|Matched vendor| CHECKLIST

        style TRIGGER fill:#fff4e6
        style PREFLIGHT fill:#ffcdd2
        style MDMDETECT fill:#b2dfdb
        style CHECKLIST fill:#b2dfdb
    end

    subgraph Runtime["▶️ Runtime Execution"]
        DIALOG["swiftDialog<br>Interactive health check dialog<br>with live status updates<br>and optional Dock integration"]
        CHECKLOOP["Health Check Loop<br>System · User · Disk · MDM<br>Network · Apps · External"]
        STATUSES["Check Statuses<br>✅ pass · ⚠️ warning<br>❌ error · ⏭️ skipped"]
        FINAL["Final Summary Dialog<br>Healthy / Unhealthy state<br>with countdown timer"]

        CHECKLIST -->|Initialize dialog| DIALOG
        DIALOG <-->|dialogUpdate per check| CHECKLOOP
        CHECKLOOP --> STATUSES
        STATUSES --> FINAL

        style DIALOG fill:#e1f5ff
        style CHECKLOOP fill:#b2dfdb
        style STATUSES fill:#fff4e6
        style FINAL fill:#cfd8dc
    end

    subgraph Output["📤 Output"]
        LOG["Client Log<br>/var/log/org.churchofjesuschrist.log<br>Structured entries with prefixes:<br>PRE-FLIGHT · NOTICE · INFO<br>WARNING · ERROR · FATAL ERROR"]
        FAILNOTE["Failure Notification<br>Persistent swiftDialog pseudo-alert<br>(non-Silent, failures only)"]
        WEBHOOK["Webhook Notification<br>Microsoft Teams or Slack<br>(optional — param 5)"]
        INVENTORY["MDM Inventory Update<br>Via updateComputerInventory()<br>(Jamf Pro only)"]

        FINAL --> LOG
        FINAL -.->|if failures & non-Silent| FAILNOTE
        FINAL -.->|if webhookURL set & failures| WEBHOOK
        CHECKLOOP -.->|Jamf Pro only| INVENTORY

        style LOG fill:#c8e6c9
        style FAILNOTE fill:#c8e6c9
        style WEBHOOK fill:#c8e6c9
        style INVENTORY fill:#c8e6c9
    end

    classDef default font-size:11px
```

---

## Component Descriptions

### Administrator Configuration

**`Mac-Health-Check.zsh`**
The single deployable artifact (4,900+ lines). Contains the health check logic, swiftDialog UI layer, Dock handling, logging helpers, webhook delivery, and vendor-specific branching. Administrators typically customize the **Organization Variables** and **IT Support Variables** sections before uploading it to MDM.

**Organization + Support Defaults**
Key settings administrators configure before deployment:
- `organizationBrandingBannerURL` / `organizationOverlayiconURL` — Branding
- `enableDockIntegration` / `dockIcon` — Dock launch behavior and badge icon
- `vpnClientVendor` — VPN type (`paloalto`, `cisco`, `tailscale`, `none`)
- `organizationFirewall` — Firewall type (`socketfilterfw` or `pf`)
- `allowedMinimumFreeDiskPercentage` — Free disk threshold
- `allowedUptimeMinutes` — Uptime warning threshold
- `supportLabel1`–`supportLabel6` / `supportValue1`–`supportValue6` — Dynamic support lines and Info button target
- `completionTimer` — Dialog auto-close delay

**`external-checks/`**
Optional plugin scripts for third-party tools (BeyondTrust, Cisco Umbrella, CrowdStrike Falcon, GlobalProtect). Each plugin is uploaded to MDM as a separate policy and writes results to a shared defaults domain (`organizationDefaultsDomain`) for the main script to read.

---

### MDM Deployment

Mac Health Check is MDM-agnostic and has been tested with eight MDM platforms. The script is uploaded as a policy script and executed with two optional parameters:

- **Parameter 4 (`operationMode`)** — Intended production default is `Self Service`; other supported modes are `Silent`, `Debug`, `Development`, and `Test`
- **Parameter 5 (`webhookURL`)** — Optional Microsoft Teams or Slack webhook URL used when unhealthy runs need to post a failure summary

---

### Client Mac

**Pre-flight Checks**
The script validates its environment before running any health checks:
1. Confirms execution as root
2. Verifies `jq` is installed
3. Checks for swiftDialog ≥ 3.0.1.4955 (installs from GitHub if missing)
4. Kills any existing swiftDialog instances

**MDM Vendor Detection**
The script inspects installed configuration profiles to identify the MDM vendor, then selects the appropriate health check set (26–37 checks depending on vendor capabilities).

---

### Runtime Execution

Health checks execute sequentially, with each result posted to the swiftDialog dialog via a named pipe (`dialogUpdate`). When Dock integration is enabled, non-`Silent` runs also show a Dock icon with a decreasing badge count. Checks report one of four statuses: **pass**, **warning**, **error**, or **skipped**. After all checks complete, a final summary dialog appears with a countdown timer, and non-`Silent` runs with failures also trigger a persistent swiftDialog pseudo-alert notification.

---

### Output

**Client Log** — Every run writes structured log entries to `/var/log/org.churchofjesuschrist.log` using prefixed log levels (`[PRE-FLIGHT]`, `[NOTICE]`, `[INFO]`, `[WARNING]`, `[ERROR]`, `[FATAL ERROR]`). Logs include computer name, serial number, user, OS version, and all check results.

**Failure Notification** — When a non-`Silent` run detects failures, `displayFailureNotification()` presents a persistent swiftDialog pseudo-alert listing the failed health checks and offering a support link.

**Webhook** — When configured, a summary of failed checks is posted to Microsoft Teams or Slack at the end of each unhealthy run. Jamf Pro deployments include a direct link to the computer record.

**MDM Inventory** — Jamf Pro deployments include `updateComputerInventory()` as the final Jamf-specific check.
