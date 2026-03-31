# Mac Health Check: Script Execution Flow

This flowchart documents the `3.2.0` decision logic executed each time Mac Health Check runs, from the initial invocation through pre-flight validation, health check execution, and final output.

```mermaid
graph TB
    START(["▶ Script Invoked<br>via MDM policy or local test"])

    subgraph Params["📋 Parameter Parsing"]
        P4["Parameter 4:<br>operationMode<br>intended default: 'Self Service'"]
        P5["Parameter 5:<br>webhookURL<br>default: empty"]
        START --> P4
        START --> P5

        style P4 fill:#f3e5f5
        style P5 fill:#f3e5f5
    end

    subgraph Mode["🔀 Operation Mode Check"]
        ISDEBUG{"operationMode<br>== 'Debug' ?"}
        SETX["Enable set -x<br>(verbose shell tracing)"]

        P4 --> ISDEBUG
        ISDEBUG -->|Yes| SETX
        ISDEBUG -->|No| PREFLIGHT_START

        style ISDEBUG fill:#ffecb3
        style SETX fill:#ffcdd2
    end

    subgraph PreFlight["✈️ Pre-flight Checks"]
        PREFLIGHT_START["Initialize client log<br>/var/log/org.churchofjesuschrist.log"]
        ROOTCHECK{"Running as root?"}
        JQCHECK{"jq installed?"}
        SDCHECK{"swiftDialog<br>≥ 3.0.1.4955?"}
        SDINSTALL["Download & install<br>swiftDialog from GitHub"]
        KILLSD["Kill existing<br>Dialog instances"]
        DOCKBADGE["Prepare Dock launch state<br>and initial badge<br>(non-Silent when enabled)"]

        SETX --> PREFLIGHT_START
        PREFLIGHT_START --> ROOTCHECK
        ROOTCHECK -->|No| FATAL1(["💀 Fatal Error:<br>Not running as root"])
        ROOTCHECK -->|Yes| JQCHECK
        JQCHECK -->|No| FATAL2(["💀 Fatal Error:<br>jq not found"])
        JQCHECK -->|Yes| SDCHECK
        SDCHECK -->|No| SDINSTALL
        SDINSTALL --> KILLSD
        SDCHECK -->|Yes| KILLSD
        KILLSD --> DOCKBADGE

        style PREFLIGHT_START fill:#b2dfdb
        style ROOTCHECK fill:#ffecb3
        style JQCHECK fill:#ffecb3
        style SDCHECK fill:#ffecb3
        style SDINSTALL fill:#fff4e6
        style KILLSD fill:#fff4e6
        style DOCKBADGE fill:#e1f5ff
        style FATAL1 fill:#ffcdd2
        style FATAL2 fill:#ffcdd2
    end

    subgraph MDMDetect["🔍 MDM Vendor Detection"]
        DETECTMDM["Inspect installed profiles<br>Match against known MDM vendors"]
        MDMVENDOR{"MDM Vendor<br>Identified?"}
        JAMF["Jamf Pro<br>37 checks"]
        KANDJI["Kandji<br>30 checks"]
        INTUNE["Microsoft Intune<br>30 checks"]
        MOSYLE["Mosyle<br>31 checks"]
        JUMPCLOUD["JumpCloud<br>30 checks"]
        OTHERS["Addigy / Filewave<br>Fleet / Generic<br>28–30 checks"]

        DOCKBADGE --> DETECTMDM
        DETECTMDM --> MDMVENDOR
        MDMVENDOR -->|Jamf Pro| JAMF
        MDMVENDOR -->|Kandji| KANDJI
        MDMVENDOR -->|Intune| INTUNE
        MDMVENDOR -->|Mosyle| MOSYLE
        MDMVENDOR -->|JumpCloud| JUMPCLOUD
        MDMVENDOR -->|Other / None| OTHERS

        style DETECTMDM fill:#b2dfdb
        style MDMVENDOR fill:#ffecb3
        style JAMF fill:#c8e6c9
        style KANDJI fill:#c8e6c9
        style INTUNE fill:#c8e6c9
        style MOSYLE fill:#c8e6c9
        style JUMPCLOUD fill:#c8e6c9
        style OTHERS fill:#c8e6c9
    end

    subgraph ModeCheck2["🎛️ Operation Mode Branch"]
        MODESWITCH{"operationMode?"}
        ISSILENT["Silent Mode<br>Skip main dialog — log only"]
        ISDEV["Development Mode<br>Run curated dev subset<br>(Updates, AirDrop, Jamf Hosts,<br>Disk and user folders)"]
        ISTEST["Test Mode<br>Simulate current vendor list items<br>without running real checks"]
        NORMAL["Self Service / Debug<br>Full interactive run"]

        JAMF --> MODESWITCH
        KANDJI --> MODESWITCH
        INTUNE --> MODESWITCH
        MOSYLE --> MODESWITCH
        JUMPCLOUD --> MODESWITCH
        OTHERS --> MODESWITCH

        MODESWITCH -->|"Silent"| ISSILENT
        MODESWITCH -->|"Development"| ISDEV
        MODESWITCH -->|"Test"| ISTEST
        MODESWITCH -->|"Self Service" / "Debug"| NORMAL

        style MODESWITCH fill:#ffecb3
        style ISSILENT fill:#cfd8dc
        style ISDEV fill:#fff4e6
        style ISTEST fill:#fff4e6
        style NORMAL fill:#e1f5ff
    end

    subgraph CheckLoop["🔄 Health Check Execution Loop"]
        INITDIALOG["Initialize swiftDialog<br>with loading state<br>and optional Dock badge"]
        RUNCHECK["Execute next check<br>in vendor check set"]
        DIALOGUPDATE["dialogUpdate:<br>Post result to swiftDialog<br>(pass / warning / error / skipped)"]
        MORECHECKS{"More checks<br>remaining?"}

        NORMAL --> INITDIALOG
        ISTEST --> INITDIALOG
        ISDEV --> INITDIALOG
        ISSILENT --> RUNCHECK

        INITDIALOG --> RUNCHECK
        RUNCHECK --> DIALOGUPDATE
        DIALOGUPDATE --> MORECHECKS
        MORECHECKS -->|Yes| RUNCHECK
        MORECHECKS -->|No| FINALSTATE

        style INITDIALOG fill:#e1f5ff
        style RUNCHECK fill:#b2dfdb
        style DIALOGUPDATE fill:#b2dfdb
        style MORECHECKS fill:#ffecb3
    end

    subgraph Final["🏁 Final State & Output"]
        FINALSTATE["Evaluate overall compliance<br>Update dialog to final state"]
        FAILURES{"Failures detected?"}
        FAILNOTICE{"Non-Silent mode?"}
        NOTIFY["Display persistent failure notification<br>swiftDialog pseudo-alert"]
        WEBHOOK{"webhookURL<br>configured?"}
        SENDWEBHOOK["Post failure summary<br>to Teams or Slack"]
        COMPLETIONUI{"Non-Silent mode?"}
        COMPLETIONTIMER["Display completion timer<br>enable Close button"]
        CLEANUP["Remove temp files<br>clear Dock badge"]
        EXIT(["⏹ Script Exits"])

        FINALSTATE --> FAILURES
        FAILURES -->|Yes| FAILNOTICE
        FAILURES -->|No| COMPLETIONUI
        FAILNOTICE -->|Yes| NOTIFY
        FAILNOTICE -->|No| WEBHOOK
        NOTIFY --> WEBHOOK
        WEBHOOK -->|Yes| SENDWEBHOOK
        WEBHOOK -->|No| COMPLETIONUI
        SENDWEBHOOK --> COMPLETIONUI
        COMPLETIONUI -->|Yes| COMPLETIONTIMER
        COMPLETIONUI -->|No| CLEANUP
        COMPLETIONTIMER --> CLEANUP
        CLEANUP --> EXIT

        style FINALSTATE fill:#b2dfdb
        style FAILURES fill:#ffecb3
        style FAILNOTICE fill:#ffecb3
        style NOTIFY fill:#c8e6c9
        style WEBHOOK fill:#ffecb3
        style SENDWEBHOOK fill:#c8e6c9
        style COMPLETIONUI fill:#ffecb3
        style COMPLETIONTIMER fill:#cfd8dc
        style CLEANUP fill:#c8e6c9
    end

    classDef default font-size:11px
```

---

## Key Decision Points

### 1. Operation Mode (Parameter 4)
Set via MDM policy parameter. Determines UI behavior and which checks execute. The intended release default is `Self Service`.

### 2. Root Validation
The script must run as root. If not, it calls `fatal()` and exits immediately with a log entry.

### 3. jq Availability
The `jq` JSON processor is required for building the swiftDialog JSON payload. The script exits with a fatal error if not found.

### 4. swiftDialog Version
The script requires swiftDialog ≥ 3.0.1.4955. If the installed version is older (or swiftDialog is absent), the script downloads and installs the latest release from GitHub before proceeding.

### 5. Dock Integration
If `enableDockIntegration` is `true` and the mode is not `Silent`, the script resolves the Dock icon, attempts a named `Dialog.app` launch so Dock hover text matches the script name, initializes `dockiconbadge`, and falls back to the standard dialog binary if the Dock-enabled launch fails.

### 6. MDM Vendor Detection
The script reads installed configuration profiles to identify the MDM platform. Each vendor maps to a specific ordered list of health checks. Unrecognized or no MDM vendor falls through to a generic baseline check set.

### 7. Individual Check Results
Each health check function returns one of four statuses posted to swiftDialog via `dialogUpdate`:
- `pass` — Check succeeded, requirement met
- `warning` — Check found a non-critical condition
- `error` — Check found a compliance failure
- `skipped` — Check not applicable (e.g., VPN vendor set to `none`)

### 8. Webhook Delivery
If `webhookURL` (Parameter 5) is populated and failures are detected, `quitScript()` posts a JSON payload to Microsoft Teams or Slack summarizing failed checks. The payload auto-detects the webhook type from the URL.

### 9. Failure Notification
When non-`Silent` runs detect failures, `displayFailureNotification()` launches a persistent swiftDialog pseudo-alert summarizing the failed health checks and offering a support action link.

---

## Exit Paths

| Path | Trigger | Logged? |
|---|---|---|
| Fatal: Not root | `EUID != 0` | Yes (`[FATAL ERROR]`) |
| Fatal: jq missing | `jq` not found | Yes (`[FATAL ERROR]`) |
| Normal: Silent | All checks complete, no UI | Yes |
| Normal: Self Service | User dismisses or timer expires | Yes |
| Normal: Test | Current vendor list items simulated as success | Yes |
| Normal: With failure notification | Non-`Silent` failures trigger pseudo-alert summary | Yes |
| Normal: With webhook | Failed run posts webhook before final countdown/cleanup | Yes |
