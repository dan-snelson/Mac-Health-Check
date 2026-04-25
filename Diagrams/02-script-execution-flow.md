# Mac Health Check: Script Execution Flow

This flowchart documents the `4.0.0b18` decision logic executed each time Mac Health Check runs, from the initial invocation through pre-flight validation, health check execution, and final output.

```mermaid
graph TB
    START(["▶ Script Invoked<br>via MDM policy or local test"])

    subgraph Params["📋 Parameter Parsing"]
        P4["Parameter 4:<br>operationMode<br>intended default: 'Self Service'"]
        P5["Parameter 5:<br>webhookURL<br>default: empty"]
        P6["Parameter 6:<br>splunkOperationMode<br>default: test"]
        START --> P4
        START --> P5
        START --> P6

        style P4 fill:#f3e5f5
        style P5 fill:#f3e5f5
        style P6 fill:#f3e5f5
    end

    subgraph Mode["🔀 Operation Mode Check"]
        ISDEBUG{"operationMode<br>== 'Debug' ?"}
        SETX["Enable set -x<br>(verbose shell tracing)"]

        P4 --> ISDEBUG
        ISDEBUG -->|Yes| SETX
        SETX --> CSCCHECK
        ISDEBUG -->|No| CSCCHECK

        style ISDEBUG fill:#ffecb3
        style SETX fill:#ffcdd2
    end

    subgraph ClientSideCache["Client-Side Cache"]
        CSCCHECK{"Silent + Splunk production<br>server-side Jamf run?"}
        CSCSKIP{"Client script version matches<br>and cached report valid<br>and < 36h old?"}
        CSCSHORTCUT["Set clientSideSkipChecks=true<br>for cached Splunk upload"]

        CSCCHECK -->|No| PREFLIGHT_START
        CSCCHECK -->|Yes| CSCSKIP
        CSCSKIP -->|Yes| CSCSHORTCUT
        CSCSKIP -->|No| PREFLIGHT_START
        CSCSHORTCUT --> PREFLIGHT_START

        style CSCCHECK fill:#ffecb3
        style CSCSKIP fill:#ffecb3
        style CSCSHORTCUT fill:#c8e6c9
    end

    subgraph PreFlight["✈️ Pre-flight Checks"]
        PREFLIGHT_START["Initialize client log<br>/var/log/org.churchofjesuschrist.log"]
        ROOTCHECK{"Running as root?"}
        JSONTOOLS["Require jq<br>for JSON validation,<br>formatting, and merge helpers"]
        CACHEDUPLOADCHECK{"clientSideSkipChecks<br>== true?"}
        CACHEDUPLOAD["Validate cached report again<br>wrap existing JSON in HEC payload<br>upload to Splunk and exit"]
        INSTALLCHECK{"Non-Silent or<br>Silent + Splunk production?"}
        INSTALLCACHE["Install or update client-side script<br>sanitize Jamf inventory code<br>validate and load LaunchDaemon"]
        SDCHECK{"swiftDialog<br>≥ 3.1.0.4976?"}
        SDINSTALL["Download & install<br>swiftDialog from GitHub"]
        KILLSD["Kill existing<br>Dialog instances"]
        REPLAYCHECK{"Self Service + inspectSummaryPreset=on<br>cached inspect config age<br>< inspectReplayMaximumAgeSeconds and valid?"}
        REPLAYLAUNCH["Launch cached moveable Preset 6 summary<br>skip checks and exit"]
        DOCKBADGE["Prepare Dock launch state<br>and initial badge<br>(non-Silent when enabled)"]

        PREFLIGHT_START --> ROOTCHECK
        ROOTCHECK -->|No| FATAL1(["💀 Fatal Error:<br>Not running as root"])
        ROOTCHECK -->|Yes| JSONTOOLS
        JSONTOOLS --> CACHEDUPLOADCHECK
        CACHEDUPLOADCHECK -->|Yes| CACHEDUPLOAD
        CACHEDUPLOADCHECK -->|No| INSTALLCHECK
        INSTALLCHECK -->|Yes| INSTALLCACHE
        INSTALLCHECK -->|No| SDCHECK
        INSTALLCACHE --> SDCHECK
        SDCHECK -->|No| SDINSTALL
        SDINSTALL --> KILLSD
        SDCHECK -->|Yes| KILLSD
        KILLSD --> REPLAYCHECK
        REPLAYCHECK -->|Yes| REPLAYLAUNCH
        REPLAYCHECK -->|No| DOCKBADGE

        style PREFLIGHT_START fill:#b2dfdb
        style ROOTCHECK fill:#ffecb3
        style JSONTOOLS fill:#e1f5ff
        style CACHEDUPLOADCHECK fill:#ffecb3
        style CACHEDUPLOAD fill:#c8e6c9
        style INSTALLCHECK fill:#ffecb3
        style INSTALLCACHE fill:#fff4e6
        style SDCHECK fill:#ffecb3
        style SDINSTALL fill:#fff4e6
        style KILLSD fill:#fff4e6
        style REPLAYCHECK fill:#ffecb3
        style REPLAYLAUNCH fill:#c8e6c9
        style DOCKBADGE fill:#e1f5ff
        style FATAL1 fill:#ffcdd2
    end

    subgraph MDMDetect["🔍 MDM Vendor Detection"]
        DETECTMDM["Inspect installed profiles<br>Match against known MDM vendors"]
        MDMVENDOR{"MDM Vendor<br>Identified?"}
        JAMF["Jamf Pro<br>39 checks"]
        KANDJI["Kandji<br>31 checks"]
        INTUNE["Microsoft Intune<br>32 checks"]
        MOSYLE["Mosyle<br>33 checks"]
        JUMPCLOUD["JumpCloud<br>32 checks"]
        OTHERS["Addigy / Filewave<br>Fleet / Generic<br>28–32 checks"]

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
        ISDEV["Development Mode<br>Run current dev subset<br>(Wi-Fi Strength only)"]
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
        FAILURES{"Health issues detected?"}
        WEBHOOK{"webhookURL<br>configured?"}
        SENDWEBHOOK["Post issue summary<br>to Teams or Slack"]
        REPORT["Write canonical local JSON report<br>and optional Splunk HEC payload"]
        COMPLETIONUI{"Non-Silent mode?"}
        INSPECTHANDOFF{"Self Service + inspectSummaryPreset=on<br>inspect handoff succeeds?"}
        INSPECT["Launch detached moveable Preset 6 summary<br>retain main dialog countdown"]
        COMPLETIONTIMER["Display completion timer<br>enable Close button"]
        CLEANUP["Remove temp files<br>clear Dock badge"]
        EXIT(["⏹ Script Exits"])

        FINALSTATE --> FAILURES
    FAILURES -->|Yes| WEBHOOK
        FAILURES -->|No| REPORT
        WEBHOOK -->|Yes| SENDWEBHOOK
        WEBHOOK -->|No| REPORT
        SENDWEBHOOK --> REPORT
        REPORT --> COMPLETIONUI
        CACHEDUPLOAD --> EXIT
        REPLAYLAUNCH --> EXIT
        COMPLETIONUI -->|Yes| INSPECTHANDOFF
        COMPLETIONUI -->|No| CLEANUP
        INSPECTHANDOFF -->|Yes| INSPECT
        INSPECTHANDOFF -->|No| COMPLETIONTIMER
        INSPECT --> COMPLETIONTIMER
        COMPLETIONTIMER --> CLEANUP
        CLEANUP --> EXIT

        style FINALSTATE fill:#b2dfdb
        style FAILURES fill:#ffecb3
        style FAILNOTICE fill:#ffecb3
        style NOTIFY fill:#c8e6c9
        style WEBHOOK fill:#ffecb3
        style SENDWEBHOOK fill:#c8e6c9
        style REPORT fill:#c8e6c9
        style COMPLETIONUI fill:#ffecb3
        style INSPECTHANDOFF fill:#ffecb3
        style INSPECT fill:#c8e6c9
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
The script requires `jq` for JSON validation, formatting, and dialog/listitem JSON merging. If `jq` is unavailable, `4.0.0b18` exits during pre-flight with a fatal dependency message.

### 4. swiftDialog Version
The script requires swiftDialog ≥ 3.1.0.4976. If the installed version is older (or swiftDialog is absent), the script downloads and installs the latest release from GitHub before proceeding.

### 5. Dock Integration
If `enableDockIntegration` is `true` and the mode is not `Silent`, the script resolves the Dock icon, attempts a named `Dialog.app` launch so Dock hover text matches the script name, initializes `dockiconbadge`, and falls back to the standard dialog binary if the Dock-enabled launch fails.

### 6. Client-Side Cache Upload
When Jamf Pro runs the server-side script in `Silent` mode with `splunkOperationMode=production`, the script compares the client-side script at `/Library/Management/org.churchofjesuschrist/MHC.zsh` to the running server-side version. If versions match and `/var/tmp/MacHealthCheck-Report.json` is valid and younger than 36 hours, it marks the run for cached upload. After root and `jq` pre-flight checks pass, the script validates the cached report again, wraps that existing JSON in the normal Splunk HEC payload, uploads it, and exits without running health checks or reinstalling client-side files.

### 7. MDM Vendor Detection
The script reads installed configuration profiles to identify the MDM platform. Each vendor maps to a specific ordered list of health checks. Unrecognized or no MDM vendor falls through to a generic baseline check set.

### 8. Individual Check Results
Each health check function returns one of four statuses posted to swiftDialog via `dialogUpdate`:
- `pass` — Check succeeded, requirement met
- `warning` — Check found a non-critical condition
- `error` — Check found a compliance failure
- `skipped` — Check not applicable (e.g., VPN vendor set to `none`)

### 9. Webhook Delivery
If `webhookURL` (Parameter 5) is populated and health issues are detected, `quitScript()` posts a JSON payload to Microsoft Teams or Slack summarizing warning, failed, or errored checks. The payload auto-detects the webhook type from the URL.

### 10. JSON Report + Splunk Delivery
At the end of the run, `generateAndSendSplunkReport()` writes the canonical local JSON report and, when `splunkOperationMode=production` plus Parameters 7 and 8 are configured, optionally delivers a Splunk HEC envelope. `splunkOperationMode=off` or `test` still generates the report but skips network transmission. The Client-Side Cache LaunchDaemon uses the local client copy with `Silent` + default `splunkOperationMode=test`, refreshing the report without storing HEC secrets on disk. The daemon does not use `RunAtLoad`; scheduled runs set `launchDaemonRun=true`, and the client script uses that marker to apply deterministic hardware-derived jitter only for daemon-triggered runs.

### 11. Self Service Inspect Summary
In `Self Service`, the script uses finalized in-memory results to generate `/var/tmp/MacHealthCheck-Inspect-Config.json`, then tries to launch a detached, moveable swiftDialog Inspect Mode Preset 6 guided summary. That summary now separates recorded results into `Unhealthy` and `Healthy` sections and omits either section when that bucket is empty. On a normal run, the existing `completionTimer` countdown remains on the main dialog whether the detached summary launches or not. Set `inspectSummaryPreset="off"` to skip both the handoff generation and detached launch.

### 12. Self Service Cached Replay
If `/var/tmp/MacHealthCheck-Inspect-Config.json` is younger than `inspectReplayMaximumAgeSeconds` and the cached inspect JSON still validates, a rerun in `Self Service` skips the health-check loop, launches the cached moveable Preset 6 guided summary after pre-flight/client-side installation, and exits without showing the main dialog countdown. Setting `inspectSummaryPreset="off"` disables this replay path.

### 13. Final Health State
When health issues are detected, non-`Silent` runs update the main dialog to either `Computer Needs Attention` for warning-only results or `Computer Unhealthy` for failures and errors, then continue through report generation, webhook delivery when configured, and the existing completion flow. In `Self Service` with `inspectSummaryPreset="on"`, the detached inspect summary remains the post-run issue detail surface.

---

## Exit Paths

| Path | Trigger | Logged? |
|---|---|---|
| Fatal: Not root | `EUID != 0` | Yes (`[FATAL ERROR]`) |
| Client-Side Cache upload | Matching client/server version and fresh cached JSON in Jamf `Silent` + Splunk production | Yes |
| Normal: Silent | All checks complete, no UI | Yes |
| Normal: Self Service | Detached moveable Preset 6 guided summary launches after report generation and the main dialog still completes its normal countdown | Yes |
| Replay: Self Service cached summary | Fresh inspect config launches cached moveable Preset 6 guided summary and skips the health-check loop | Yes |
| Normal: Test | Current vendor list items simulated as success | Yes |
| Normal: Unhealthy non-`Silent` run | Main dialog ends unhealthy; `Self Service` can still launch detached inspect summary | Yes |
| Normal: With webhook | Failed run posts webhook before report generation and final UI cleanup | Yes |
