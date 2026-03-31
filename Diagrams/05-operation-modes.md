# Mac Health Check: Operation Modes

This diagram compares all five `3.2.0` Mac Health Check operation modes, showing how each mode differs in terms of UI, Dock behavior, logging, and intended use case.

```mermaid
graph TB
    ENTRY(["Mac-Health-Check.zsh<br>Parameter 4: operationMode"])

    subgraph SelfService["🖥️ Self Service (Default)"]
        SS_DESC["Trigger: User via MDM Self Service<br>UI: Full swiftDialog dialog<br>Anticipation: 2s between checks<br>Dock badge: Yes (when enabled)<br>Completion timer: 60s auto-close<br>Logging: Full structured log"]
        SS_USE["Use case:<br>End-user–initiated health check<br>on-demand via Self Service"]

        style SS_DESC fill:#e1f5ff
        style SS_USE fill:#c8e6c9
    end

    subgraph Silent["🔇 Silent"]
        SL_DESC["Trigger: Scheduled MDM policy<br>UI: None<br>Anticipation: 0s (instant)<br>Dock badge: No<br>Completion timer: N/A<br>Logging: Full structured log"]
        SL_USE["Use case:<br>Background compliance monitoring<br>Pairs with webhook for alerting"]

        style SL_DESC fill:#cfd8dc
        style SL_USE fill:#c8e6c9
    end

    subgraph Debug["🔍 Debug"]
        DB_DESC["Trigger: MDM policy or manual run<br>UI: Full swiftDialog dialog<br>Anticipation: 2s between checks<br>Dock badge: Yes (when enabled)<br>Completion timer: 60s auto-close<br>Logging: Full + set -x + dialog debug flags"]
        DB_USE["Use case:<br>Troubleshooting check failures<br>and script behavior"]

        style DB_DESC fill:#fff4e6
        style DB_USE fill:#ffecb3
    end

    subgraph Development["🔧 Development"]
        DV_DESC["Trigger: Manual / MDM policy<br>UI: swiftDialog — curated dev subset<br>Anticipation: 2s between checks<br>Dock badge: Yes (when enabled)<br>Completion timer: 60s auto-close<br>Logging: Full structured log"]
        DV_USE["Use case:<br>Iterating on a curated set of<br>high-signal health checks"]

        style DV_DESC fill:#fff4e6
        style DV_USE fill:#ffecb3
    end

    subgraph Test["🧪 Test"]
        TS_DESC["Trigger: Manual / MDM policy<br>UI: Full swiftDialog dialog<br>Anticipation: 2s between checks<br>Dock badge: Yes (when enabled)<br>Completion timer: 60s auto-close<br>Logging: Full structured log — simulated pass results"]
        TS_USE["Use case:<br>Validating UI layout and<br>check labels without real data"]

        style TS_DESC fill:#f3e5f5
        style TS_USE fill:#c8e6c9
    end

    ENTRY -->|default| SelfService
    ENTRY -->|"'Silent'"| Silent
    ENTRY -->|"'Debug'"| Debug
    ENTRY -->|"'Development'"| Development
    ENTRY -->|"'Test'"| Test

    style ENTRY fill:#b2dfdb

    classDef default font-size:11px
```

---

## Mode Comparison Table

| Attribute | Self Service | Silent | Debug | Development | Test |
|---|---|---|---|---|---|
| **Parameter 4 value** | `Self Service` | `Silent` | `Debug` | `Development` | `Test` |
| **Is default?** | Yes | No | No | No | No |
| **swiftDialog UI** | Full dialog | None | Full dialog | Curated dev subset | Full dialog |
| **Anticipation delay** | 2 seconds | 0 seconds | 2 seconds | 2 seconds | 2 seconds |
| **Dock badge** | Yes (when enabled) | No | Yes (when enabled) | Yes (when enabled) | Yes (when enabled) |
| **Completion timer** | 60s (configurable) | N/A | 60s (configurable) | 60s (configurable) | 60s (configurable) |
| **Logging** | Full | Full | Full + `set -x` | Full structured log | Full structured log |
| **Persistent failure notification** | If failures | No | If failures | If failures | No |
| **Real check data** | Yes | Yes | Yes | Yes (curated subset) | No (simulated pass results) |
| **Intended actor** | End user | Automated | Administrator | Developer | Developer |

---

## Mode Details

### Self Service (Default)
The primary end-user-facing mode. Launched by a user clicking the Mac Health Check policy in MDM Self Service. Displays a full swiftDialog dialog with real-time status updates as each check runs. When Dock integration is enabled, the Dock badge counts down remaining checks. The dialog auto-closes after the `completionTimer` countdown (default: 60 seconds), or the user can dismiss it manually.

**When to use:** Standard deployment for user-initiated compliance checks.

---

### Silent
Runs all health checks without displaying any user interface. Intended for scheduled background compliance runs (for example, at login or on recurring MDM check-in). The `anticipationDuration` is automatically set to `0` in this mode to minimize execution time. Results are written to the client log and, if configured, posted to a webhook. Dock integration and persistent failure notifications are suppressed.

**When to use:** Continuous background compliance monitoring. Pair with a Teams or Slack webhook to surface failures without interrupting users.

---

### Debug
Similar to Self Service, but with `set -x` tracing enabled plus swiftDialog debug launch arguments (`--verbose --resizable --debug red`). This makes it easier to identify which part of the zsh script or dialog rendering is causing unexpected behavior.

**When to use:** Diagnosing why a specific check is failing or returning an unexpected status.

---

### Development
Runs a curated development subset of checks in a normal non-`Silent` dialog flow. In `3.2.0`, that subset covers Available Updates, AirDrop, Jamf Hosts, Free Disk Space, and the Desktop / Downloads / Trash size checks, making it useful for iterating on high-signal list items without running the full vendor-specific suite.

**When to use:** Tuning check behavior, remediation copy, or dialog presentation while keeping the run shorter than a full production policy.

---

### Test
Builds the full current vendor list item set, then marks each item as a successful simulated result without executing the real health-check functions. The UI renders like production, making this mode useful for validating dialog layout, list item labels, status icon sequencing, and the overall visual presentation.

**When to use:** Verifying UI behavior after changing dialog configuration, list item labels, or overall script structure.

---

## Setting the Operation Mode

Operation mode is set via **Parameter 4** in the MDM policy:

```
# MDM Script Parameter 4
Self Service    ← default; omit parameter to use this
Silent
Debug
Development
Test
```

For local testing, pass the mode as the fourth argument:

```bash
sudo zsh Mac-Health-Check.zsh "" "" "" "Debug"
```
