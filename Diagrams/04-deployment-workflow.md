# Mac Health Check: Deployment Workflow

This diagram provides a step-by-step guide for deploying the `5.0.0` release of Mac Health Check through an MDM solution. Follow the phases in order for a successful deployment.

```mermaid
graph TB
    START(["🚀 Begin Deployment"])

    subgraph Phase1["Phase 1: Prerequisites"]
        P1A["Confirm MDM solution<br>Jamf Pro · Kandji · Intune · Mosyle<br>JumpCloud · Addigy · Filewave · Fleet"]
        P1B["Confirm prerequisites<br>root-owned jq required; swiftDialog<br>preinstalled or installable"]
        P1C["Download Mac-Health-Check.zsh<br>from GitHub repository"]

        P1A --> P1B
        P1B --> P1C

        style P1A fill:#b2dfdb
        style P1B fill:#b2dfdb
        style P1C fill:#b2dfdb
    end

    subgraph Phase2["Phase 2: Script Customization"]
        P2A["Edit Organization + Support Defaults<br>(branding, Dock, thresholds, contacts)"]
        P2B["Set branding and Dock behavior<br>organizationBrandingBannerURL<br>organizationOverlayiconURL<br>enableDockIntegration · dockIcon"]
        P2C["Set operational thresholds<br>vpnClientVendor · organizationFirewall<br>allowedUptimeMinutes · maxUptimeMinutes<br>allowedMinimumFreeDiskPercentage"]
        P2D["Set support links and labels<br>supportTeam* or supportLabelN/valueN"]

        P2A --> P2B
        P2A --> P2C
        P2A --> P2D

        style P2A fill:#f3e5f5
        style P2B fill:#f3e5f5
        style P2C fill:#f3e5f5
        style P2D fill:#f3e5f5
    end

    subgraph Phase3["Phase 3: External Checks (Optional)"]
        P3Q{"Deploy external<br>security tool checks?"}
        P3A["Upload external-checks/ scripts<br>to MDM as separate policies"]
        P3B["Most plugins print a keyword result;<br>set organizationDefaultsDomain only for<br>defaults-domain plugins (Defender, Tenable Alt)"]
        P3SKIP["Skip — remove the 4 Jamf Pro external<br>list items (0-based indexes 34–37) or use<br>the selector skill; otherwise each<br>reports Error (recorded as warning)"]

        P3Q -->|Yes| P3A
        P3A --> P3B
        P3Q -->|No| P3SKIP

        style P3Q fill:#ffecb3
        style P3A fill:#fff4e6
        style P3B fill:#fff4e6
        style P3SKIP fill:#cfd8dc
    end

    subgraph Phase4["Phase 4: MDM Upload"]
        P4A["Upload Mac-Health-Check.zsh<br>to MDM as a script"]
        P4B["Set Parameter 4<br>operationMode = 'Self Service'"]
        P4C["Deploy MacHealthCheck-Secrets.plist (optional)<br>webhookURL + splunkHECToken"]

        P4A --> P4B
        P4A --> P4C

        style P4A fill:#c8e6c9
        style P4B fill:#c8e6c9
        style P4C fill:#c8e6c9
    end

    subgraph Phase5["Phase 5: Self Service Policy"]
        P5A["Create MDM policy<br>Assign Mac-Health-Check.zsh"]
        P5B["Configure Self Service display<br>Name, description, icon"]
        P5C["Assign scope<br>Target devices / groups"]
        P5D["Publish policy"]

        P5A --> P5B
        P5B --> P5C
        P5C --> P5D

        style P5A fill:#c8e6c9
        style P5B fill:#c8e6c9
        style P5C fill:#c8e6c9
        style P5D fill:#c8e6c9
    end

    subgraph Phase6["Phase 6: Silent + Client-Side Cache (Optional)"]
        P6Q{"Deploy recurring<br>silent reporting?"}
        P6A["Create MDM upload policy<br>Parameter 4 = 'Silent'<br>Parameter 6 = 'production'"]
        P6B["Client LaunchDaemon refreshes<br>local report in a deterministic 00:53-01:53 window centered on 1:23 a.m.<br>No RunAtLoad · no Splunk upload · no webhooks"]
        P6C["Assign scope &amp; publish"]
        P6SKIP2["Skip recurring silent reporting"]

        P6Q -->|Yes| P6A
        P6A --> P6B
        P6B --> P6C
        P6Q -->|No| P6SKIP2

        style P6Q fill:#ffecb3
        style P6A fill:#fff4e6
        style P6B fill:#fff4e6
        style P6C fill:#fff4e6
        style P6SKIP2 fill:#cfd8dc
    end

    subgraph Phase7["Phase 7: Testing"]
        P7A["Run in Debug mode<br>Parameter 4 = 'Debug'<br>Review set -x output"]
        P7B["Run in Development mode<br>Parameter 4 = 'Development'<br>Exercise Clock Skew, Memory Pressure<br>and APNs only"]
        P7C["Run in Test mode<br>Parameter 4 = 'Test'<br>Validate full vendor UI with simulated success"]
        P7D{"All checks<br>render correctly?"}
        P7FIX["Review configuration<br>and re-test"]

        P7A --> P7B
        P7B --> P7C
        P7C --> P7D
        P7D -->|No| P7FIX
        P7FIX --> P7A

        style P7A fill:#fff4e6
        style P7B fill:#fff4e6
        style P7C fill:#fff4e6
        style P7D fill:#ffecb3
        style P7FIX fill:#ffcdd2
    end

    subgraph Phase8["Phase 8: Production &amp; Monitoring"]
        P8["Promote to production scope"]
        P8A["Monitor /var/log/org.churchofjesuschrist.log<br>Review structured log output"]
        P8B["Review webhook alerts<br>(Jamf Pro, if configured)"]
        P8C["Validate Dock badge and unhealthy end-state<br>on non-Silent runs"]
        P8D["Check MDM inventory<br>for compliance trends"]

        P8 --> P8A
        P8 --> P8B
        P8 --> P8C
        P8 --> P8D

        style P8 fill:#c8e6c9
        style P8A fill:#c8e6c9
        style P8B fill:#c8e6c9
        style P8C fill:#c8e6c9
        style P8D fill:#c8e6c9
    end

    %% Phase transitions (kept outside subgraph blocks so each node renders in its own phase)
    START --> P1A
    P1C --> P2A
    P2B --> P3Q
    P2C --> P3Q
    P2D --> P3Q
    P3B --> P4A
    P3SKIP --> P4A
    P4B --> P5A
    P4C --> P5A
    P5D --> P6Q
    P6C --> P7A
    P6SKIP2 --> P7A
    P7D -->|Yes| P8

    classDef default font-size:11px
```

---

## Detailed Step-by-Step Guide

### Phase 1: Prerequisites

Before deploying Mac Health Check, confirm:

- [ ] An MDM solution is in place (Jamf Pro, Kandji, Microsoft Intune, Mosyle, JumpCloud, Addigy, Filewave, or Fleet)
- [ ] A root-owned `jq` is present on target Macs that do not already bundle it (macOS 15+ ships `/usr/bin/jq`; user-owned Homebrew copies are rejected)
- [ ] `swiftDialog` is approved for your environment and is either preinstalled or allowed to auto-install/update
- [ ] You have downloaded the latest `Mac-Health-Check.zsh` from the [GitHub repository](https://github.com/dan-snelson/Mac-Health-Check)

---

### Phase 2: Script Customization

Open `Mac-Health-Check.zsh` and review the **Organization Variables** and **IT Support Variables** sections.

**Required changes:**
| Variable | What to Set |
|---|---|
| `organizationBrandingBannerURL` | Your organization's banner image URL |
| `organizationOverlayiconURL` | Your MDM self-service app icon path or URL |
| `enableDockIntegration` / `dockIcon` | Whether to show Dock integration in non-`Silent` modes and which icon to use; the Dock-named swiftDialog copy is re-signed ad hoc (dropping swiftDialog's Team ID), so set `enableDockIntegration="false"` where PPPC or notification profiles key on that Team ID |
| `vpnClientVendor` | `paloalto`, `cisco`, `tailscale`, or `none` |
| `organizationFirewall` | `socketfilterfw` (most orgs) or `pf` |
| `supportLabel1` / `supportValue1` (and additional pairs as needed) | Dynamic support lines and the first URL-like action for the Info button |

**Optional changes:**
| Variable | Default | Description |
|---|---|---|
| `allowedUptimeMinutes` | `10080` (7 days) | Uptime warning threshold |
| `maxUptimeMinutes` | `43200` (30 days) | Uptime fail threshold; set to `""` to disable |
| `allowedMinimumFreeDiskPercentage` | `10` | Free disk fail threshold |
| `previousMinorOS` | `2` | How many older macOS versions are compliant |
| `completionTimer` | `60` | Fallback dialog auto-close (seconds) |

`webhookURL` and `splunkHECToken` belong in the root-only secrets file `/Library/Management/org.churchofjesuschrist/MacHealthCheck-Secrets.plist` (`root:wheel`, mode `600`, deployed from a package payload), not in script defaults or policy parameters. Beginning in `5.0.0`, secrets supplied only through **Parameter 5** or **Parameter 8** are rejected unless `allowParameterSecrets="true"` is set in the script (not recommended; parameters are visible to local users via `ps`). Splunk reporting mode, HEC URL, index, and sourcetype remain runtime parameters.

---

### Phase 3: External Checks (Optional, Jamf Pro Only)

If your organization uses BeyondTrust, Cisco Umbrella, CrowdStrike, or GlobalProtect:

1. Review the scripts in `external-checks/` and customize as needed
2. Upload each external check script to Jamf Pro with its trigger name (e.g., `symvCrowdStrikeFalcon`)
3. Most plugins print a keyword result (`Running`, `Failed`, `Not Running`, `Warning`); only for plugins that write to a defaults domain (the Microsoft Defender and Tenable (Alternate) samples) set `organizationDefaultsDomain` in `Mac-Health-Check.zsh` to match
4. Ensure the `checkExternalJamfPro` calls in the Jamf Pro check set (0-based list item indexes 34–37, shown as items 35–38 in the dialog, after Microsoft Teams and before Wi-Fi Strength) reference the correct trigger names

If you skip external checks on Jamf Pro, remove those four list items and their `checkExternalJamfPro` calls (renumbering the later `SF=NN.circle` icons and `runConfiguredHealthCheck` indexes), or build a trimmed copy with the [Mac Health Check Selector skill](../Skills/mac-health-check-selector/SKILL.md), which renumbers automatically; otherwise each missing policy reports `Error`, recorded as `warning` in the JSON report.

---

### Phase 4: MDM Upload

1. Upload the customized `Mac-Health-Check.zsh` to your MDM as a script
2. Configure the script parameters:
   - **Parameter 4** — Operation mode (start with `Debug` for initial testing)
   - **Parameter 5** — Leave blank; deploy `webhookURL` in `MacHealthCheck-Secrets.plist` (rejected unless `allowParameterSecrets="true"`)
   - **Parameters 6-10** — Splunk reporting mode, HEC URL, HEC token (leave blank; deploy `splunkHECToken` in `MacHealthCheck-Secrets.plist`), HEC index, and HEC sourcetype
   - **Parameter 11** — `forceFreshRun` one-shot override for bypassing `Self Service` targeted verification/replay or the `Silent` + `production` cached upload when you need a complete fresh run

---

### Phase 5: Self Service Policy

Create an MDM policy with:
- **Script:** `Mac-Health-Check.zsh`, Parameter 4 = `Self Service`
- **Self Service:** Enabled with a descriptive name, icon, and category
- **Scope:** Start with a test group; expand to full fleet after validation

---

### Phase 6: Silent Mode Policy and Client-Side Cache (Optional)

For background compliance monitoring, create a second policy:
- **Script:** `Mac-Health-Check.zsh`, Parameter 4 = `Silent`, Parameter 6 = `production`
- **Trigger:** Login, recurring check-in, or scheduled
- **No Self Service entry** — runs silently in the background
- **Splunk parameters:** Provide HEC URL, index and sourcetype as policy Parameters 7, 9 and 10; deploy the HEC token as `splunkHECToken` in `MacHealthCheck-Secrets.plist` (Parameter 8 is rejected unless `allowParameterSecrets="true"`)
- **Client-Side Cache:** `Self Service`, `Debug` and `Silent` + `production` runs on any MDM install `/Library/Management/org.churchofjesuschrist/MHC.zsh` plus `org.churchofjesuschrist.MHC`; the script validates and loads a root LaunchDaemon without `RunAtLoad`, routes daemon stdout/stderr to `/dev/null`, and the client-side LaunchDaemon refreshes the local JSON report nightly with deterministic per-Mac jitter across 00:53-01:53 without uploading to Splunk or sending webhooks; the copy is installed only when the running script is a root-owned file in root-controlled directories, and `Test` / `Development` never install it
- The install step runs before the cached-upload decision. When any MDM runs `Silent` + `production`, matching client/server versions and a valid report under 36 hours old allow cached upload without re-running health checks
- When stale data must be overwritten immediately, set Parameter 11 to `true` for one policy invocation or create a root-owned `/var/tmp/MacHealthCheck-Force-Fresh-Run` (for example, `sudo touch`; files owned by other users are ignored and removed) before next eligible `Silent` + `production` run; both paths bypass cached upload and force a complete fresh run
- Expect two common timestamps in healthy production telemetry: an overnight full `Silent` refresh that writes fresh local JSON, then a later `Silent` + `production` policy that uploads that cached JSON without re-running checks

---

### Phase 7: Testing

Use the three developer-oriented modes to validate behavior before rolling out to all users:

| Mode | Purpose | How to Use |
|---|---|---|
| `Debug` | Shell tracing (`set -x`) for troubleshooting | Run policy and review MDM logs |
| `Development` | Exercise only `checkClockSkew()`, `checkMemoryPressure()` and `checkAPNs()` in normal dialog flow | Set Parameter 4 to `Development` |
| `Test` | Build the full current vendor list and mark each item successful without running the real checks | Validate UI layout and messages |

---

### Phase 8: Monitoring

After production deployment, monitor:

- **Client logs** at `/var/log/org.churchofjesuschrist.log` on managed Macs — look for `[WARNING]` and `[ERROR]` entries
- **Client-Side Cache assets** — confirm `/Library/Management/org.churchofjesuschrist/MHC.zsh`, `/Library/LaunchDaemons/org.churchofjesuschrist.MHC.plist`, and `/Library/Management/org.churchofjesuschrist/MacHealthCheck-Report.json` exist on test Macs
- **LaunchDaemon jitter** — confirm the plist starts at 00:53, does not include `RunAtLoad`, and the client log records `Client-Side Cache: Jitter offset = X seconds` during daemon-triggered runs
- **Fresh-write marker** — confirm full runs log `Splunk Reporting: local report written to /Library/Management/org.churchofjesuschrist/MacHealthCheck-Report.json`; this is the canonical proof that new report data was generated locally
- **Cached-upload marker and age** — confirm later `Silent` + `production` uploads log `cached report is valid and <seconds>s old. Skipping health checks.` so operators can distinguish delivery time from collection time
- **Force Fresh Run marker** — confirm bypassed runs log `Client-Side Cache: FORCE FRESH RUN triggered ...` followed by a fresh-write marker instead of cached-upload notices
- **Dock badge, inspect summary handoff, cached replay, and unhealthy end-state handling** on test Macs in non-`Silent` modes — confirm countdown badges update per check, `Self Service` launches the detached moveable Preset 6 guided summary with separate `Unhealthy` and `Healthy` sections during the retained main-dialog countdown when `inspectSummaryPreset="on"`, reruns replay the cached summary after pre-flight/client-side installation without re-running checks only while the cached handoff file remains younger than `inspectReplayMaximumAgeSeconds`, and failed runs now rely on the unhealthy main-dialog state plus the detached `Self Service` summary instead of a pseudo-alert notification
- **Webhook notifications** in Teams or Slack (if configured) — review failure summaries; delivery is effectively Jamf Pro-only (messages include a `View in Jamf Pro` link; Mosyle payloads carry an empty link and may be rejected; other MDMs send nothing)
- **MDM inventory** — Jamf Pro interactive/full runs can still trigger inventory submission, while `Silent` + Splunk production and Client-Side Cache LaunchDaemon runs skip it

---

## Deployment Checklist

- [ ] Organization and support defaults customized (branding, Dock, VPN, firewall, thresholds, contact links)
- [ ] External check scripts uploaded and triggers configured (if applicable)
- [ ] Script uploaded to MDM with correct parameters
- [ ] Self Service policy created, scoped, and published
- [ ] Tested in Debug mode — no fatal errors
- [ ] Tested in Development mode — Clock Skew, Memory Pressure and APNs behave as expected
- [ ] Tested in Test mode — UI renders correctly
- [ ] Silent mode policy created with Splunk production parameters (if desired)
- [ ] Client-Side Cache script, LaunchDaemon, and cached JSON validated on a test Mac
- [ ] Client-Side Cache jitter validated on multiple Macs; offsets differ but remain stable per Mac
- [ ] Webhook validated (Jamf Pro, if configured)
- [ ] Rolled out to full production scope
