# Mac Health Check (5.0.0)
## External Checks

This directory contains scripts that perform external checks for the services of various third-party applications. 

These checks are designed to be run in conjunction with the main Mac Health Check script to ensure comprehensive health checks.

![External Checks](../images/external_checks.png)

External checks leverage code you’ve already written, simply added to a new, single-script Jamf Pro policy.

1. The code of an existing Extension Attribute …
1. … is saved as a Script in your Jamf Pro server.
1. This script is then added to a simple Jamf Pro policy, with a custom Trigger.

This custom Trigger and the path to the app itself — so that its icon can be displayed to the end-user — is then specified in Mac Health Check's Jamf Pro branch (each index must match its row in `jamfProListitemJSON`; calling through `runConfiguredHealthCheck` keeps targeted rechecks mapped to the right row):

```
runConfiguredHealthCheck "34" checkExternalJamfPro "symvBeyondTrustPMfM"        "/Applications/PrivilegeManagement.app"
runConfiguredHealthCheck "35" checkExternalJamfPro "symvCiscoUmbrella"          "/Applications/Cisco/Cisco Secure Client.app"
runConfiguredHealthCheck "36" checkExternalJamfPro "symvCrowdStrikeFalcon"      "/Applications/Falcon.app"
runConfiguredHealthCheck "37" checkExternalJamfPro "symvGlobalProtect"          "/Applications/GlobalProtect.app"
```

These four sample checks run by default on Jamf Pro. If you have not deployed their policies, remove the four list items and calls (or use the [`mac-health-check-selector`](../Skills/mac-health-check-selector/SKILL.md) skill); otherwise each reports `Error` and every run ends with `Computer Needs Attention`.

When the policy successfully executes, the returned output should include one of the following keywords (matched case-insensitively, in this order):

- `Failed` or `Not Running` — service is missing, stopped or failed a required check
- `Running` — service is running
- `Warning` — service is installed but needs attention
- `Error` (or anything else, including `Not Installed`) — service status could not be determined

Beginning in `5.0.0`, `Not Running` is treated as a failure (earlier releases matched it as `Running` and reported stopped agents as healthy), and the sample checks print `Failed: Not Running`. Prefer the `Failed: <reason>` prefix in your own checks. Each `jamf policy -event <trigger>` call is limited to `externalCheckTimeoutSeconds` (default `120`); a policy that runs longer is terminated and reported as `Timed Out`.

`Error`, `Timed Out`, `Not Installed` and any unmatched output display as an amber `error` in the dialog and are recorded as `warning` in the JSON report and Splunk (they count toward `Computer Needs Attention`, not `Computer Unhealthy`); print `Failed: Not Installed` for agents that must be present.

```
*"failed"* | *"not running"* )
    dialogUpdate "listitem: index: ${1}, … status: fail, statustext: Failed"
    ;;
*"running"* )
    dialogUpdate "listitem: index: ${1}, … status: success, statustext: Running"
    ;;
*"warning"* )
    dialogUpdate "listitem: index: ${1}, … status: error, statustext: ${warningStatus}"
    ;;
```

Checks that write `checkStatus`, `checkType` (`success` / `warning` / `fail` / `error`) and `checkExtended` to `organizationDefaultsDomain` (for example, `Microsoft Defender Check.sh` and `TenableNessusAgent-Alternate.sh`) bypass keyword matching.

### Sample Scripts

| Script | Output |
|---|---|
| `BeyondTrust Privileged Access Management.bash` | `<result>` keyword |
| `Check Printer Install.zsh` | `Running` / `Failed: Missing printer(s)` |
| `Cisco Umbrella.bash` | keyword |
| `CrowdStrike Falcon Status.bash` | `Running; …` / `Failed: …` (temporarily sets `AppleLocale` to `en_US`; restored on exit or termination) |
| `Microsoft Defender Check.sh` | defaults domain |
| `Microsoft Office 365.bash` | `<result>Running: …</result>` / `<result>Failed: …</result>` |
| `Nessus Agent Status.sh` | `Running` / `Failed: Not Running` / `Not Installed` |
| `Palo Alto Networks GlobalProtect Status.bash` | keyword |
| `Sophos Endpoint RTS.bash` | `<result>Running</result>` / `<result>Failed: Real Time Scanning Disabled</result>` / `<result>Not Installed</result>` |
| `Splunk Universal Forwarder Check.sh` | `Running` / `Failed: Not Running` / `Not Installed` |
| `TenableNessusAgent-Alternate.sh` | defaults domain |
| `Zscaler Tunnel Status.sh` | `Running` / `Failed: Not Running` |
