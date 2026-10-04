# Mac Health Check (5.0.0)
## External Checks

This directory contains scripts that perform external checks for the services of various third-party applications. 

These checks are designed to be run in conjunction with the main Mac Health Check script to ensure comprehensive health checks.

![External Checks](../images/external_checks.png)

External checks leverage code you’ve already written, simply added to a new, single-script Jamf Pro policy.

1. The code of an existing Extension Attribute …
1. … is saved as a Script in your Jamf Pro server.
1. This script is then added to a simple Jamf Pro policy, with a custom Trigger.

This custom Trigger and the path to the app itself — so that its icon can be displayed to the end-user — is then specified in Mac Health Check:

```
checkExternalJamfPro "12" "symvBeyondTrustPMfM" "/Applications/PrivilegeManagement.app"
checkExternalJamfPro "13" "symvCiscoUmbrella" "/Applications/Cisco/Cisco Secure Client.app"
checkExternalJamfPro "14" "symvCrowdStrikeFalcon" "/Applications/Falcon.app"
checkExternalJamfPro "15" "symvGlobalProtect" "/Applications/GlobalProtect.app"
```

When the policy successfully executes, the returned output should include one of the following keywords (matched case-insensitively, in this order):

- `Failed` or `Not Running` — service is missing, stopped or failed a required check
- `Running` — service is running
- `Warning` — service is installed but needs attention
- `Error` (or anything else, including `Not Installed`) — service status could not be determined

Beginning in `5.0.0`, `Not Running` is treated as a failure (earlier releases matched it as `Running` and reported stopped agents as healthy), and the sample checks print `Failed: Not Running`. Prefer the `Failed: <reason>` prefix in your own checks. Each `jamf policy -event <trigger>` call is limited to `externalCheckTimeoutSeconds` (default `120`); a policy that runs longer is terminated and reported as `Timed Out`.

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
| `CrowdStrike Falcon Status.bash` | keyword (temporarily sets `AppleLocale` to `en_US`; restored on exit or termination) |
| `Microsoft Defender Check.sh` | defaults domain |
| `Microsoft Office 365.bash` | `<result>Running: …</result>` / `<result>Failed: …</result>` |
| `Nessus Agent Status.sh` | `Running` / `Failed: Not Running` / `Not Installed` |
| `Palo Alto Networks GlobalProtect Status.bash` | keyword |
| `Sophos Endpoint RTS.bash` | `<result>` keyword |
| `Splunk Universal Forwarder Check.sh` | `Running` / `Failed: Not Running` / `Not Installed` |
| `TenableNessusAgent-Alternate.sh` | defaults domain |
| `Zscaler Tunnel Status.sh` | `Running` / `Failed: Not Running` |
