#!/bin/bash
###############################################################################
# Script Name: Nessus Agent Status
# Author: Tony Young
# Organization: Cloud Lake Technology, an Akima company
# Date Created: 2025-09-29
# Last Updated: 2026-10-04
#
# Purpose:
#   Check whether Tenable Nessus Agent is installed and running on macOS.
#
# Usage:
#   Run locally or via Jamf Pro (as an external check or policy script):
#       ./Nessus Agent Status.sh
#
# Output:
#   Prints a single line status (no <result> tags), suitable for Jamf "External"
#   scripts or log parsing, e.g.:
#       Running
#       Failed: Not Running
#       Not Installed
#
# Changelog:
#   2026-10-04 - v1.1.3 - `nessus-service is not running` no longer matches `running`; reports `Not Installed` when the agent is absent (Mac Health Check 5.0.0).
#   2026-10-03 - v1.1.2 - Prints `Failed: Not Running` (Mac Health Check reported `Not Running` as healthy) and uses `#!/bin/bash` (Mac Health Check 5.0.0).
#   2026-09-29 - v1.1.1 - Removed `/usr/local/bin` from `PATH` (Mac Health Check 5.0.0b6).
#   2025-09-29 - v1.1.0 - Converted to external check style output (no <result> tags).
#   2025-09-29 - v1.0.0 - Initial version created for GitHub release.
#
# Disclaimer:
#   This script is provided "as-is" without warranty of any kind. Use at your
#   own risk. Test thoroughly before deploying to production systems.
###############################################################################

set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

RESULT="Not Installed"

# Preferred: use Nessus Agent service script if present
SVC="/Library/NessusAgent/run/svc.sh"
if [ -x "$SVC" ]; then
    # svc.sh status returns text such as "nessus-service is running"; "not running" also contains "running"
    SVC_STATUS="$("$SVC" status 2>/dev/null || true)"
    if printf '%s\n' "$SVC_STATUS" | grep -qi "not running"; then
        RESULT="Failed: Not Running"
    elif printf '%s\n' "$SVC_STATUS" | grep -qi "running"; then
        RESULT="Running"
    else
        RESULT="Failed: Not Running"
    fi
elif [ -d "/Library/NessusAgent" ] || launchctl list 2>/dev/null | grep -q "com.tenablesecurity.nessusagent"; then
    # Fallbacks: launchctl label or process name
    if launchctl print system/com.tenablesecurity.nessusagent 2>/dev/null | grep -q "pid =" ; then
        RESULT="Running"
    elif pgrep -f "[n]essus.*agent" >/dev/null 2>&1; then
        RESULT="Running"
    else
        RESULT="Failed: Not Running"
    fi
fi

echo "${RESULT}"
