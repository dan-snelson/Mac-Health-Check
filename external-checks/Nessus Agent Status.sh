###############################################################################
# Script Name: Nessus Agent Status
# Author: Tony Young
# Organization: Cloud Lake Technology, an Akima company
# Date Created: 2025-09-29
# Last Updated: 2025-09-29
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
#       Not Running
#       Not Installed
#
# Changelog:
#   2025-09-29 - v1.1.0 - Converted to external check style output (no <result> tags).
#   2025-09-29 - v1.0.0 - Initial version created for GitHub release.
#
# Disclaimer:
#   This script is provided "as-is" without warranty of any kind. Use at your
#   own risk. Test thoroughly before deploying to production systems.
###############################################################################

#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin

RESULT="Not Installed"

# Preferred: use Nessus Agent service script if present
SVC="/Library/NessusAgent/run/svc.sh"
if [ -x "$SVC" ]; then
    # svc.sh status returns text such as "nessus-service is running"
    if "$SVC" status 2>/dev/null | grep -qi "running"; then
        RESULT="Running"
    else
        RESULT="Not Running"
    fi
else
    # Fallbacks: launchctl label or process name
    if launchctl list 2>/dev/null | grep -q "com.tenablesecurity.nessusagent"; then
        # If listed, check if it has a PID column via launchctl print (macOS 11+)
        if launchctl print system/com.tenablesecurity.nessusagent 2>/dev/null | grep -q "pid =" ; then
            RESULT="Running"
        else
            RESULT="Not Running"
        fi
    elif pgrep -f "[n]essus.*agent" >/dev/null 2>&1; then
        RESULT="Running"
    else
        RESULT="Not Running"
    fi
fi

echo "${RESULT}"
