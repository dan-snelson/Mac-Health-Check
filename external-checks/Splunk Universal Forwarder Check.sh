###############################################################################
# Script Name: Splunk Universal Forwarder Check
# Author: Tony Young
# Organization: Cloud Lake Technology, an Akima company
# Date Created: 2025-09-29
# Last Updated: 2025-09-29
#
# Purpose:
#   Check whether Splunk Universal Forwarder is installed and if its daemon is running.
#
# Usage:
#   Run locally or via Jamf Pro (as an external check or policy script):
#       ./Splunk Unversal Forwarder Check.sh
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

SPLUNK_PATH="/private/var/splunkforwarder/bin/splunk"
RESULT="Not Installed"

if [ -x "$SPLUNK_PATH" ]; then
    # If the binary exists, query status
    if "$SPLUNK_PATH" status 2>/dev/null | grep -q 'splunkd.*is running'; then
        RESULT="Running"
    else
        RESULT="Not Running"
    fi
fi

echo "${RESULT}"
