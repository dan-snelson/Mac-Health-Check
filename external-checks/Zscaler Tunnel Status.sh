###############################################################################
# Script Name: Zscaler Tunnel Status
# Author: Tony Young
# Organization: Cloud Lake Technology, an Akima company
# Date Created: 2025-09-29
# Last Updated: 2025-09-29
#
# Purpose:
#   Determine whether the Zscaler Tunnel process is currently active.
#
# Usage:
#   Run locally or via Jamf Pro (as an external check or policy script):
#       ./Zscaler Tunnel Status.sh
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

# Zscaler Client Connector tunnel process
if pgrep -x "ZscalerTunnel" >/dev/null 2>&1; then
    echo "Running"
else
    echo "Not Running"
fi
