###############################################################################
# Script Name: Zscaler Tunnel Status
# Author: Tony Young
# Organization: Cloud Lake Technology, an Akima company
# Date Created: 2025-09-29
# Last Updated: 2025-09-29
#
# Purpose:
#   Determines whether the Zscaler Tunnel process is running on a macOS device.
#
# Usage:
#   Run as a Jamf Pro Extension Attribute or standalone script:
#       ./Zscaler_Tunnel_Status.sh
#
# Output:
#   Prints the status in the format required by Jamf Pro:
#       <result>Running</result>
#       <result>Not Running</result>
#
# Changelog:
#   2025-09-29 - v1.0.0 - Initial version created for GitHub release.
#
# Disclaimer:
#   This script is provided "as-is" without warranty of any kind. Use at your
#   own risk. Test thoroughly before deploying to production systems.
###############################################################################

#!/bin/bash

# check for process
PROCESS=$(pgrep ZscalerTunnel)

# see if process is running
if [[ -z "$PROCESS" ]]; then
    RESULT="Not Running"
else
    RESULT="Running"
fi

# report results
echo "<result>${RESULT}</result>"