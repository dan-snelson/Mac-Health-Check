###############################################################################
# Script Name: Splunk Universal Forwarder Check
# Author: Tony Young
# Organization: Cloud Lake Technology, an Akima company
# Date Created: 2025-09-29
# Last Updated: 2025-09-29
#
# Purpose:
#   This script checks whether the Splunk Universal Forwarder is installed and
#   whether its `splunkd` process is currently running.
#
# Usage:
#   Run as a Jamf Pro Extension Attribute or standalone script:
#       ./Splunk_Universal_Forwarder_Check.sh
#
# Output:
#   Prints the result in the format required by Jamf Pro:
#       <result>running</result>
#       <result>not running</result>
#       <result>Not Installed</result>
#
# Changelog:
#   2025-09-29 - v1.0.0 - Initial version created for GitHub release.
#
# Disclaimer:
#   This script is provided "as-is" without warranty of any kind. Use at your
#   own risk. Test thoroughly before deploying to production systems.
###############################################################################

#!/bin/bash

SPLUNK_PATH="/private/var/splunkforwarder/bin/splunk"
RESULT="Not Installed"

if [ -x "$SPLUNK_PATH" ]; then
    STATUS_OUTPUT=$($SPLUNK_PATH status 2>/dev/null | grep 'splunkd')
   
    if echo "$STATUS_OUTPUT" | grep -q "is running"; then
        RESULT="running"
    else
        RESULT="not running"
    fi
fi

echo "<result>$RESULT</result>"