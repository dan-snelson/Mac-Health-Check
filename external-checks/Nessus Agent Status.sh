###############################################################################
# Script Name: Nessus Agent Status
# Author: Tony Young
# Organization: Cloud Lake Technology, an Akima company
# Date Created: 2025-09-29
# Last Updated: 2025-09-29
#
# Purpose:
#   Checks if the Tenable Nessus Agent service is running on macOS.
#
# Usage:
#   Designed to run as a Jamf Pro Extension Attribute or standalone script:
#       ./Nessus_Agent_Status.sh
#
# Output:
#   Prints the status in the format required by Jamf Pro:
#       <result>Running</result>
#       <result>Stopped</result>
#
# Changelog:
#   2025-09-29 - v1.0.0 - Initial version created for GitHub release.
#
# Disclaimer:
#   This script is provided "as-is" without warranty of any kind. Use at your
#   own risk. Test thoroughly before deploying to production systems.
###############################################################################

#!/bin/sh
# Check to see if Nessus Agent is running
NessusAgentRunning="$(sudo launchctl list com.tenablesecurity.nessusagent | grep "PID" | awk '{ print $1 }' | tr -d '\"')"
if [ "$NessusAgentRunning" = "PID" ]
then
 echo "<result>Running</result>"
else
 echo "<result>Stopped</result>"
fi