#!/bin/bash

####################################################################################################
#
# ABOUT
#
#   A script which determines the health of Cisco Umbrella
#
####################################################################################################
#
# HISTORY
#
#   Version 0.0.1, 22-Dev-2023, Dan K. Snelson (@dan-snelson)
#       Original version
#
#   Version 0.0.2, 19-Jan-2024, Dan K. Snelson (@dan-snelson)
#       Updated for Extension Attribute Usage
#
#   Version 0.0.3, 26-Jan-2024, Dan K. Snelson (@dan-snelson)
#       Updated for console-side updates (which unload the System Extension)
#
#   Version 0.0.4, 13-May-2025, Dan K. Snelson (@dan-snelson)
#       Updated for macOS 15.5 information transfers
#
#   Version 0.0.5, 13-May-2025, Dan K. Snelson (@dan-snelson)
#       Added a retry loop for failed filter check
#
#   Version 0.0.6, 14-May-2025, Dan K. Snelson (@dan-snelson)
#       Changed filter check to nslookup of debug.opendns.com
#
#   Version 0.0.7, 18-Jun-2025, Dan K. Snelson (@dan-snelson)
#       Skip filter check if enrolled in the last hour
#
####################################################################################################



####################################################################################################
#
# Variables
#
####################################################################################################

export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin/



####################################################################################################
#
# Functions
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check for running processes (supplied as Parameter 1)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function procesStatus() {

    processToCheck="${1}"
    status=$( pgrep -x "${processToCheck}" )
    if [[ -n ${status} ]]; then
        processCheckResult+="'${processToCheck}' Running; "
    else
        processCheckResult+="'${processToCheck}' Failed; "
    fi

}



####################################################################################################
#
# Program
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Validate Cisco Umbrella
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Determine Cisco Umbrella Organizational ID
if [[ -e "/opt/cisco/secureclient/Umbrella/OrgInfo.json" ]]; then
    umbrellaOrgID=$( plutil -extract organizationId raw /opt/cisco/secureclient/Umbrella/OrgInfo.json )
    if [[ $(find /var/db/.AppleSetupDone -mmin +60) ]]; then
        protectionStatus=$( nslookup -q=txt debug.opendns.com | grep "${umbrellaOrgID}" )
        if [[ -n "${protectionStatus}" ]]; then
            processCheckResult+="Filter Check: Active; "
        else
            processCheckResult+="Filter Check: Failed; "
        fi
    fi
else
    processCheckResult+="Filter Check Failed: Not Installed; "
fi

# Validate Cisco Umbrella System Extension
systemExtensionTest=$( systemextensionsctl list | awk -F"[][]" '/com.cisco.anyconnect.macos.acsockext/ {print $2}' )

case "${systemExtensionTest}" in
    *"activated enabled"*   ) processCheckResult+="'System Extension' Running; " ;;
    *                       ) processCheckResult+="'System Extension' Failed; " ;;
esac

# Validate various Cisco Umbrella Processes
procesStatus "com.cisco.anyconnect.macos.acsockext"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Output Results
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Remove trailing "; "
processCheckResult=${processCheckResult/%; }

case "${processCheckResult}" in
    *"Failed"*  ) RESULT="At least one service failed: ${processCheckResult}" ;;
    *           ) RESULT="All Services Running" ;;
esac

echo "${RESULT}"
