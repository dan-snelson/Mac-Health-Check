#!/bin/bash
####################################################################################################
#
# ABOUT
#
#   A script which determines the health of BeyondTrust Privilege Management for Mac
#
####################################################################################################
#
# HISTORY
#
#   Version 0.0.1, 22-Dec-2023, Dan K. Snelson (@dan-snelson)
#       Original version
#
#   Version 0.0.2, 07-Jun-2024, Dan K. Snelson (@dan-snelson)
#       Updates for BT PMfM 24.x
#
#   Version 0.0.3, 10-Mar-2025, Dan K. Snelson (@dan-snelson)
#       Updates for BT PMfM 25.2
#
#   Version 0.0.4, 14-Aug-2025, Dan K. Snelson (@dan-snelson)
#       Updates for BT PMfM 25.4.2.2
#
####################################################################################################



####################################################################################################
#
# Variables
#
####################################################################################################

scriptVersion="0.0.4"
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
    status=$( /usr/bin/pgrep -x "${processToCheck}" )
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
# Validate BeyondTrust Privilege Management for Mac
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Validate BT PMfM System Extension
systemExtensionTest=$( systemextensionsctl list | awk -F"[][]" '/com.beyondtrust.endpointsecurity/ {print $2}' )

case "${systemExtensionTest}" in
    *"activated enabled"* ) processCheckResult="'System Extension' Running; " ;;
    *                     ) processCheckResult="'System Extension' Failed; " ;;
esac

# Validate various BT PMfM Processes
procesStatus "defendpointd"
procesStatus "Custodian"
# procesStatus "PMCAdapter"
procesStatus "PMCPackageManager"
procesStatus "PrivilegeManagement"
# procesStatus "NewPrivilegeManagement"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Output Results
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Remove trailing "; "
processCheckResult=${processCheckResult/%; }

case "${processCheckResult}" in
    *"Failed"*  ) RESULT="At least one service failed: ${processCheckResult}" ;;
    *           ) RESULT="All Services Running" ;;
esac

/bin/echo "<result>${RESULT}</result>"