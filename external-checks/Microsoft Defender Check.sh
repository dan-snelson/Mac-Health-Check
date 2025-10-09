#!/bin/bash

##################################################################################################
# A script to collect the status of Microsoft Defender.                                          #
# • If Microsoft Defender is not installed, "Not Installed" will be returned.                    #
# • If Microsoft Defender reports unhealthy, "Unhealthy" will be reported along with the reason. #
# •  If Microsoft Defender reports healthy, "Healthy" will be reported.                          #
##################################################################################################
#
# HISTORY
#
#   Version 0.0.2, 09-Oct-2025, Howard Griffith (@HowardGMac)
#   - Added empty checkExtended field to the Not Installed failure to prevent spurious error message
#
###########################################################################################

# Organization's Defaults Domain for External Checks
organizationDefaultsDomain="org.churchofjesuschrist.external"
# checkStatus : string with value for statustext section of dialogUpdate call
# checkExtended : string with value of extended status you want appended with checkStatus value
# checkType: string with value of success, error, or fail to make sure status is properly color coded

    if [[ -f /usr/local/bin/mdatp ]]; then
        defenderOverallHealth=$(/usr/local/bin/mdatp health --field healthy)
        defenderDefinitionsUpdated=$(/usr/local/bin/mdatp health --field definitions_updated_minutes_ago)
        
        if [[ "$defenderOverallHealth" == "true" ]]; then
            /usr/bin/defaults write $organizationDefaultsDomain checkStatus -string "Healthy"
            /usr/bin/defaults write $organizationDefaultsDomain checkType -string "success"
            /usr/bin/defaults write $organizationDefaultsDomain checkExtended -string ""
        else
            /usr/bin/defaults write $organizationDefaultsDomain checkStatus -string "Unhealthy"
            /usr/bin/defaults write $organizationDefaultsDomain checkType -string "error"
            /usr/bin/defaults write $organizationDefaultsDomain checkExtended -string "$(/usr/local/bin/mdatp health --field health_issues)"
        fi
        # 7days * 24 hours/day * 60 minutes/hr = 10080 minutes
        if [[ $defenderDefinitionsUpdated -gt 10080 ]]; then
            /usr/bin/defaults write $organizationDefaultsDomain checkStatus -string "Unhealthy"
            /usr/bin/defaults write $organizationDefaultsDomain checkType -string "error"
            /usr/bin/defaults write $organizationDefaultsDomain checkExtended -string "Definitions Out of Date"
        fi

    else
            /usr/bin/defaults write $organizationDefaultsDomain checkStatus -string "Not Installed"
            /usr/bin/defaults write $organizationDefaultsDomain checkType -string "fail"
            /usr/bin/defaults write $organizationDefaultsDomain checkExtended -string ""
    fi
    
    echo "<result>$(/usr/bin/defaults read $organizationDefaultsDomain checkStatus)</result>"
