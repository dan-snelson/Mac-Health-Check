#!/bin/zsh --no-rcs

############################################################################################################################
# A script to collect the status of Tenable Nessus Agent.                                                                  #
# • If Tenable Nessus Agent is not installed, "Not Installed" will be returned.                                            #
# • If Tenable Nessus Agent is not linked to a manager, "Unhealthy" will be reported along with the reason.                #
# • If Tenable Nessus Agent is linked but has an authentication error, "Unhealthy" will be reported along with the reason. #
# • If Tenable Nessus Agent reports that it is running without previously listed errors, "Running" will be reported.       #                                       
############################################################################################################################
#
# HISTORY
#
#   Version 0.0.1, 11-Oct-2025, Howard Griffith (@HowardGMac)
#   - Intial version of this external check
#
###########################################################################################

# Organization's Defaults Domain for External Checks
organizationDefaultsDomain="org.churchofjesuschrist.external"
# checkStatus : string with value for statustext section of dialogUpdate call
# checkExtended : string with value of extended status you want appended with checkStatus value
# checkType: string with value of success, error, or fail to make sure status is properly color coded

    if [[ -f /Library/NessusAgent/run/sbin/nessuscli ]]; then
        nessusOverallHealth=$(/Library/NessusAgent/run/sbin/nessuscli agent status)
        
        if [[ "$nessusOverallHealth" =~ "Link status: authentication error" ]]; then
            /usr/bin/defaults write $organizationDefaultsDomain checkStatus -string "Unhealthy"
            /usr/bin/defaults write $organizationDefaultsDomain checkType -string "error"
            /usr/bin/defaults write $organizationDefaultsDomain checkExtended -string "Linked to controller with Authentication Error."
        elif [[ "$nessusOverallHealth" =~ "Link status: Not linked to a manager" ]]; then
            /usr/bin/defaults write $organizationDefaultsDomain checkStatus -string "Unhealthy"
            /usr/bin/defaults write $organizationDefaultsDomain checkType -string "error"
            /usr/bin/defaults write $organizationDefaultsDomain checkExtended -string "Agent not linked to a manager."
        fi

        if [[ "$nessusOverallHealth" =~ "Running: Yes" ]]; then
            /usr/bin/defaults write $organizationDefaultsDomain checkStatus -string "Running"
            /usr/bin/defaults write $organizationDefaultsDomain checkType -string "success"
            /usr/bin/defaults write $organizationDefaultsDomain checkExtended -string ""
        fi

    else
            /usr/bin/defaults write $organizationDefaultsDomain checkStatus -string "Not Installed"
            /usr/bin/defaults write $organizationDefaultsDomain checkType -string "fail"
            /usr/bin/defaults write $organizationDefaultsDomain checkExtended -string ""
    fi
    
    echo "<result>$(/usr/bin/defaults read $organizationDefaultsDomain checkStatus)</result>"
