#!/bin/bash

#####################################################################################
#
# Sophos Endpoint Validation
# for
# Mac Health Check
#
####################################################################################
#
# HISTORY
#
#   Version 0.0.1, 14-Dec-2022, Dan K. Snelson (@dan-snelson)
#   - Original Version
#
#   Version 0.0.2, 04-Oct-2026, Dan K. Snelson (@dan-snelson)
#   - Disabled "Real Time Scanning > Files" now returns `Failed: Real Time Scanning Disabled`, which Mac Health Check
#     reports as a failure (previously `Disabled` matched no keyword and was reported as an error)
#
####################################################################################
# A script to collect the state of Sophos Endpoint's "Real Time Scanning > Files". #
# If Sophos Endpoint is not installed, "Not Installed" will be returned.           #
# If disabled, "Failed: Real Time Scanning Disabled" will be returned.            #
####################################################################################

RESULT="Not Installed"

if [[ -d /Applications/Sophos/Sophos\ Endpoint.app ]]; then
    if [[ -f /Library/Preferences/com.sophos.sav.plist ]]; then
        sophosOnAccessRunning=$( /usr/bin/defaults read /Library/Preferences/com.sophos.sav.plist OnAccessRunning )
        case ${sophosOnAccessRunning} in
            "0" ) RESULT="Failed: Real Time Scanning Disabled" ;;
            "1" ) RESULT="Running" ;;
             *  ) RESULT="Unknown" ;;
        esac
    else
        RESULT="Not Found"
    fi
fi

/bin/echo "<result>${RESULT}</result>"