#!/bin/bash

###########################################################################################
# A script to collect the status of Palo Alto GlobalProtect.                              #
# • If Palo Alto GlobalProtect is not installed, "Not Installed" will be returned.        #
# • If the local user is not logged-in, "${loggedInUser} not logged-in" will be returned. #
# • If no gateway is selected, "Best Available Gateway selected" will be returned.        #
###########################################################################################
#
# HISTORY
#
#   Version 0.0.1, 14-Dec-2022, Dan K. Snelson (@dan-snelson)
#   - Original Version
#
#   Version 0.0.2, 26-Aug-2025, Dan K. Snelson (@dan-snelson)
#   - Updated based on Mac Health Check (2.3.0)
#
###########################################################################################

loggedInUser=$( /bin/echo "show State:/Users/ConsoleUser" | /usr/sbin/scutil | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }' )
vpnAppPath="/Applications/GlobalProtect.app"
vpnStatus="GlobalProtect is NOT installed"

if [[ -d "${vpnAppPath}" ]]; then
    vpnStatus="Running: Installed"
    if [[ $(find /var/db/.AppleSetupDone -mmin +60) ]]; then
        globalProtectTunnelStatus=$( /usr/libexec/PlistBuddy -c "Print :'Palo Alto Networks':GlobalProtect:DEM:'tunnel-status'" /Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist )
        case "$globalProtectTunnelStatus" in
            "connected"* | "internal" )
                globalProtectVpnIP=$( /usr/libexec/PlistBuddy -c 'Print :"Palo Alto Networks":GlobalProtect:DEM:"tunnel-ip"' /Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist 2>/dev/null | sed -nE 's/.*ipv4=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*/\1/p' )
                vpnStatus="Running: ${globalProtectVpnIP}; "
                globalProtectUserResult=$( defaults read /Users/"${loggedInUser}"/Library/Preferences/com.paloaltonetworks.GlobalProtect.client User 2>&1 )
                if [[ "${globalProtectUserResult}"  == *"Does Not Exist" || -z "${globalProtectUserResult}" ]]; then
                    globalProtectUserResult="${loggedInUser} NOT logged-in"
                elif [[ ! -z "${globalProtectUserResult}" ]]; then
                    globalProtectUserResult="\"${loggedInUser}\" logged-in"
                fi
                ;;
            "disconnected" )
                vpnStatus="Failed: Disconnected"
                ;;
            *)
                vpnStatus="Error: Unknown"
                ;;
        esac
    fi
fi

/bin/echo "<result>${vpnStatus}${globalProtectUserResult}</result>"

exit 0