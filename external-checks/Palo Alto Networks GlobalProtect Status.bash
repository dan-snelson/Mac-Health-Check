#!/bin/bash

###########################################################################################
# A script to collect the status of Palo Alto GlobalProtect.                              #
# • If Palo Alto GlobalProtect is not installed, "Failed: ... NOT installed" is returned. #
# • If GlobalProtect is connected, "Running: Connected ..." is returned.                  #
# • If GlobalProtect is internal, "Running: Internal ..." is returned.                    #
# • If GlobalProtect is disconnected, "Warning: Disconnected" is returned.                #
# • If GlobalProtect status cannot be determined, "Error: Unknown" is returned.           #
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
#   Version 0.0.3, 14-Jul-2026, Dan K. Snelson (@dan-snelson)
#   - Updated based on Mac Health Check (4.0.0) [inspired by @kgolden-code’s PR #88]
#   - Added safe plist reads, connected-non-pa support and normalized external-check output
#   - Report disconnected VPN as a warning instead of a failure
#
###########################################################################################

export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin/

function readPlistValue() {
    local plistPath="${1}"
    local plistKey="${2}"

    /usr/libexec/PlistBuddy -c "Print ${plistKey}" "${plistPath}" 2>/dev/null
}

function getGlobalProtectUserStatus() {
    local globalProtectUserResult

    if [[ -z "${loggedInUser}" ]]; then
        echo "No console user"
        return
    fi

    globalProtectUserResult=$( defaults read "/Users/${loggedInUser}/Library/Preferences/com.paloaltonetworks.GlobalProtect.client" User 2>/dev/null )

    if [[ -z "${globalProtectUserResult}" ]]; then
        echo "${loggedInUser} NOT logged-in"
    else
        echo "\"${loggedInUser}\" logged-in"
    fi
}

loggedInUser=$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ && ! /loginwindow/ { print $3 }' )
vpnAppPath="/Applications/GlobalProtect.app"
globalProtectSettingsPlist="/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist"
vpnStatus="Failed: GlobalProtect is NOT installed"

if [[ -d "${vpnAppPath}" ]]; then
    vpnStatus="Running: Installed"

    if [[ -e "/var/db/.AppleSetupDone" ]] && [[ -n $( find /var/db/.AppleSetupDone -mmin +60 2>/dev/null ) ]]; then
        globalProtectTunnelStatus=$( readPlistValue "${globalProtectSettingsPlist}" ":'Palo Alto Networks':GlobalProtect:DEM:'tunnel-status'" )

        case "${globalProtectTunnelStatus}" in
            "connected" | "connected-non-pa" )
                globalProtectVpnIP=$( readPlistValue "${globalProtectSettingsPlist}" ':"Palo Alto Networks":GlobalProtect:DEM:"tunnel-ip"' | sed -nE 's/.*ipv4=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*/\1/p' )
                globalProtectUserResult=$( getGlobalProtectUserStatus )
                vpnStatus="Running: Connected ${globalProtectVpnIP:-<no-IP>}; ${globalProtectUserResult}"
                ;;
            "internal" )
                globalProtectUserResult=$( getGlobalProtectUserStatus )
                vpnStatus="Running: Internal; ${globalProtectUserResult}"
                ;;
            "disconnected" )
                vpnStatus="Warning: Disconnected"
                ;;
            *)
                vpnStatus="Error: Unknown"
                ;;
        esac
    fi
fi

echo "${vpnStatus}"

exit 0
