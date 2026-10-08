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
#   Version 0.0.4, 30-Sep-2026, Dan K. Snelson (@dan-snelson)
#   - Removed `/usr/local/bin` from `PATH` (Monocle S3)
#
#   Version 0.0.5, 08-Oct-2026, Dan K. Snelson (@dan-snelson)
#   - Updated based on Mac Health Check (5.0.1b1)
#   - Detect live tunnel interface IPv4 before trusting DEM keys, which can report "disconnected" while connected
#
###########################################################################################

export PATH=/usr/bin:/bin:/usr/sbin:/sbin

function readPlistValue() {
    local plistPath="${1}"
    local plistKey="${2}"

    /usr/libexec/PlistBuddy -c "Print ${plistKey}" "${plistPath}" 2>/dev/null
}

function getDemTunnelIPv4() {
    # DEM tunnel-ip is stored as "ipv4=<address>,ipv6=<address>"; print IPv4 only
    readPlistValue "${globalProtectSettingsPlist}" ':"Palo Alto Networks":GlobalProtect:DEM:"tunnel-ip"' | sed -nE 's/.*ipv4=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*/\1/p'
}

function getPreferredIPv4List() {
    # PanGPS keeps per-portal "PreferredIP_<hash>" values; pattern excludes "PreferredIPV6_<hash>" keys
    readPlistValue "${globalProtectSettingsPlist}" ":'Palo Alto Networks':GlobalProtect:PanGPS" | awk '$1 ~ /^PreferredIP_/ && $3 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $3 }'
}

function getTunnelInterfaceIPv4List() {
    # IPv4 addresses bound to tunnel interfaces (utun* for current clients; gpd* for legacy kext)
    ifconfig 2>/dev/null | awk '
        /^[^[:space:]]/ { interface = $1; sub(/:$/, "", interface) }
        interface ~ /^(utun|gpd)[0-9]+$/ && $1 == "inet" { print $2 }
    '
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
        globalProtectDemTunnelIPv4=$( getDemTunnelIPv4 )
        globalProtectKnownIPv4List=$( { echo "${globalProtectDemTunnelIPv4}"; getPreferredIPv4List; } | sed '/^$/d' )
        globalProtectTunnelIPv4List=$( getTunnelInterfaceIPv4List )
        globalProtectTunnelIPv4Count=$( printf '%s\n' "${globalProtectTunnelIPv4List}" | grep -c . )
        globalProtectVpnIP=""

        # Live tunnel IPv4 matching a known GlobalProtect address wins, regardless of (possibly stale) DEM status
        for globalProtectTunnelIPv4 in ${globalProtectTunnelIPv4List}; do
            if printf '%s\n' "${globalProtectKnownIPv4List}" | grep -Fxq "${globalProtectTunnelIPv4}"; then
                globalProtectVpnIP="${globalProtectTunnelIPv4}"
                break
            fi
        done

        # Gateway may assign an address outside the known list; accept only an unambiguous single tunnel
        if [[ -z "${globalProtectVpnIP}" ]] && [[ "${globalProtectTunnelIPv4Count}" -eq 1 ]] && pgrep -x PanGPS >/dev/null 2>&1; then
            globalProtectVpnIP="${globalProtectTunnelIPv4List}"
        fi

        if [[ -n "${globalProtectVpnIP}" ]]; then
            globalProtectUserResult=$( getGlobalProtectUserStatus )
            vpnStatus="Running: Connected ${globalProtectVpnIP}; ${globalProtectUserResult}"
        else
            # Fall back to DEM status
            globalProtectTunnelStatus=$( readPlistValue "${globalProtectSettingsPlist}" ":'Palo Alto Networks':GlobalProtect:DEM:'tunnel-status'" )

            case "${globalProtectTunnelStatus}" in
                "connected"* )
                    globalProtectUserResult=$( getGlobalProtectUserStatus )
                    vpnStatus="Running: Connected ${globalProtectDemTunnelIPv4:-<no-IP>}; ${globalProtectUserResult}"
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
fi

echo "${vpnStatus}"

exit 0
