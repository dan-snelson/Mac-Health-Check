#!/bin/zsh --no-rcs
# shellcheck shell=bash

####################################################################################################
#
# Mac Health Check
#
# A practical and user-friendly approach to surfacing Mac compliance information directly to end-users
# via your MDM's Self Service portal.
#
# https://snelson.us/mhc
#
# Inspired by:
#   - @talkingmoose and @robjschroeder
#
####################################################################################################
#
# HISTORY
#
# Version 3.0.0rc4, 21-Jan-2026, Dan K. Snelson (@dan-snelson)
#   - First (attempt at a) MDM-agnostic release
#   - Added a new "Development" Operation Mode to aid in developing / testing individual Health Checks
#   - Minor update to host check curl logic (Pull Request #60; thanks, @ecubrooks!)
#   - Refactored "Palo Alto Networks GlobalProtect VPN Information" (in an _attempt_ to address Issue #61; thanks, @RussCollis)
#   - Refactored "checkElectronCornerMask" to display the list o' apps as the "listitem" "subtitle" (and removed dedicated "Electron Corner Mask" reporting)
#   - Refactored many other functions, adding instructive "listitem" "subtitle" self-remedidation instructions
#   - Refactored AirPlay Receiver logic (Pull Request #66; thanks for another one, @bigdoodr!)
#   - Update System Memory and System Storage sidebar calculations (Pull Request #68 to address Issue #69; thanks, @HowardGMac and @mallej!)
#   - Added `mdmProfileIdentifier` to `checkMdmProfile` function (Pull Request #70; thanks for yet another one, @bigdoodr!)
#   - Added detection for staged macOS updates (from [DDM-OS-Reminder](https://github.com/dan-snelson/DDM-OS-Reminder))
#   - Updated check for App Auto-Patch to support version 3.5.0
#   - Force locale to English for date command (Pull Request #72; thanks, @aedekuiper!)
#   - Added "-endUsername" to the Jamf Pro-specific `updateComputerInventory` function
#   - Updated comment to reference MDM's Self Service portal (Pull Request #75; thanks, @nikeshashar!)
#   - Added retry logic with file existence verification for `dialogJSONFile` and `dialogCommandFile` to address race condition errors (Issue #73; thanks for the heads-up, @sabanessts!)
#
####################################################################################################



####################################################################################################
#
# Global Variables
#
####################################################################################################

export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin/

# Script Version
scriptVersion="3.0.0rc4"

# Client-side Log
scriptLog="/var/log/org.churchofjesuschrist.log"

# Load is-at-least for version comparison
autoload -Uz is-at-least

# Minimum Required Version of swiftDialog
swiftDialogMinimumRequiredVersion="2.5.6.4805"

# Force locale to English (so `date` does not error on localization formatting)
LANG="en_us_88591"

# Elapsed Time
SECONDS="0"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Script Paramters
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Parameter 4: Operation Mode [ Debug | Development | Self Service | Silent | Test ]
operationMode="${4:-"Self Service"}"

    # Enable `set -x` if operation mode is "Debug" to help identify issues
    [[ "${operationMode}" == "Debug" ]] && set -x

# Parameter 5: Microsoft Teams or Slack Webhook URL [ Leave blank to disable (default) | https://microsoftTeams.webhook.com/URL | https://hooks.slack.com/services/URL ]
webhookURL="${5:-""}"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Organization Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Script Human-readable Name
humanReadableScriptName="Mac Health Check"

# Organization's Script Name
organizationScriptName="MHC"

# Organization's Self Service Marketing Name 
organizationSelfServiceMarketingName="Workforce App Store"

# Organization's Boilerplate Compliance Message 
organizationBoilerplateComplianceMessage="Meets organizational standards"

# Organization's Branding Banner URL
organizationBrandingBannerURL="https://img.freepik.com/free-photo/abstract-textured-backgound_1258-30469.jpg" # [Image by benzoix on Freepik](https://www.freepik.com/author/benzoix)

# Organization's Overlayicon URL
organizationOverlayiconURL=""

# Organization's Defaults Domain for External Checks
organizationDefaultsDomain="org.churchofjesuschrist.external"

# Organization's Color Scheme
if [[ $( defaults read /Users/$(stat -f %Su /dev/console)/Library/Preferences/.GlobalPreferences.plist AppleInterfaceStyle 2>/dev/null ) == "Dark" ]]; then
    # Dark Mode
    organizationColorScheme="weight=semibold,colour1=#2E5B91,colour2=#4291C8"
else
    # Light Mode
    organizationColorScheme="weight=semibold,colour1=#2E5B91,colour2=#4291C8"
fi

# Organization's Kerberos Realm (leave blank to disable check)
kerberosRealm=""

# Organization's Firewall Type [ socketfilterfw | pf ]
organizationFirewall="socketfilterfw"

# Organization's VPN client type [ none | paloalto | cisco | tailscale ]
vpnClientVendor="paloalto"

# Organization's VPN data type [ basic | extended ]
vpnClientDataType="extended"

# "Anticipation" Duration (in seconds)
if [[ "${operationMode}" == "Silent" ]]; then
    anticipationDuration="0"
else
    anticipationDuration="2"
fi

# How many previous minor OS versions will be marked as compliant
previousMinorOS="2"

# Allowed minimum percentage of free disk space
allowedMinimumFreeDiskPercentage="10"

# Allowed maximum percentage of disk space for user directories (i.e., Desktop, Downloads, Trash)
allowedMaximumDirectoryPercentage="5"

# Network Quality Test Maximum Age
# Leverages `date -v-`; One of either y, m, w, d, H, M or S
# must be used to specify which part of the date is to be adjusted
networkQualityTestMaximumAge="1H"

# Allowed number of uptime minutes
# - 1 day = 24 hours × 60 minutes/hour = 1,440 minutes
# - 7 days, multiply: 7 × 1,440 minutes = 10,080 minutes
allowedUptimeMinutes="10080"

# Should excessive uptime result in a "warning" or "error" ?
excessiveUptimeAlertStyle="warning"

# Completion Timer (in seconds)
completionTimer="60"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# MDM vendor (thanks, @TechTrekkie!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ -n "$(profiles list -output stdout-xml | awk '/com.apple.mdm/ {print $1}' | tail -1)" ]]; then
    serverURL=$( profiles list -output stdout-xml | grep -a1 'ServerURL' | sed -n 's/.*<string>\(https:\/\/[^\/]*\).*/\1/p' )
    if [[ -n "$serverURL" ]]; then
        # echo "MDM server address: $serverURL"
    else
        echo "Failed to get MDM URL"
    fi
else
    echo "Not enrolled in an MDM server."
fi

# Vendor's MDM Profile UUID
# You can find this out by using: `sudo profiles show enrollment | grep -A3 -B3 com.apple.mdm`
# Or
# Vendor's MDM Profile Identifier (alternative to UUID for MDMs like Mosyle)
# Find with: `sudo profiles show enrollment | grep "profileIdentifier:"`

case "${serverURL}" in

    *addigy* )
        mdmVendor="Addigy"
        mdmVendorUuid=""
        ;;

    *filewave* )
        mdmVendor="Filewave"
        mdmProfileIdentifier="com.filewave.profile"
        ;;

    *fleet* )
        mdmVendor="Fleet"
        mdmVendorUuid="BCA53F9D-5DD2-494D-98D3-0D0F20FF6BA1"
        ;;

    *jamf* | *jss* )
        mdmVendor="Jamf Pro"
        mdmVendorUuid="00000000-0000-0000-A000-4A414D460004"
        [[ -f "/private/var/log/jamf.log" ]] || { echo "jamf.log missing; exiting."; exit 1; }
        ;;

    *jumpcloud* )
        mdmVendor="JumpCloud"
        mdmProfileIdentifier="com.jumpcloud.mdm.enroll"
        ;;

    *kandji* )
        mdmVendor="Kandji"
        mdmProfileIdentifier="io.kandji.mdm.profile"
        ;;
    
    *microsoft* )
        mdmVendor="Microsoft Intune"
        mdmVendorUuid="67A5265B-12D4-4EB5-A2B3-72C683E33BCF"
        ;;

    *mosyle* )
        mdmVendor="Mosyle"
        mdmProfileIdentifier="com.mosyle.macos.config" 
        ;;

    * )
        mdmVendor="None"
        echo "Unable to determine MDM from ServerURL"
        ;;

esac



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Configuration Profile Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

case ${mdmVendor} in

    "Jamf Pro" )

        # Organization's Client-side Jamf Pro Variables
        jamfProVariables="org.churchofjesuschrist.jamfprovariables.plist"

        # Property List File
        plistFilepath="/Library/Managed Preferences/${jamfProVariables}"

        if [[ -e "${plistFilepath}" ]]; then
            jamfProID=$( defaults read "${plistFilepath}" "Jamf Pro ID" 2>/dev/null )
            jamfProSiteName=$( defaults read "${plistFilepath}" "Site Name" 2>/dev/null )
        fi
        ;;

esac



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Computer Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

osVersion=$( sw_vers -productVersion )
osVersionExtra=$( sw_vers -productVersionExtra ) 
osBuild=$( sw_vers -buildVersion )
osMajorVersion=$( echo "${osVersion}" | awk -F '.' '{print $1}' )
osMinorVersion=$( echo "${osVersion}" | awk -F '.' '{print $2}' )
if [[ -n $osVersionExtra ]] && [[ "${osMajorVersion}" -ge 13 ]]; then osVersion="${osVersion} ${osVersionExtra}"; fi
serialNumber=$( ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}' )
computerName=$( scutil --get ComputerName | sed 's/’//' )
computerModel=$( sysctl -n hw.model )
localHostName=$( scutil --get LocalHostName )
systemMemory="$(( $(sysctl -n hw.memsize) / $((1024**3)) )) GB"
rawStorage=$(( $(/usr/sbin/diskutil info / | grep "Container Total Space" | awk '{print $6}' | sed 's/(//g') / $((1000**3)) ))
if [[ $rawStorage -ge 1998 ]]; then
    systemStorage=$(diskutil info / | grep "Container Total Space" | awk '{print $4" "$5}')
elif [[ $rawStorage -ge 994 ]]; then
    systemStorage="$(echo "scale=0; ( ( ($rawStorage +999) /1000 * 1000)/1000)" | bc) TB"
elif [[ $rawStorage -lt 300 ]]; then
    systemStorage="$(echo "scale=0; ( ($rawStorage +9) /10 * 10)" | bc) GB"
else
    systemStorage="$(echo "scale=0; ( ($rawStorage +99) /100 * 100)" | bc) GB"
fi
totalDiskBytes=$( diskutil info / | grep "Container Total Space" | sed -E 's/.*\(([0-9]+) Bytes\).*/\1/' )
if [[ -z "${totalDiskBytes}" || "${totalDiskBytes}" == "0" ]]; then
    totalDiskBytes=$( echo "${rawStorage} * 1000000000" | bc 2>/dev/null || echo "0" )
fi
batteryCycleCount=$( ioreg -r -c "AppleSmartBattery" | grep '"CycleCount" = ' | awk '{ print $3 }' | sed s/\"//g )
activationLockStatus=$( system_profiler SPHardwareDataType | awk '/Activation Lock Status/{print $NF}' )
bootstrapTokenStatus=$( profiles status -type bootstraptoken | awk '{sub(/^profiles: /, ""); printf "%s", $0; if (NR < 2) printf "; "}' | sed 's/; $//' )
sshStatus=$( systemsetup -getremotelogin | awk -F ": " '{ print $2 }' )
networkTimeServer=$( systemsetup -getnetworktimeserver )
locationServices=$( defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled )
locationServicesStatus=$( [ "${locationServices}" = "1" ] && echo "Enabled" || echo "Disabled" )
sudoStatus=$( visudo -c )
sudoAllLines=$( awk '/\(ALL\)/' /etc/sudoers | tr '\t\n#' ' ' )



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# SSID (thanks, ZP!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

wirelessInterface=$( networksetup -listnetworkserviceorder | sed -En 's/^\(Hardware Port: (Wi-Fi|AirPort), Device: (en.)\)$/\2/p' )
ipconfig setverbose 1
ssid=$( ipconfig getsummary "${wirelessInterface}" | awk -F ' SSID : ' '/ SSID : / {print $2}')
ipconfig setverbose 0
[[ -z "${ssid}" ]] && ssid="Not connected"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Boot Policies
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

bootPoliciesRaw=$( bputil --display-policy )
extractBootPoliciesStatus() {
  local key="$1"
  printf '%s\n' "$bootPoliciesRaw" |
  grep -E "^[ ]*$key:" |
  awk -F: '{gsub(/^[ \t]+|[ \t]+$/, "", $2); split($2,a,"  "); print a[1]}'
}
bootPoliciesSecurityMode=$(extractBootPoliciesStatus "Security Mode") # See: quitScript function
bootPoliciesDepAllowedMdmControl=$(extractBootPoliciesStatus "DEP-allowed MDM Control") # See: quitScript function
bootPoliciesSipStatus=$(extractBootPoliciesStatus "SIP Status") # See: checkSIP function
bootPoliciesSsvStatus=$(extractBootPoliciesStatus "Signed System Volume Status") # See: checkSSV function



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Logged-in User Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

loggedInUser=$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ { print $3 }' )
loggedInUserFullname=$( id -F "${loggedInUser}" )
loggedInUserFirstname=$( echo "$loggedInUserFullname" | sed -E 's/^.*, // ; s/([^ ]*).*/\1/' | sed 's/\(.\{25\}\).*/\1…/' | awk '{print ( $0 == toupper($0) ? toupper(substr($0,1,1))substr(tolower($0),2) : toupper(substr($0,1,1))substr($0,2) )}' )
loggedInUserID=$( id -u "${loggedInUser}" )
loggedInUserGroupMembership=$( id -Gn "${loggedInUser}" )
if [[ ${loggedInUserGroupMembership} == *"admin"* ]]; then localAdminWarning="WARNING: '$loggedInUser' IS A MEMBER OF 'admin'; "; fi
loggedInUserHomeDirectory=$( dscl . read "/Users/${loggedInUser}" NFSHomeDirectory | awk -F ' ' '{print $2}' )

# Secure Token Status
secureTokenStatus=$( sysadminctl -secureTokenStatus ${loggedInUser} 2>&1 )
case "${secureTokenStatus}" in
    *"ENABLED"*)    secureToken="Enabled"   ;;
    *"DISABLED"*)   secureToken="Disabled"  ;;
    *)              secureToken="Unknown"   ;;
esac

# Kerberos Single Sign-on Extension
if [[ -n "${kerberosRealm}" ]]; then
    su \- "${loggedInUser}" -c "app-sso -i ${kerberosRealm}" > /var/tmp/app-sso.plist
    ssoLoginTest=$( /usr/libexec/PlistBuddy -c "Print:login_date" /var/tmp/app-sso.plist 2>&1 )
    if [[ ${ssoLoginTest} == *"Does Not Exist"* ]]; then
        kerberosSSOeResult="${loggedInUser} NOT logged in"
    else
        username=$( /usr/libexec/PlistBuddy -c "Print:upn" /var/tmp/app-sso.plist | awk -F@ '{print $1}' )
        kerberosSSOeResult="${username}"
    fi
    rm -f /var/tmp/app-sso.plist
fi

# Platform Single Sign-on Extension
pssoeEmail=$( dscl . read /Users/"${loggedInUser}" dsAttrTypeStandard:AltSecurityIdentities 2>/dev/null | awk -F'SSO:' '/PlatformSSO/ {print $2}' )
if [[ -n "${pssoeEmail}" ]]; then
    platformSSOeResult="${pssoeEmail}"
else
    platformSSOeResult="${loggedInUser} NOT logged in"
fi

# Last modified time of user's Microsoft OneDrive sync file (thanks, @pbowden-msft!)
if [[ -d "${loggedInUserHomeDirectory}/Library/Application Support/OneDrive/settings/Business1/" ]]; then
    DataFile=$( ls -t "${loggedInUserHomeDirectory}"/Library/Application\ Support/OneDrive/settings/Business1/*.ini | head -n 1 )
    EpochTime=$( stat -f %m "$DataFile" )
    UTCDate=$( date -u -r $EpochTime '+%d-%b-%Y' )
    oneDriveSyncDate="${UTCDate}"
else
    oneDriveSyncDate="Not Configured"
fi

# Time Machine Backup Date
tmDestinationInfo=$( tmutil destinationinfo 2>/dev/null )
if [[ "${tmDestinationInfo}" == *"No destinations configured"* ]]; then
    tmStatus="Not configured"
    tmLastBackup=""
else
    tmDestinations=$( tmutil destinationinfo 2>/dev/null | grep "Name" | awk -F ':' '{print $NF}' | awk '{$1=$1};1')
    tmStatus="${tmDestinations//$'\n'/, }"

    tmBackupDates=$( tmutil latestbackup  2>/dev/null | awk -F "/" '{print $NF}' | cut -d'.' -f1 )
    if [[ -z $tmBackupDates ]]; then
        tmLastBackup="Last backup date(s) unknown; connect destination(s)"
    else
        tmLastBackup="; Date(s): ${tmBackupDates//$'\n'/, }"
    fi
fi



####################################################################################################
#
# Networking Variables
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Active IP Address
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

networkServices=$( networksetup -listallnetworkservices | grep -v asterisk )

while IFS= read -r aService; do
    activePort=$( networksetup -getinfo "$aService" | grep "IP address" | grep -v "IPv6" )
    activePort=${activePort/IP address: /}
    if [ "$activePort" != "" ] && [ "$activeServices" != "" ]; then
        activeServices="$activeServices\n**$aService IP:** $activePort"
    elif [ "$activePort" != "" ] && [ "$activeServices" = "" ]; then
        activeServices="**$aService IP:** $activePort"
    fi
done <<< "$networkServices"

activeIPAddress=$( echo "$activeServices" | sed '/^$/d' | head -n 1 )



####################################################################################################
#
# VPN Client Information
#
####################################################################################################

if [[ "${vpnClientVendor}" == "none" ]]; then
    vpnStatus="None"
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Palo Alto Networks GlobalProtect VPN Information
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${vpnClientVendor}" == "paloalto" ]]; then
    vpnAppName="GlobalProtect VPN Client"
    vpnAppPath="/Applications/GlobalProtect.app"
    vpnStatus="GlobalProtect is NOT installed"

    if [[ -d "${vpnAppPath}" ]]; then
        vpnStatus="GlobalProtect is Idle"

        # Safely read the plist key; suppress "Does Not Exist" noise
        globalProtectTunnelStatus=$(
            /usr/libexec/PlistBuddy -c \
                "Print :'Palo Alto Networks':GlobalProtect:DEM:'tunnel-status'" \
                /Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist 2>/dev/null
        )

        case "${globalProtectTunnelStatus}" in
            "connected"*|"internal"|"connected-non-pa")
                # Extract the IPv4 tunnel address if available
                globalProtectVpnIP=$(
                    /usr/libexec/PlistBuddy -c \
                        'Print :"Palo Alto Networks":GlobalProtect:DEM:"tunnel-ip"' \
                        /Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist 2>/dev/null \
                    | sed -nE 's/.*ipv4=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*/\1/p'
                )
                vpnStatus="Connected ${globalProtectVpnIP:-<no-IP>}"

                if [[ "${vpnClientDataType}" == "extended" ]]; then
                    globalProtectUserResult=$(
                        defaults read "/Users/${loggedInUser}/Library/Preferences/com.paloaltonetworks.GlobalProtect.client" User 2>&1
                    )

                    case "${globalProtectUserResult}" in
                        *"Does Not Exist"*|"")
                            globalProtectUserResult="${loggedInUser} NOT logged-in"
                            ;;
                        *)
                            globalProtectUserResult="\"${loggedInUser}\" logged-in"
                            ;;
                    esac

                    vpnExtendedStatus="${globalProtectUserResult}"
                fi
                ;;
            "disconnected")
                vpnStatus="Disconnected"
                ;;
            *)
                vpnStatus="Unknown"
                ;;
        esac
    fi
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Cisco VPN Information
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${vpnClientVendor}" == "cisco" ]]; then
    vpnAppName="Cisco VPN Client"
    vpnAppPath="/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app"
    vpnStatus="Cisco VPN is NOT installed"
    if [[ -d "${vpnAppPath}" ]]; then
        ciscoVPNStats=$(/opt/cisco/anyconnect/bin/vpn -s stats)
    elif [[ -d "/Applications/Cisco/Cisco Secure Client.app" ]]; then
        vpnAppPath="/Applications/Cisco/Cisco Secure Client.app"
        ciscoVPNStats=$(/opt/cisco/secureclient/bin/vpn -s stats)
    fi
    if [[ -n $ciscoVPNStats ]]; then
        ciscoVPNStatus=$(echo "${ciscoVPNStats}" | grep -m1 'Connection State:' | awk '{print $3}')
        ciscoVPNIP=$(echo "${ciscoVPNStats}" | grep -m1 'Client Address' | awk '{print $4}')
        if [[ "${ciscoVPNStatus}" == "Connected" ]]; then
            vpnStatus="${ciscoVPNIP}"
        else
            vpnStatus="Cisco VPN is Idle"
        fi
        if [[ "${vpnClientDataType}" == "extended" ]] && [[ "${ciscoVPNStatus}" == "Connected" ]]; then
            ciscoVPNServer=$(echo "${ciscoVPNStats}" | grep -m1 'Server Address:' | awk '{print $3}')
            ciscoVPNDuration=$(echo "${ciscoVPNStats}" | grep -m1 'Duration:' | awk '{print $2}')
            ciscoVPNSessionDisconnect=$(echo "${ciscoVPNStats}" | grep -m1 'Session Disconnect:' | awk '{print $3, $4, $5, $6, $7}')
            vpnExtendedStatus="VPN Server Address: ${ciscoVPNServer} VPN Connection Duration: ${ciscoVPNDuration} VPN Session Disconnect: $ciscoVPNSessionDisconnect"
        fi
    fi
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Tailscale VPN Information
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${vpnClientVendor}" == "tailscale" ]]; then
    vpnAppName="Tailscale VPN Client"
    vpnAppPath="/Applications/Tailscale.app"
    vpnStatus="Tailscale is NOT installed"
    if [[ -d "${vpnAppPath}" ]]; then
        vpnStatus="Tailscale is Idle"
        if command -v tailscale >/dev/null 2>&1; then
            tailscaleCLI="tailscale"
        elif [[ -f "/Applications/Tailscale.app/Contents/MacOS/Tailscale" ]]; then
            tailscaleCLI="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
        else
            tailscaleCLI=""
        fi
        if [[ -n "${tailscaleCLI}" ]]; then
            tailscaleStatusOutput=$("${tailscaleCLI}" status --json 2>/dev/null)
            if [[ $? -eq 0 ]] && [[ -n "${tailscaleStatusOutput}" ]]; then
                tailscaleBackendState=$(echo "${tailscaleStatusOutput}" | grep -o '"BackendState":"[^"]*' | cut -d'"' -f4)
                tailscaleIP=$(echo "${tailscaleStatusOutput}" | grep -o '"TailscaleIPs":\["[^"]*' | cut -d'"' -f4)
                case "${tailscaleBackendState}" in
                    "Running" ) 
                        if [[ -n "${tailscaleIP}" ]]; then
                            vpnStatus="${tailscaleIP}"
                        else
                            vpnStatus="Tailscale Connected (No IP)"
                        fi
                        ;;
                    "Stopped" ) vpnStatus="Tailscale is Stopped" ;;
                    "Starting" ) vpnStatus="Tailscale is Starting" ;;
                    "NeedsLogin" ) vpnStatus="Tailscale Needs Login" ;;
                    * ) vpnStatus="Tailscale Status Unknown" ;;
                esac
            else
                if pgrep -x "tailscaled" > /dev/null; then
                    vpnStatus="Tailscale Running (Status Unknown)"
                else
                    vpnStatus="Tailscale is Idle"
                fi
            fi
        fi
    fi
    if [[ "${vpnClientDataType}" == "extended" ]] && [[ "${tailscaleBackendState}" == "Running" ]]; then
        if [[ -n "${tailscaleCLI}" ]]; then
            tailscaleCurrentUser=$(echo "${tailscaleStatusOutput}" | grep -o '"CurrentTailnet":{"Name":"[^"]*' | cut -d'"' -f6)
            tailscaleHostname=$(echo "${tailscaleStatusOutput}" | grep -o '"Self":{"ID":"[^"]*","PublicKey":"[^"]*","HostName":"[^"]*' | cut -d'"' -f8)
            tailscaleExitNode=$(echo "${tailscaleStatusOutput}" | grep -o '"ExitNodeStatus":{"ID":"[^"]*' | cut -d'"' -f4)
            vpnExtendedStatus=""
            if [[ -n "${tailscaleCurrentUser}" ]]; then
                vpnExtendedStatus="${vpnExtendedStatus}Tailnet: ${tailscaleCurrentUser}; "
            fi
            if [[ -n "${tailscaleHostname}" ]]; then
                vpnExtendedStatus="${vpnExtendedStatus}Hostname: ${tailscaleHostname}; "
            fi
            if [[ -n "${tailscaleExitNode}" ]] && [[ "${tailscaleExitNode}" != "null" ]]; then
                vpnExtendedStatus="${vpnExtendedStatus}Using Exit Node; "
            else
                vpnExtendedStatus="${vpnExtendedStatus}Direct Connection; "
            fi
            tailscalePeerCount=$(echo "${tailscaleStatusOutput}" | grep -c '"Online":true')
            if [[ -n "${tailscalePeerCount}" ]] && [[ "${tailscalePeerCount}" -gt 0 ]]; then
                vpnExtendedStatus="${vpnExtendedStatus}Connected Peers: ${tailscalePeerCount}; "
            fi
        fi
    fi
fi



####################################################################################################
#
# swiftDialog Variables
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Dialog binary
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# swiftDialog Binary Path
dialogBinary="/usr/local/bin/dialog"

# Enable debugging options for swiftDialog
[[ "${operationMode}" == "Debug" ]] && dialogBinary="${dialogBinary} --verbose --resizable --debug red"

# swiftDialog JSON File
dialogJSONFile=$( mktemp -u /var/tmp/dialogJSONFile_${organizationScriptName}.XXXX )

# swiftDialog Command File
dialogCommandFile=$( mktemp /var/tmp/dialogCommandFile_${organizationScriptName}.XXXX )

# Set Permissions on Dialog Command Files
chmod 644 "${dialogCommandFile}"

# Verify dialogCommandFile exists and is readable
retryCount=0
maxRetries=5
while [[ ! -f "${dialogCommandFile}" || ! -r "${dialogCommandFile}" ]] && [[ ${retryCount} -lt ${maxRetries} ]]; do
    sleep 0.2
    ((retryCount++))
done
if [[ ! -f "${dialogCommandFile}" || ! -r "${dialogCommandFile}" ]]; then
    echo "FATAL ERROR: dialogCommandFile (${dialogCommandFile}) is not readable after ${maxRetries} attempts"
    exit 1
fi

# The total number of steps for the progress bar (i.e., "progress: increment")
progressSteps="40"

# Set initial icon based on whether the Mac is a desktop or laptop
if system_profiler SPPowerDataType | grep -q "Battery Power"; then
    icon="SF=laptopcomputer.and.arrow.down,${organizationColorScheme}"
else
    icon="SF=desktopcomputer.and.arrow.down,${organizationColorScheme}"
fi

# Download the overlayicon from ${organizationOverlayiconURL}
if [[ -n "${organizationOverlayiconURL}" ]]; then
    # echo "Downloading overlayicon from '${organizationOverlayiconURL}' …"
    curl -o "/var/tmp/overlayicon.png" "${organizationOverlayiconURL}" --silent --show-error --fail
    if [[ "$?" -ne 0 ]]; then
        echo "Error: Failed to download the overlayicon from '${brandingImageURL}'."
        overlayicon="/System/Library/CoreServices/Apple Diagnostics.app"
    else
        overlayicon="/var/tmp/overlayicon.png"
    fi
else
    overlayicon="/System/Library/CoreServices/Apple Diagnostics.app"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# IT Support Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

supportTeamName="IT Support"
supportTeamPhone="+1 (801) 555-1212"
supportTeamEmail="rescue@domain.org"
supportTeamWebsite="https://support.domain.org"
supportTeamHyperlink="[${supportTeamWebsite}](${supportTeamWebsite})"
supportKB="KB8675309"
infobuttonaction="https://servicenow.domain.org/support?id=kb_article_view&sysparm_article=${supportKB}"
supportKBURL="[${supportKB}](${infobuttonaction})"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Help Message Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

helpmessage="For assistance, please contact: **${supportTeamName}**<br>- **Telephone:** ${supportTeamPhone}<br>- **Email:** ${supportTeamEmail}<br>- **Website:** ${supportTeamWebsite}<br>- **Knowledge Base Article:** ${supportKBURL}<br><br>**User Information:**<br>- **Full Name:** ${loggedInUserFullname}<br>- **User Name:** ${loggedInUser}<br>- **User ID:** ${loggedInUserID}<br>- **Secure Token:** ${secureToken}<br>- **Location Services:** ${locationServicesStatus}<br>- **Microsoft OneDrive Sync Date:** ${oneDriveSyncDate}<br>- **Platform SSOe:** ${platformSSOeResult}<br><br>**Computer Information:**<br>- **macOS:** ${osVersion} (${osBuild})<br>- **Dialog:** $(dialog -v)<br>- **Script:** ${scriptVersion}<br>- **Computer Name:** ${computerName}<br>- **Serial Number:** ${serialNumber}<br>- **Wi-Fi:** ${ssid}<br>- ${activeIPAddress}<br>- **VPN IP:** ${vpnStatus}"

case ${mdmVendor} in

    "Jamf Pro" )
        helpmessage+="<br><br>**Jamf Pro Information:**<br>- **Jamf Pro Computer ID:** ${jamfProID}<br>- **Site Name:** ${jamfProSiteName}"
        ;;

esac

helpimage="qr=${infobuttonaction}"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Main Dialog Window
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

mainDialogJSON='
{
    "commandfile" : "'"${dialogCommandFile}"'",
    "bannerimage" : "'"${organizationBrandingBannerURL}"'",
    "bannertext" : "'"${humanReadableScriptName} (${scriptVersion})"'",
    "title" : "'"${humanReadableScriptName} (${scriptVersion})"'",
    "titlefont" : "shadow=true, size=36, colour=#FFFDF4",
    "ontop" : true,
    "moveable" : true,
    "windowbuttons" : "min",
    "quitkey" : "k",
    "icon" : "'"${icon}"'",
    "overlayicon" : "'"${overlayicon}"'",
    "message" : "none",
    "iconsize" : "198",
    "infobox" : "**User:** '"{userfullname}"'<br><br>**Computer Model:** '"{computermodel}"'<br><br>**Serial Number:** '"{serialnumber}"'<br><br>**System Memory:** '"${systemMemory}"'<br><br>**System Storage:** '"${systemStorage}"' ",
    "infobuttontext" : "'"${supportKB}"'",
    "infobuttonaction" : "'"${infobuttonaction}"'",
    "button1text" : "Wait",
    "button1disabled" : "true",
    "helpmessage" : "'"${helpmessage}"'",
    "helpimage" : "'"${helpimage}"'",
    "position" : "center",
    "progress" :  "'"${progressSteps}"'",
    "progresstext" : "Please wait …",
    "height" : "750",
    "width" : "975",
    "messagefont" : "size=14"
}
'

# Validate mainDialogJSON is valid JSON
if ! echo "$mainDialogJSON" | jq . >/dev/null 2>&1; then
  echo "Error: mainDialogJSON is invalid JSON"
  echo "$mainDialogJSON"
  exit 1
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Addigy MDM List Items
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

addigyMdmListitemJSON='
[
    {"title" : "macOS Version", "subtitle" : "Organizational standards are the current and immediately previous versions of macOS", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Available Updates", "subtitle" : "Keep your Mac up-to-date to ensure its security and performance", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "App Auto-Patch", "subtitle" : "Keep your apps up-to-date to ensure their security and performance", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "System Integrity Protection", "subtitle" : "System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code.", "icon" : "SF=04.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Signed System Volume", "subtitle" : "Signed System Volume (SSV) ensures macOS is booted from a signed, cryptographically protected volume.", "icon" : "SF=05.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Firewall", "subtitle" : "The built-in macOS firewall helps protect your Mac from unauthorized access.", "icon" : "SF=06.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "FileVault Encryption", "subtitle" : "FileVault is built-in to macOS and provides full-disk encryption to help prevent unauthorized access to your Mac", "icon" : "SF=07.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Gatekeeper / XProtect", "subtitle" : "Prevents the execution of Apple-identified malware and adware.", "icon" : "SF=08.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Touch ID", "subtitle" : "Touch ID provides secure biometric authentication for unlock your Mac and authorize third-party apps.", "icon" : "SF=09.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=10.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=11.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Free Disk Space", "subtitle" : "Checks for the amount of free disk space on your Mac’s boot volume", "icon" : "SF=12.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Desktop Size and Item Count", "subtitle" : "Checks the size and item count of the Desktop", "icon" : "SF=13.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Downloads Size and Item Count", "subtitle" : "Checks the size and item count of the Downloads folder", "icon" : "SF=14.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Trash Size and Item Count", "subtitle" : "Checks the size and item count of the Trash", "icon" : "SF=15.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Password Hint", "subtitle" : "Ensure no password hint is set for better security", "icon" : "SF=16.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirPlay Receiver", "subtitle" : "Ensure AirPlay Receiver is disabled when not needed", "icon" : "SF=18.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=19.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Profile", "subtitle" : "The presence of the '${mdmVendor}' MDM profile helps ensure your Mac is enrolled", "icon" : "SF=20.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Certificate Expiration", "subtitle" : "Validate the expiration date of the '${mdmVendor}' MDM certificate", "icon" : "SF=21.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=22.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=23.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=24.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=25.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=26.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=27.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Microsoft Teams", "subtitle" : "The hub for teamwork in Microsoft 365.", "icon" : "SF=28.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'
# Validate addigyMdmListitemJSON is valid JSON
if ! echo "$addigyMdmListitemJSON" | jq . >/dev/null 2>&1; then
  echo "Error: addigyMdmListitemJSON is invalid JSON"
  echo "$addigyMdmListitemJSON"
  exit 1
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Filewave MDM List Items
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

filewaveMdmListitemJSON='
[
    {"title" : "macOS Version", "subtitle" : "Organizational standards are the current and immediately previous versions of macOS", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Available Updates", "subtitle" : "Keep your Mac up-to-date to ensure its security and performance", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "App Auto-Patch", "subtitle" : "Keep your apps up-to-date to ensure their security and performance", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "System Integrity Protection", "subtitle" : "System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code.", "icon" : "SF=04.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Signed System Volume", "subtitle" : "Signed System Volume (SSV) ensures macOS is booted from a signed, cryptographically protected volume.", "icon" : "SF=05.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Firewall", "subtitle" : "The built-in macOS firewall helps protect your Mac from unauthorized access.", "icon" : "SF=06.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "FileVault Encryption", "subtitle" : "FileVault is built-in to macOS and provides full-disk encryption to help prevent unauthorized access to your Mac", "icon" : "SF=07.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Gatekeeper / XProtect", "subtitle" : "Prevents the execution of Apple-identified malware and adware.", "icon" : "SF=08.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Touch ID", "subtitle" : "Touch ID provides secure biometric authentication for unlock your Mac and authorize third-party apps.", "icon" : "SF=09.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=10.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=11.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Free Disk Space", "subtitle" : "Checks for the amount of free disk space on your Mac’s boot volume", "icon" : "SF=12.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Desktop Size and Item Count", "subtitle" : "Checks the size and item count of the Desktop", "icon" : "SF=13.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Downloads Size and Item Count", "subtitle" : "Checks the size and item count of the Downloads folder", "icon" : "SF=14.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Trash Size and Item Count", "subtitle" : "Checks the size and item count of the Trash", "icon" : "SF=15.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Password Hint", "subtitle" : "Ensure no password hint is set for better security", "icon" : "SF=16.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirPlay Receiver", "subtitle" : "Ensure AirPlay Receiver is disabled when not needed", "icon" : "SF=18.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=19.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Profile", "subtitle" : "The presence of the '${mdmVendor}' MDM profile helps ensure your Mac is enrolled", "icon" : "SF=20.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Certificate Expiration", "subtitle" : "Validate the expiration date of the '${mdmVendor}' MDM certificate", "icon" : "SF=21.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=22.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=23.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=24.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=25.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=26.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=27.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=28.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'
# Validate filewaveMdmListitemJSON is valid JSON
if ! echo "$filewaveMdmListitemJSON" | jq . >/dev/null 2>&1; then
  echo "Error: filewaveMdmListitemJSON is invalid JSON"
  echo "$filewaveMdmListitemJSON"
  exit 1
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Fleet MDM List Items
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

fleetMdmListitemJSON='
[
    {"title" : "macOS Version", "subtitle" : "Organizational standards are the current and immediately previous versions of macOS", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Available Updates", "subtitle" : "Keep your Mac up-to-date to ensure its security and performance", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "App Auto-Patch", "subtitle" : "Keep your apps up-to-date to ensure their security and performance", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "System Integrity Protection", "subtitle" : "System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code.", "icon" : "SF=04.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Signed System Volume", "subtitle" : "Signed System Volume (SSV) ensures macOS is booted from a signed, cryptographically protected volume.", "icon" : "SF=05.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Firewall", "subtitle" : "The built-in macOS firewall helps protect your Mac from unauthorized access.", "icon" : "SF=06.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "FileVault Encryption", "subtitle" : "FileVault is built-in to macOS and provides full-disk encryption to help prevent unauthorized access to your Mac", "icon" : "SF=07.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Gatekeeper / XProtect", "subtitle" : "Prevents the execution of Apple-identified malware and adware.", "icon" : "SF=08.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Touch ID", "subtitle" : "Touch ID provides secure biometric authentication for unlock your Mac and authorize third-party apps.", "icon" : "SF=09.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=10.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=11.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Free Disk Space", "subtitle" : "Checks for the amount of free disk space on your Mac’s boot volume", "icon" : "SF=12.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Desktop Size and Item Count", "subtitle" : "Checks the size and item count of the Desktop", "icon" : "SF=13.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Downloads Size and Item Count", "subtitle" : "Checks the size and item count of the Downloads folder", "icon" : "SF=14.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Trash Size and Item Count", "subtitle" : "Checks the size and item count of the Trash", "icon" : "SF=15.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Password Hint", "subtitle" : "Ensure no password hint is set for better security", "icon" : "SF=16.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirPlay Receiver", "subtitle" : "Ensure AirPlay Receiver is disabled when not needed", "icon" : "SF=18.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=19.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Profile", "subtitle" : "The presence of the '${mdmVendor}' MDM profile helps ensure your Mac is enrolled", "icon" : "SF=20.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Certificate Expiration", "subtitle" : "Validate the expiration date of the '${mdmVendor}' MDM certificate", "icon" : "SF=21.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=22.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=23.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=24.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=25.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=26.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=27.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Fleet Desktop", "subtitle" : "Visibility into the security posture of your Mac.", "icon" : "SF=28.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'
# Validate fleetMdmListitemJSON is valid JSON
if ! echo "$fleetMdmListitemJSON" | jq . >/dev/null 2>&1; then
  echo "Error: fleetMdmListitemJSON is invalid JSON"
  echo "$fleetMdmListitemJSON"
  exit 1
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Kandji MDM List Items
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

kandjiMdmListitemJSON='
[
    {"title" : "macOS Version", "subtitle" : "Organizational standards are the current and immediately previous versions of macOS", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Available Updates", "subtitle" : "Keep your Mac up-to-date to ensure its security and performance", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "App Auto-Patch", "subtitle" : "Keep your apps up-to-date to ensure their security and performance", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "System Integrity Protection", "subtitle" : "System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code.", "icon" : "SF=04.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Signed System Volume", "subtitle" : "Signed System Volume (SSV) ensures macOS is booted from a signed, cryptographically protected volume.", "icon" : "SF=05.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Firewall", "subtitle" : "The built-in macOS firewall helps protect your Mac from unauthorized access.", "icon" : "SF=06.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "FileVault Encryption", "subtitle" : "FileVault is built-in to macOS and provides full-disk encryption to help prevent unauthorized access to your Mac", "icon" : "SF=07.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Gatekeeper / XProtect", "subtitle" : "Prevents the execution of Apple-identified malware and adware.", "icon" : "SF=08.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Touch ID", "subtitle" : "Touch ID provides secure biometric authentication for unlock your Mac and authorize third-party apps.", "icon" : "SF=09.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=10.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=11.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Free Disk Space", "subtitle" : "Checks for the amount of free disk space on your Mac’s boot volume", "icon" : "SF=12.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Desktop Size and Item Count", "subtitle" : "Checks the size and item count of the Desktop", "icon" : "SF=13.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Downloads Size and Item Count", "subtitle" : "Checks the size and item count of the Downloads folder", "icon" : "SF=14.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Trash Size and Item Count", "subtitle" : "Checks the size and item count of the Trash", "icon" : "SF=15.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Password Hint", "subtitle" : "Ensure no password hint is set for better security", "icon" : "SF=16.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirPlay Receiver", "subtitle" : "Ensure AirPlay Receiver is disabled when not needed", "icon" : "SF=18.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=19.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Profile", "subtitle" : "The presence of the '${mdmVendor}' MDM profile helps ensure your Mac is enrolled", "icon" : "SF=20.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Certificate Expiration", "subtitle" : "Validate the expiration date of the '${mdmVendor}' MDM certificate", "icon" : "SF=21.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=22.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=23.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=24.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=25.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=26.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=27.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Microsoft Teams", "subtitle" : "The hub for teamwork in Microsoft 365.", "icon" : "SF=28.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'
# Validate kandjiMdmListitemJSON is valid JSON
if ! echo "$kandjiMdmListitemJSON" | jq . >/dev/null 2>&1; then
  echo "Error: kandjiMdmListitemJSON is invalid JSON"
  echo "$kandjiMdmListitemJSON"
  exit 1
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Jamf Pro List Items
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

jamfProListitemJSON='
[
    {"title" : "macOS Version", "subtitle" : "Organizational standards are the current and immediately previous versions of macOS", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Available Updates", "subtitle" : "Keep your Mac up-to-date to ensure its security and performance", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "System Integrity Protection", "subtitle" : "System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code.", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Signed System Volume", "subtitle" : "Signed System Volume (SSV) ensures macOS is booted from a signed, cryptographically protected volume.", "icon" : "SF=04.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Firewall", "subtitle" : "The built-in macOS firewall helps protect your Mac from unauthorized access.", "icon" : "SF=05.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "FileVault Encryption", "subtitle" : "FileVault is built-in to macOS and provides full-disk encryption to help prevent unauthorized access to your Mac", "icon" : "SF=06.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Gatekeeper / XProtect", "subtitle" : "Prevents the execution of Apple-identified malware and adware.", "icon" : "SF=07.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Touch ID", "subtitle" : "Touch ID provides secure biometric authentication for unlock your Mac and authorize third-party apps.", "icon" : "SF=08.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Password Hint", "subtitle" : "Ensure no password hint is set for better security", "icon" : "SF=09.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=10.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirPlay Receiver", "subtitle" : "Ensure AirPlay Receiver is disabled when not needed", "icon" : "SF=11.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=12.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=13.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=14.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Free Disk Space", "subtitle" : "Checks for the amount of free disk space on your Mac’s boot volume", "icon" : "SF=15.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Desktop Size and Item Count", "subtitle" : "Checks the size and item count of the Desktop", "icon" : "SF=16.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Downloads Size and Item Count", "subtitle" : "Checks the size and item count of the Downloads folder", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Trash Size and Item Count", "subtitle" : "Checks the size and item count of the Trash", "icon" : "SF=18.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Profile", "subtitle" : "The presence of the '${mdmVendor}' MDM profile helps ensure your Mac is enrolled", "icon" : "SF=19.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Certificate Expiration", "subtitle" : "Validate the expiration date of the '${mdmVendor}' MDM certificate", "icon" : "SF=20.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=21.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Jamf Pro Check-In", "subtitle" : "Your Mac should check-in with the Jamf Pro MDM server multiple times each day", "icon" : "SF=22.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Jamf Pro Inventory", "subtitle" : "Your Mac should submit its inventory to the Jamf Pro MDM server daily", "icon" : "SF=23.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=24.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=25.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=26.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=27.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=28.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Jamf Hosts","subtitle":"Test connectivity to Jamf Pro cloud and on-prem endpoints","icon":"SF=29.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "App Auto-Patch", "subtitle" : "Keep your apps up-to-date to ensure their security and performance", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=31.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Microsoft Teams", "subtitle" : "The hub for teamwork in Microsoft 365.", "icon" : "SF=32.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "BeyondTrust Privilege Management", "subtitle" : "Privilege Management for Mac pairs powerful least-privilege management and application control", "icon" : "SF=33.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Cisco Umbrella", "subtitle" : "Cisco Umbrella combines multiple security functions so you can extend data protection anywhere.", "icon" : "SF=34.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "CrowdStrike Falcon", "subtitle" : "Technology, intelligence, and expertise come together in CrowdStrike Falcon to deliver security that works.", "icon" : "SF=35.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Palo Alto GlobalProtect", "subtitle" : "Virtual Private Network (VPN) connection to Church headquarters", "icon" : "SF=36.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=37.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Computer Inventory", "subtitle" : "The listing of your Mac’s apps and settings", "icon" : "SF=38.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'

# Validate jamfProListitemJSON is valid JSON
if ! echo "$jamfProListitemJSON" | jq . >/dev/null 2>&1; then
  echo "Error: jamfProListitemJSON is invalid JSON"
  echo "$jamfProListitemJSON"
  exit 1
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# JumpCloud MDM List Items
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

jumpcloudMdmListitemJSON='
[
    {"title" : "macOS Version", "subtitle" : "Organizational standards are the current and immediately previous versions of macOS", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Available Updates", "subtitle" : "Keep your Mac up-to-date to ensure its security and performance", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "App Auto-Patch", "subtitle" : "Keep your apps up-to-date to ensure their security and performance", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "System Integrity Protection", "subtitle" : "System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code.", "icon" : "SF=04.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Signed System Volume", "subtitle" : "Signed System Volume (SSV) ensures macOS is booted from a signed, cryptographically protected volume.", "icon" : "SF=05.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Firewall", "subtitle" : "The built-in macOS firewall helps protect your Mac from unauthorized access.", "icon" : "SF=06.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "FileVault Encryption", "subtitle" : "FileVault is built-in to macOS and provides full-disk encryption to help prevent unauthorized access to your Mac", "icon" : "SF=07.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Gatekeeper / XProtect", "subtitle" : "Prevents the execution of Apple-identified malware and adware.", "icon" : "SF=08.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Touch ID", "subtitle" : "Touch ID provides secure biometric authentication for unlock your Mac and authorize third-party apps.", "icon" : "SF=09.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=10.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=11.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Free Disk Space", "subtitle" : "Checks for the amount of free disk space on your Mac’s boot volume", "icon" : "SF=12.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Desktop Size and Item Count", "subtitle" : "Checks the size and item count of the Desktop", "icon" : "SF=13.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Downloads Size and Item Count", "subtitle" : "Checks the size and item count of the Downloads folder", "icon" : "SF=14.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Trash Size and Item Count", "subtitle" : "Checks the size and item count of the Trash", "icon" : "SF=15.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Password Hint", "subtitle" : "Ensure no password hint is set for better security", "icon" : "SF=16.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirPlay Receiver", "subtitle" : "Ensure AirPlay Receiver is disabled when not needed", "icon" : "SF=18.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=19.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Profile", "subtitle" : "The presence of the '${mdmVendor}' MDM profile helps ensure your Mac is enrolled", "icon" : "SF=20.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Certificate Expiration", "subtitle" : "Validate the expiration date of the '${mdmVendor}' MDM certificate", "icon" : "SF=21.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=22.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=23.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=24.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=25.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=26.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=27.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Microsoft Teams", "subtitle" : "The hub for teamwork in Microsoft 365.", "icon" : "SF=28.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'

# Validate jumpcloudMdmListitemJSON is valid JSON
if ! echo "$jumpcloudMdmListitemJSON" | jq . >/dev/null 2>&1; then
  echo "Error: jumpcloudMdmListitemJSON is invalid JSON"
  echo "$jumpcloudMdmListitemJSON"
  exit 1
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Microsoft Intune MDM List Items
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

microsoftMdmListitemJSON='
[
    {"title" : "macOS Version", "subtitle" : "Organizational standards are the current and immediately previous versions of macOS", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Available Updates", "subtitle" : "Keep your Mac up-to-date to ensure its security and performance", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "App Auto-Patch", "subtitle" : "Keep your apps up-to-date to ensure their security and performance", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "System Integrity Protection", "subtitle" : "System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code.", "icon" : "SF=04.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Signed System Volume", "subtitle" : "Signed System Volume (SSV) ensures macOS is booted from a signed, cryptographically protected volume.", "icon" : "SF=05.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Firewall", "subtitle" : "The built-in macOS firewall helps protect your Mac from unauthorized access.", "icon" : "SF=06.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "FileVault Encryption", "subtitle" : "FileVault is built-in to macOS and provides full-disk encryption to help prevent unauthorized access to your Mac", "icon" : "SF=07.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Gatekeeper / XProtect", "subtitle" : "Prevents the execution of Apple-identified malware and adware.", "icon" : "SF=08.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Touch ID", "subtitle" : "Touch ID provides secure biometric authentication for unlock your Mac and authorize third-party apps.", "icon" : "SF=09.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=10.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=11.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Free Disk Space", "subtitle" : "Checks for the amount of free disk space on your Mac’s boot volume", "icon" : "SF=12.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Desktop Size and Item Count", "subtitle" : "Checks the size and item count of the Desktop", "icon" : "SF=13.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Downloads Size and Item Count", "subtitle" : "Checks the size and item count of the Downloads folder", "icon" : "SF=14.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Trash Size and Item Count", "subtitle" : "Checks the size and item count of the Trash", "icon" : "SF=15.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Password Hint", "subtitle" : "Ensure no password hint is set for better security", "icon" : "SF=16.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirPlay Receiver", "subtitle" : "Ensure AirPlay Receiver is disabled when not needed", "icon" : "SF=18.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=19.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Profile", "subtitle" : "The presence of the '${mdmVendor}' MDM profile helps ensure your Mac is enrolled", "icon" : "SF=20.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Certificate Expiration", "subtitle" : "Validate the expiration date of the '${mdmVendor}' MDM certificate", "icon" : "SF=21.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=22.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=23.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=24.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=25.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=26.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=27.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Microsoft Company Portal", "subtitle" : "Securely access and manage corporate apps, resources, and devices via Intune.", "icon" : "SF=28.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'

# Validate microsoftMdmListitemJSON is valid JSON
if ! echo "$microsoftMdmListitemJSON" | jq . >/dev/null 2>&1; then
  echo "Error: microsoftMdmListitemJSON is invalid JSON"
  echo "$microsoftMdmListitemJSON"
  exit 1
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Mosyle List Items (thanks, @precursorca and @bigdoodr!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

mosyleListitemJSON='
[
    {"title" : "macOS Version", "subtitle" : "Organizational standards are the current and immediately previous versions of macOS", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Available Updates", "subtitle" : "Keep your Mac up-to-date to ensure its security and performance", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "App Auto-Patch", "subtitle" : "Keep your apps up-to-date to ensure their security and performance", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "System Integrity Protection", "subtitle" : "System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code.", "icon" : "SF=04.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Signed System Volume", "subtitle" : "Signed System Volume (SSV) ensures macOS is booted from a signed, cryptographically protected volume.", "icon" : "SF=05.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Firewall", "subtitle" : "The built-in macOS firewall helps protect your Mac from unauthorized access.", "icon" : "SF=06.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "FileVault Encryption", "subtitle" : "FileVault is built-in to macOS and provides full-disk encryption to help prevent unauthorized access to your Mac", "icon" : "SF=07.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Gatekeeper / XProtect", "subtitle" : "Prevents the execution of Apple-identified malware and adware.", "icon" : "SF=08.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Touch ID", "subtitle" : "Touch ID provides secure biometric authentication for unlock your Mac and authorize third-party apps.", "icon" : "SF=09.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=10.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=11.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Free Disk Space", "subtitle" : "Checks for the amount of free disk space on your Mac’s boot volume", "icon" : "SF=12.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Desktop Size and Item Count", "subtitle" : "Checks the size and item count of the Desktop", "icon" : "SF=13.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Downloads Size and Item Count", "subtitle" : "Checks the size and item count of the Downloads folder", "icon" : "SF=14.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Trash Size and Item Count", "subtitle" : "Checks the size and item count of the Trash", "icon" : "SF=15.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Password Hint", "subtitle" : "Ensure no password hint is set for better security", "icon" : "SF=16.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirPlay Receiver", "subtitle" : "Ensure AirPlay Receiver is disabled when not needed", "icon" : "SF=18.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=19.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Profile", "subtitle" : "The presence of the '${mdmVendor}' MDM profile helps ensure your Mac is enrolled", "icon" : "SF=20.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Certificate Expiration", "subtitle" : "Validate the expiration date of the '${mdmVendor}' MDM certificate", "icon" : "SF=21.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=22.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Mosyle Check-In", "subtitle" : "Your Mac should check-in with the Mosyle MDM server multiple times each day", "icon" : "SF=23.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.4},
    {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=24.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=25.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=26.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=27.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=28.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' Self-Service", "subtitle" : "Your one-stop shop for all things '${mdmVendor}'.", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=31.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'

# Validate mosyleListitemJSON is valid JSON
if ! echo "$mosyleListitemJSON" | jq . >/dev/null 2>&1; then
  echo "Error: mosyletitemJSON is invalid JSON"
  echo "$mosyleListitemJSON"
  exit 1
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Generic MDM List Items
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

genericMdmListitemJSON='
[
    {"title" : "macOS Version", "subtitle" : "Organizational standards are the current and immediately previous versions of macOS", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Available Updates", "subtitle" : "Keep your Mac up-to-date to ensure its security and performance", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "System Integrity Protection", "subtitle" : "System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code.", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Signed System Volume", "subtitle" : "Signed System Volume (SSV) ensures macOS is booted from a signed, cryptographically protected volume.", "icon" : "SF=04.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Firewall", "subtitle" : "The built-in macOS firewall helps protect your Mac from unauthorized access.", "icon" : "SF=05.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "FileVault Encryption", "subtitle" : "FileVault is built-in to macOS and provides full-disk encryption to help prevent unauthorized access to your Mac", "icon" : "SF=06.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Gatekeeper / XProtect", "subtitle" : "Prevents the execution of Apple-identified malware and adware.", "icon" : "SF=07.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Touch ID", "subtitle" : "Touch ID provides secure biometric authentication for unlock your Mac and authorize third-party apps.", "icon" : "SF=08.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=09.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=10.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Free Disk Space", "subtitle" : "Checks for the amount of free disk space on your Mac’s boot volume", "icon" : "SF=11.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Desktop Size and Item Count", "subtitle" : "Checks the size and item count of the Desktop", "icon" : "SF=12.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Downloads Size and Item Count", "subtitle" : "Checks the size and item count of the Downloads folder", "icon" : "SF=13.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Trash Size and Item Count", "subtitle" : "Checks the size and item count of the Trash", "icon" : "SF=14.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Password Hint", "subtitle" : "Ensure no password hint is set for better security", "icon" : "SF=15.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=16.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirPlay Receiver", "subtitle" : "Ensure AirPlay Receiver is disabled when not needed", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=18.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=19.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=20.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=21.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=22.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=23.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=24.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=25.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=26.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'

# Validate genericMdmListitemJSON is valid JSON
if ! echo "$genericMdmListitemJSON" | jq . >/dev/null 2>&1; then
  echo "Error: genericMdmListitemJSON is invalid JSON"
  echo "$genericMdmListitemJSON"
  exit 1
fi



####################################################################################################
#
# Functions
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Client-side Logging
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function updateScriptLog() {
    echo "${organizationScriptName} ($scriptVersion): $( date +%Y-%m-%d\ %H:%M:%S ) - ${1}" | tee -a "${scriptLog}"
}

function preFlight()    { updateScriptLog "[PRE-FLIGHT]      ${1}"; }
function logComment()   { updateScriptLog "                  ${1}"; }
function notice()       { updateScriptLog "[NOTICE]          ${1}"; }
function info()         { updateScriptLog "[INFO]            ${1}"; }
function errorOut()     { updateScriptLog "[ERROR]           ${1}"; }
function error()        { updateScriptLog "[ERROR]           ${1}"; let errorCount++; }
function warning()      { updateScriptLog "[WARNING]         ${1}"; let errorCount++; }
function fatal()        { updateScriptLog "[FATAL ERROR]     ${1}"; exit 1; }
function quitOut()      { updateScriptLog "[QUIT]            ${1}"; }



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update the running dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dialogUpdate(){
    if [[ "${operationMode}" != "Silent" ]]; then
        sleep 0.3
        echo "$1" >> "$dialogCommandFile"
    else
        # info "Operation Mode is 'Silent'; not updating dialog."
    fi
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Run command as logged-in user (thanks, @scriptingosx!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function runAsUser() {

    info "Run \"$@\" as \"$loggedInUserID\" … "
    launchctl asuser "$loggedInUserID" sudo -u "$loggedInUser" "$@"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Parse JSON via osascript and JavaScript
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function get_json_value() {
    JSON="$1" osascript -l 'JavaScript' \
        -e 'const env = $.NSProcessInfo.processInfo.environment.objectForKey("JSON").js' \
        -e "JSON.parse(env).$2"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Webhook Message (Microsoft Teams or Slack) (thanks, @robjschroeder! and @TechTrekkie!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function webHookMessage() {

    # Generate MDM-specific `computerMdmURL`
    case "${mdmVendor}" in
        "Jamf Pro" )
            mdmURL=$( /usr/bin/defaults read /Library/Preferences/com.jamfsoftware.jamf.plist jss_url )
            computerMdmURL="${mdmURL}computers.html?query=${serialNumber}&queryType=COMPUTERS"
            ;;
        "Mosyle" )
            # mdmURL=$( /usr/bin/defaults read /Library/Preferences/com.jamfsoftware.jamf.plist jss_url )
            # computerMdmURL="${mdmURL}computers.html?query=${serialNumber}&queryType=COMPUTERS"
            ;;
        * )
            return
            ;;
    esac

    if [[ $webhookURL == *"slack"* ]]; then
        
        info "Generating Slack Message …"
        
        webHookdata=$(cat <<EOF
        {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "Mac Health Check: '${webhookStatus}'",
                        "emoji": true
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        { "type": "mrkdwn", "text": "*Computer Name:*\n$( scutil --get ComputerName )" },
                        { "type": "mrkdwn", "text": "*Serial:*\n${serialNumber}" },
                        { "type": "mrkdwn", "text": "*Timestamp:*\n${timestamp}" },
                        { "type": "mrkdwn", "text": "*User:*\n${loggedInUser}" },
                        { "type": "mrkdwn", "text": "*OS Version:*\n${osVersion} (${osBuild})" },
                        { "type": "mrkdwn", "text": "*Health Failures:*\n${overallHealth%%; }" }
                    ]
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "View in Jamf Pro"
                            },
                            "style": "primary",
                            "url": "${computerMdmURL}"
                        }
                    ]
                }
            ]
        }
EOF
)

        # Send the message to Slack
        info "Send the message to Slack …"
        info "${webHookdata}"
        # Submit the data to Slack
        curl -sSX POST -H 'Content-type: application/json' --data "${webHookdata}" $webhookURL 2>&1
        webhookResult="$?"
        info "Slack Webhook Result: ${webhookResult}"

    else
        
        info "Generating Microsoft Teams Message …"

        webHookdata=$(cat <<EOF
        {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": null,
                    "content": {
                        "type": "AdaptiveCard",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "Large",
                                "weight": "Bolder",
                                "text": "Mac Health Check: ${webhookStatus}"
                            },
                            {
                                "type": "ColumnSet",
                                "columns": [
                                    {
                                        "type": "Column",
                                        "items": [
                                            {
                                                "type": "Image",
                                                "url": "https://usw2.ics.services.jamfcloud.com/icon/hash_38a7af6b0231e76e3f4842ee3c8a18fb8b1642750f6a77385eff96707124e1fb",
                                                "altText": "Mac Health Check",
                                                "size": "Small"
                                            }
                                        ],
                                        "width": "auto"
                                    },
                                    {
                                        "type": "Column",
                                        "items": [
                                            {
                                                "type": "TextBlock",
                                                "weight": "Bolder",
                                                "text": "$( scutil --get ComputerName )",
                                                "wrap": true
                                            },
                                            {
                                                "type": "TextBlock",
                                                "spacing": "None",
                                                "text": "${serialNumber}",
                                                "isSubtle": true,
                                                "wrap": true
                                            }
                                        ],
                                        "width": "stretch"
                                    }
                                ]
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    { "title": "Timestamp", "value": "${timestamp}" },
                                    { "title": "User", "value": "${loggedInUser}" },
                                    { "title": "Operating System", "value": "${osVersion} (${osBuild})" },
                                    { "title": "Health Failures", "value": "${overallHealth%%; }" }
                                ]
                            }
                        ],
                        "actions": [
                            {
                                "type": "Action.OpenUrl",
                                "title": "View in Jamf Pro",
                                "url": "${computerMdmURL}"
                            }
                        ],
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.2"
                    }
                }
            ]
        }
EOF
)

    # Send the message to Microsoft Teams
        info "Send the message to Microsoft Teams …"
        curl --silent \
            --request POST \
            --url "${webhookURL}" \
            --header 'Content-Type: application/json' \
            --data "${webHookdata}" \
            --output /dev/null

        webhookResult="$?"
        info "Microsoft Teams Webhook Result: ${webhookResult}"
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Quit Script (thanks, @bartreadon!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function quitScript() {

    quitOut "Exiting …"

    notice "${localAdminWarning}User: ${loggedInUserFullname} (${loggedInUser}) [${loggedInUserID}] ${loggedInUserGroupMembership}; Security Mode: ${bootPoliciesSecurityMode}; DEP-allowed MDM Control: ${bootPoliciesDepAllowedMdmControl}; Activation Lock: ${activationLockStatus}; ${bootstrapTokenStatus}; sudo Check: ${sudoStatus}; sudoers: ${sudoAllLines}; Kerberos SSOe: ${kerberosSSOeResult}; Platform SSOe: ${platformSSOeResult}; Location Services: ${locationServicesStatus}; SSH: ${sshStatus}; Microsoft OneDrive Sync Date: ${oneDriveSyncDate}; Time Machine Backup Date: ${tmStatus} ${tmLastBackup}; Battery Cycle Count: ${batteryCycleCount}; Wi-Fi: ${ssid}; ${activeIPAddress//\*\*/}; VPN IP: ${vpnStatus} ${vpnExtendedStatus}; ${networkTimeServer}"

    case ${mdmVendor} in

        "Jamf Pro" )
            notice "Jamf Pro Computer ID: ${jamfProID}; Site: ${jamfProSiteName}"
            ;;

    esac

    if [[ -n "${overallHealth}" ]]; then
        if [[ "${operationMode}" != "Silent" ]]; then
            dialogUpdate "icon: SF=xmark.circle, weight=bold, colour1=#BB1717, colour2=#F31F1F"
            dialogUpdate "title: Computer Unhealthy <br>as of $( date '+%d-%b-%Y %H:%M:%S' )"
        fi
        if [[ -n "${webhookURL}" ]]; then
            info "Sending webhook message"
            webhookStatus="Failures Detected (${#errorMessages[@]} errors)"
            webHookMessage
        fi
        errorOut "${overallHealth%%; }"
        exitCode="1"
    else
        if [[ "${operationMode}" != "Silent" ]]; then
            dialogUpdate "icon: SF=checkmark.circle, weight=bold, colour1=#00ff44, colour2=#075c1e"
            dialogUpdate "title: Computer Healthy <br>as of $( date '+%d-%b-%Y %H:%M:%S' )"
        fi
    fi

    if [[ "${operationMode}" != "Silent" ]]; then
        dialogUpdate "progress: 100"
        dialogUpdate "progresstext: Elapsed Time: $(printf '%dh:%dm:%ds\n' $((SECONDS/3600)) $((SECONDS%3600/60)) $((SECONDS%60)))"
        dialogUpdate "button1text: Close"
        dialogUpdate "button1: enable"
        
        sleep "${anticipationDuration}"

        # Progress countdown (thanks, @samg and @bartreadon!)
        dialogUpdate "progress: reset"
        while true; do
            if [[ ${completionTimer} -lt ${progressSteps} ]]; then
                dialogUpdate "progress: ${completionTimer}"
            fi
            dialogUpdate "progresstext: Closing automatically in ${completionTimer} seconds …"
            sleep 1
            ((completionTimer--))
            if [[ ${completionTimer} -lt 0 ]]; then break; fi
            if ! kill -0 "${dialogPID}" 2>/dev/null; then break; fi
        done
        dialogUpdate "quit:"
    fi

    # Remove the dialog command file
    rm -f "${dialogCommandFile}"

    # Remove the dialog JSON file
    if [[ "${operationMode}" == "Self Service" ]] || [[ "${operationMode}" == "Silent" ]]; then
        rm -f /var/tmp/dialogJSONFile_*
    else
        notice "${operationMode} mode: NOT deleting dialogJSONFile ${dialogJSONFile}"
    fi

    # Remove overlay icon
    if [[ -f "${overlayicon}" ]] && [[ "${overlayicon}" != "/System/Library/CoreServices/Apple Diagnostics.app" ]]; then
        rm -f "${overlayicon}"
    fi

    # Remove default dialog.log
    rm -f /var/tmp/dialog.log

    # Remove SOFA JSON cache directory
    if [[ "${operationMode}" == "Self Service" ]] || [[ "${operationMode}" == "Silent" ]]; then
        rm -Rf "${json_cache_dir}"
    else
        notice "${operationMode} mode: NOT deleting json_cache_dir ${json_cache_dir}"
    fi

    notice "Total Elapsed Time: $(printf '%dh:%dm:%ds\n' $((SECONDS/3600)) $((SECONDS%3600/60)) $((SECONDS%60)))"

    quitOut "Goodbye!"

    exit "${exitCode}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Kill a specified process (thanks, @grahampugh!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function killProcess() {
    process="$1"
    if process_pid=$( pgrep -a "${process}" 2>/dev/null ) ; then
        info "Attempting to terminate the '$process' process …"
        info "(Termination message indicates success.)"
        kill "$process_pid" 2> /dev/null
        if pgrep -a "$process" >/dev/null ; then
            error "'$process' could not be terminated."
        fi
    else
        info "The '$process' process isn’t running."
    fi
}



####################################################################################################
#
# Pre-flight Checks
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Client-side Logging
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ ! -f "${scriptLog}" ]]; then
    touch "${scriptLog}"
    if [[ -f "${scriptLog}" ]]; then
        preFlight "Created specified scriptLog: ${scriptLog}"
    else
        fatal "Unable to create specified scriptLog '${scriptLog}'; exiting.\n\n(Is this script running as 'root' ?)"
    fi
else
    # preFlight "Specified scriptLog '${scriptLog}' exists; writing log entries to it"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Logging Preamble
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

preFlight "\n\n###\n# $humanReadableScriptName (${scriptVersion})\n# https://snelson.us/mhc\n#\n# Operation Mode: ${operationMode}\n####\n\n"
preFlight "Initiating …"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Computer Information
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

preFlight "${computerName} (S/N ${serialNumber})"
preFlight "${loggedInUserFullname} (${loggedInUser}) [${loggedInUserID}]" 



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Confirm script is running as root
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ $(id -u) -ne 0 ]]; then
    fatal "This script must be run as root; exiting."
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Confirm jq is installed
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if ! command -v jq &> /dev/null; then
    fatal "jq is not installed; exiting."
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Validate / install swiftDialog (Thanks big bunches, @acodega!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dialogInstall() {
    # Get the URL of the latest PKG From the Dialog GitHub repo
    dialogURL=$(curl -L --silent --fail --connect-timeout 10 --max-time 30 \
        "https://api.github.com/repos/swiftDialog/swiftDialog/releases/latest" \
        | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")
    
    # Validate URL was retrieved
    if [[ -z "${dialogURL}" ]]; then
        fatal "Failed to retrieve swiftDialog download URL from GitHub API"
    fi
    
    # Validate URL format
    if [[ ! "${dialogURL}" =~ ^https://github\.com/ ]]; then
        fatal "Invalid swiftDialog URL format: ${dialogURL}"
    fi

    # Expected Team ID of the downloaded PKG
    expectedDialogTeamID="PWA5E9TQ59"

    preFlight "Installing swiftDialog from ${dialogURL}..."

    # Create temporary working directory
    workDirectory=$( basename "$0" )
    tempDirectory=$( mktemp -d "/private/tmp/$workDirectory.XXXXXX" )

    # Download the installer package with timeouts
    if ! curl --location --silent --fail --connect-timeout 10 --max-time 60 \
             "$dialogURL" -o "$tempDirectory/Dialog.pkg"; then
        rm -Rf "$tempDirectory"
        fatal "Failed to download swiftDialog package"
    fi

    # Verify the download
    teamID=$(spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')

    # Install the package if Team ID validates
    if [[ "$expectedDialogTeamID" == "$teamID" ]]; then

        installer -pkg "$tempDirectory/Dialog.pkg" -target /
        sleep 2
        dialogVersion=$( /usr/local/bin/dialog --version )
        preFlight "swiftDialog version ${dialogVersion} installed; proceeding..."

    else

        # Display a so-called "simple" dialog if Team ID fails to validate
        osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\r• Dialog Team ID verification failed\r\r" with title "Mac Health Check Error" buttons {"Close"} with icon caution'
        exit "1"

    fi

    # Remove the temporary working directory when done
    rm -Rf "$tempDirectory"

}



function dialogCheck() {

    # Check for Dialog and install if not found
    if [[ ! -x "/Library/Application Support/Dialog/Dialog.app" ]]; then

        preFlight "swiftDialog not found; installing …"
        dialogInstall
        if [[ ! -x "/usr/local/bin/dialog" ]]; then
            fatal "swiftDialog still not found; are downloads from GitHub blocked on this Mac?"
        fi

    else

        dialogVersion=$(/usr/local/bin/dialog --version)
        if ! is-at-least "${swiftDialogMinimumRequiredVersion}" "${dialogVersion}"; then
            
            preFlight "swiftDialog version ${dialogVersion} found but swiftDialog ${swiftDialogMinimumRequiredVersion} or newer is required; updating …"
            dialogInstall
            if [[ ! -x "/usr/local/bin/dialog" ]]; then
                fatal "Unable to update swiftDialog; are downloads from GitHub blocked on this Mac?"
            fi

        else

            preFlight "swiftDialog version ${dialogVersion} found; proceeding …"

        fi
    
    fi

}

if [[ "${operationMode}" != "Silent" ]]; then
    dialogCheck
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Forcible-quit for all other running dialogs
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${operationMode}" != "Silent" ]]; then
    preFlight "Forcible-quit for all other running dialogs …"
    killProcess "Dialog"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Complete
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

preFlight "Complete"



####################################################################################################
#
# Health Check Functions
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Compliant OS Version (thanks, @robjschroeder!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkOS() {

    local humanReadableCheckName="macOS Version"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=pencil.and.list.clipboard,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Comparing installed OS version with compliant version …"

    sleep "${anticipationDuration}"

    if [[ "${osBuild}" =~ [a-zA-Z]$ ]]; then

        logComment "OS Build, ${osBuild}, ends with a letter; skipping"
        osResult="Beta macOS ${osVersion} (${osBuild})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, subtitle: Beta builds of macOS are purposely marked as unsupported, status: error, statustext: ${osResult}"
        warning "${osResult}"
    
    else

        logComment "OS Build, ${osBuild}, ends with a number; proceeding …"

        # N-rule variable [How many previous minor OS path versions will be marked as compliant]
        n="${previousMinorOS}"

        # URL to the online JSON data
        online_json_url="https://sofafeed.macadmins.io/v1/macos_data_feed.json"
        user_agent="Mac-Health-Check-checkOS/3.0.0"

        # local store
        json_cache_dir="/var/tmp/sofa"
        json_cache="$json_cache_dir/macos_data_feed.json"
        etag_cache="$json_cache_dir/macos_data_feed_etag.txt"

        # ensure local cache folder exists
        mkdir -p "$json_cache_dir"

        # check local vs online using etag
        if [[ -f "$etag_cache" && -f "$json_cache" ]]; then
            logComment "e-tag stored, will download only if e-tag doesn’t match"
            etag_old=$(cat "$etag_cache")
            curl --compressed --silent --etag-compare "$etag_cache" --etag-save "$etag_cache" --header "User-Agent: $user_agent" "$online_json_url" --output "$json_cache"
            etag_new=$(cat "$etag_cache")
            if [[ "$etag_old" == "$etag_new" ]]; then
                logComment "Cached ETag matched online ETag - cached json file is up to date"
            else
                logComment "Cached ETag did not match online ETag, so downloaded new SOFA json file"
            fi
        else
            logComment "No e-tag cached, proceeding to download SOFA json file"
            curl --compressed --location --max-time 3 --silent --header "User-Agent: $user_agent" "$online_json_url" --etag-save "$etag_cache" --output "$json_cache"
        fi

        # 1. Get model (DeviceID)
        model=$(sysctl -n hw.model)
        logComment "Model Identifier: $model"

        # check that the model is virtual or is in the feed at all
        if [[ $model == "VirtualMac"* ]]; then
            model="Macmini9,1"
        elif ! grep -q "$model" "$json_cache"; then
            warning "Unsupported Hardware"
            # return 1
        fi

        # 2. Get current system OS
        system_version=$( sw_vers -productVersion )
        system_os=$(cut -d. -f1 <<< "$system_version")
        # system_version="15.3"
        logComment "System Version: $system_version"

        # if [[ $system_version == *".0" ]]; then
        #     system_version=${system_version%.0}
        #     logComment "Corrected System Version: $system_version"
        # fi

        # exit if less than macOS 12
        if [[ "$system_os" -lt 12 ]]; then
            osResult="Unsupported macOS"
            result "$osResult"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${osResult}"
            # return 1
        fi

        # 3. Identify latest compatible major OS
        latest_compatible_os=$(plutil -extract "Models.$model.SupportedOS.0" raw -expect string "$json_cache" | head -n 1)
        logComment "Latest Compatible macOS: $latest_compatible_os"

        # 4. Get OSVersions.Latest.ProductVersion
        latest_version_match=false
        security_update_within_30_days=false
        n_rule=false

        for i in {0..3}; do
            os_version=$(plutil -extract "OSVersions.$i.OSVersion" raw "$json_cache" | head -n 1)

            if [[ -z "$os_version" ]]; then
                break
            fi

            latest_product_version=$(plutil -extract "OSVersions.$i.Latest.ProductVersion" raw "$json_cache" | head -n 1)

            if [[ "$latest_product_version" == "$system_version" ]]; then
                latest_version_match=true
                break
            fi

            num_security_releases=$(plutil -extract "OSVersions.$i.SecurityReleases" raw "$json_cache" | xargs | awk '{ print $1}' )

            if [[ -n "$num_security_releases" ]]; then
                for ((j=0; j<num_security_releases; j++)); do
                    security_release_product_version=$(plutil -extract "OSVersions.$i.SecurityReleases.$j.ProductVersion" raw "$json_cache" | head -n 1)
                    if [[ "${system_version}" == "${security_release_product_version}" ]]; then
                        security_release_date=$(plutil -extract "OSVersions.$i.SecurityReleases.$j.ReleaseDate" raw "$json_cache" | head -n 1)
                        security_release_date_epoch=$(date -jf "%Y-%m-%dT%H:%M:%SZ" "$security_release_date" +%s)
                        days_ago_30=$(date -v-30d +%s)

                        if [[ $security_release_date_epoch -ge $days_ago_30 ]]; then
                            security_update_within_30_days=true
                        fi
                        if (( $j <= "$n" )); then
                            n_rule=true
                        fi
                    fi
                done
            fi
        done

        if [[ "$latest_version_match" == true ]] || [[ "$security_update_within_30_days" == true ]] || [[ "$n_rule" == true ]]; then
            osResult="macOS ${osVersion} (${osBuild})"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${osResult}"
            info "${osResult}"
        else
            osResult="macOS ${osVersion} (${osBuild})"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please update to a supported macOS version via System Settings > General > Software Update, status: fail, statustext: ${osResult}"
            errorOut "${osResult}"
            overallHealth+="${humanReadableCheckName}; "
        fi

    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Staged macOS Updates
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkStagedUpdate() {

    local stagedUpdateSize="0"
    local stagedUpdateLocation="Not detected"
    local stagedUpdateStatus="Pending download"
    
    # Check for APFS snapshots indicating staged updates
    local updateSnapshots=$(tmutil listlocalsnapshots / 2>/dev/null | grep -c "com.apple.os.update")
    
    if [[ ${updateSnapshots} -gt 0 ]]; then
        info "Found ${updateSnapshots} update snapshot(s)"
        stagedUpdateStatus="Partially staged"
    fi
    
    # Identify Preboot UUID directory
    local systemVolumeUUID
    systemVolumeUUID=$(
        ls -1 /System/Volumes/Preboot 2>/dev/null \
        | grep -E '^[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}$' \
        | head -1
    )

    if [[ -z "${systemVolumeUUID}" ]]; then
        info "No Preboot UUID directory found; staging cannot be evaluated."
        updateStagingStatus="Pending download"
        return
    fi

    local prebootPath="/System/Volumes/Preboot/${systemVolumeUUID}"
    info "Using Preboot UUID directory: ${prebootPath}"

    if [[ -n "${systemVolumeUUID}" ]]; then
        local prebootPath="/System/Volumes/Preboot/${systemVolumeUUID}"

        # Diagnostic Logging (Preboot visibility)
        info "Analyzing Preboot path: ${prebootPath}"

        if [[ ! -d "${prebootPath}" ]]; then
            info "Preboot path does not exist or is not a directory."
        else
            info "Listing contents of Preboot UUID directory:"
            ls -l "${prebootPath}" 2>/dev/null | sed 's/^/    /' || info "Unable to list Preboot contents"

            # Check for expected staging directories
            if [[ ! -d "${prebootPath}/cryptex1" ]]; then
                info "No 'cryptex1' directory present (normal until staging begins)"
            fi
            if [[ ! -d "${prebootPath}/restore-staged" ]]; then
                info "No 'restore-staged' directory present (normal until later staging phase)"
            fi
        fi

        # Check cryptex1 for staged update content
        if [[ -d "${prebootPath}/cryptex1" ]]; then
            local cryptexSize=$(sudo du -sk "${prebootPath}/cryptex1" 2>/dev/null | awk '{print $1}')
            
            # Typical cryptex1 is < 1GB; if > 1GB, staging is very likely underway
            if [[ -n "${cryptexSize}" ]] && [[ ${cryptexSize} -gt 1048576 ]]; then
                stagedUpdateSize=$(echo "scale=2; ${cryptexSize} / 1048576" | bc)
                stagedUpdateLocation="${prebootPath}/cryptex1"
                stagedUpdateStatus="Fully staged"
                info "Staged update detected: ${stagedUpdateSize} GB in cryptex1"
            fi
        fi
        
        # Check restore-staged directory (optional supplemental assets)
        if [[ -d "${prebootPath}/restore-staged" ]]; then
            local restoreSize=$(sudo du -sk "${prebootPath}/restore-staged" 2>/dev/null | awk '{print $1}')
            if [[ -n "${restoreSize}" ]] && [[ ${restoreSize} -gt 102400 ]]; then
                local restoreSizeGB=$(echo "scale=2; ${restoreSize} / 1048576" | bc)
                info "Additional staged content: ${restoreSizeGB} GB in restore-staged"
            fi
        fi
        
        # Check total Preboot volume usage
        local totalPrebootSize=$(sudo du -sk "${prebootPath}" 2>/dev/null | awk '{print $1}')
        if [[ -n "${totalPrebootSize}" ]]; then
            local prebootGB=$(echo "scale=2; ${totalPrebootSize} / 1048576" | bc)
            
            # Typical Preboot is 1–3 GB; if > 8 GB, major update assets are staged
            if (( $(echo "${prebootGB} > 8" | bc -l) )); then
                if [[ "${stagedUpdateStatus}" != "Fully staged" ]]; then
                    stagedUpdateSize="${prebootGB}"
                    stagedUpdateLocation="${prebootPath}"
                    stagedUpdateStatus="Fully staged"
                    info "Large Preboot volume detected: ${prebootGB} GB total (threshold 8 GB)"
                fi
            fi
        fi
    fi
    
    # Export variables for use in dialog
    updateStagedSize="${stagedUpdateSize}"
    updateStagedLocation="${stagedUpdateLocation}"
    updateStagingStatus="${stagedUpdateStatus}"
    
    notice "Update Staging Status: ${stagedUpdateStatus}"
    if [[ "${stagedUpdateStatus}" == "Fully staged" ]]; then
        notice "Update Size: ${stagedUpdateSize} GB"
        notice "Location: ${stagedUpdateLocation}"
    fi

    case "${updateStagingStatus}" in
        "Fully staged")
            stagingMessage="Ready to install (${updateStagedSize} GB downloaded)"
            ;;
        "Partially staged")
            stagingMessage="Preparing update …"
            ;;
        "Pending download")
            stagingMessage="Will start download when you open System Settings > General > Software Update"
            ;;
        *)
            stagingMessage="Open System Settings > General > Software Update"
            ;;
    esac

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Available Software Updates
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkAvailableSoftwareUpdates() {

    local humanReadableCheckName="Available Software Updates"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=arrow.trianglehead.2.clockwise,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    # sleep "${anticipationDuration}"

    # MDM Client Available OS Updates
    mdmClientAvailableOSUpdates=$( /usr/libexec/mdmclient AvailableOSUpdates | awk '/Available updates/,/^\)/{if(/HumanReadableName =/){n=$0;sub(/.*= "/,"",n);sub(/".*/,"",n)}if(/DeferredUntil =/){d=$0;sub(/.*= "/,"",d);sub(/ 00:00:00.*/,"",d)}if(n!=""&&d!=""){print n" | "d;n="";d=""}}' )
    if [[ -n "${mdmClientAvailableOSUpdates}" ]]; then
        notice "MDM Client Available OS Updates | Deferred Until"
        info "${mdmClientAvailableOSUpdates}"
    fi

    # DDM-enforced OS Version
    ddmEnforcedInstallDateRaw=$( grep EnforcedInstallDate /var/log/install.log | tail -n 1 )
    if [[ -n "$ddmEnforcedInstallDateRaw" ]]; then
        
        # DDM-enforced Install Date
        tmp=${ddmEnforcedInstallDateRaw##*|EnforcedInstallDate:}
        ddmEnforcedInstallDate=${tmp%%|*}
        
        # DDM-enforced Version
        tmp=${ddmEnforcedInstallDateRaw##*|VersionString:}
        ddmVersionString=${tmp%%|*}

        ddmEnforcedInstallDateHumanReadable=$(date -jf "%Y-%m-%dT%H" "$ddmEnforcedInstallDate" "+%d-%b-%Y" 2>/dev/null)

    fi

    # Software Update Recommended Updates
    recommendedUpdates=$( /usr/libexec/PlistBuddy -c "Print :RecommendedUpdates:0" /Library/Preferences/com.apple.SoftwareUpdate.plist 2>/dev/null )
    if [[ -n "${recommendedUpdates}" ]]; then
        SUListRaw=$( softwareupdate --list 2>&1 )
        case "${SUListRaw}" in
            *"Can’t connect"* )
                availableSoftwareUpdates="Can’t connect to the Software Update server"
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: System Settings > General > Software Update, status: fail, statustext: ${availableSoftwareUpdates}"
                errorOut "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                overallHealth+="${humanReadableCheckName}; "
                ;;
            *"The operation couldn’t be completed."* )
                availableSoftwareUpdates="The operation couldn’t be completed."
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: System Settings > General > Software Update, status: fail, statustext: ${availableSoftwareUpdates}"
                errorOut "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                overallHealth+="${humanReadableCheckName}; "
                ;;
            *"Deferred: YES"* )
                availableSoftwareUpdates="Deferred software available."
                checkStagedUpdate
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, subtitle: System Settings > General > Software Update; ${stagingMessage}, status: error, statustext: ${availableSoftwareUpdates}"
                warning "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                ;;
            *"No new software available."* )
                availableSoftwareUpdates="No new software available."
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: Thanks for keeping your Mac up-to-date, status: success, statustext: ${availableSoftwareUpdates}"
                info "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                ;;
            * )
                SUList=$( echo "${SUListRaw}" | grep "*" | sed "s/\* Label: //g" | sed "s/,*$//g" )
                availableSoftwareUpdates="${SUList}"
                checkStagedUpdate
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, subtitle: System Settings > General > Software Update; ${stagingMessage}, status: error, statustext: ${availableSoftwareUpdates}"
                warning "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                ;;
        esac

    else

        # Treat a DDM-enforced OS Updates which contains the current OS as if there are no updates
        if [[ -z "$ddmEnforcedInstallDate" ]]; then
            availableSoftwareUpdates="None"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: Thanks for keeping your Mac up-to-date, status: success, statustext: ${availableSoftwareUpdates}"
            info "${humanReadableCheckName}: ${availableSoftwareUpdates}"
        elif is-at-least "${ddmVersionString}" "${osVersion}"; then
            availableSoftwareUpdates="Up-to-date"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: Thanks for keeping your Mac up-to-date, status: success, statustext: ${availableSoftwareUpdates}"
            info "${humanReadableCheckName}: ${availableSoftwareUpdates}"
        else
            availableSoftwareUpdates="macOS ${ddmVersionString} (${ddmEnforcedInstallDateHumanReadable})"
            checkStagedUpdate
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, subtitle: System Settings > General > Software Update; ${stagingMessage}, status: error, statustext: ${availableSoftwareUpdates}"
            info "${humanReadableCheckName}: ${availableSoftwareUpdates}"
        fi

    fi

}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Last App Auto-Patch Run
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkAppAutoPatch() {

    local humanReadableCheckName="App Auto-Patch last run"
    notice "Checking ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=arrow.triangle.2.circlepath.circle,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} …"

    sleep "${anticipationDuration}"
    
    # Thresholds in days
    local aap_warning_threshold=7
    local aap_critical_threshold=30

    # Path to App Auto-Patch log
    local aap_log_path="/Library/Management/AppAutoPatch/logs/aap.log"

    # Check if log file exists
    if [[ ! -f "${aap_log_path}" ]]; then
        errorOut "${humanReadableCheckName}: Log file not found"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please run App Auto-Patch from the ${organizationSelfServiceMarketingName}, status: fail, statustext: Log not found"
        overallHealth+="${humanReadableCheckName}; "
        return
    fi

    # Preferred: pull the last machine timestamp from the log (YYYYMMDDHHMMSS)
    local aap_ts_line aap_ts last_run_epoch now_epoch seconds_since_last_run days_since_last_run

    aap_ts_line=$(grep -E "Current time stamp:" "${aap_log_path}" | tail -1)

    if [[ -z "${aap_ts_line}" ]]; then
        # Fallback: use log mtime if the timestamp line is missing
        last_run_epoch=$(stat -f %m "${aap_log_path}" 2>/dev/null)
    else
        aap_ts=$(echo "${aap_ts_line}" | awk '{print $NF}')

        # Validate expected format (14 digits)
        if [[ ! "${aap_ts}" =~ ^[0-9]{14}$ ]]; then
            errorOut "${humanReadableCheckName}: Unable to parse AAP timestamp"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please run App Auto-Patch from the ${organizationSelfServiceMarketingName}, status: fail, statustext: Invalid timestamp format"
            overallHealth+="${humanReadableCheckName}; "
            return
        fi

        # Convert YYYYMMDDHHMMSS -> epoch seconds (macOS date)
        last_run_epoch=$(date -j -f "%Y%m%d%H%M%S" "${aap_ts}" "+%s" 2>/dev/null)
    fi

    if [[ -z "${last_run_epoch}" || ! "${last_run_epoch}" =~ ^[0-9]+$ ]]; then
        errorOut "${humanReadableCheckName}: Unable to determine last run time"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please run App Auto-Patch from the ${organizationSelfServiceMarketingName}, status: fail, statustext: Unable to determine last run"
        overallHealth+="${humanReadableCheckName}; "
        return
    fi

    now_epoch=$(date "+%s")
    seconds_since_last_run=$(( now_epoch - last_run_epoch ))

    # Guard against clock issues
    if (( seconds_since_last_run < 0 )); then seconds_since_last_run=0; fi

    days_since_last_run=$(( seconds_since_last_run / 86400 ))

    # Display string (avoid "0 day(s) ago")
    local days_since_last_run_display
    if (( days_since_last_run == 0 )); then
        days_since_last_run_display="Today"
    else
        days_since_last_run_display="${days_since_last_run} day(s) ago"
    fi

    # Set status based on days since last run
    if (( days_since_last_run >= aap_critical_threshold )); then
        errorOut "${humanReadableCheckName}: ${days_since_last_run_display} (exceeds critical threshold of ${aap_critical_threshold} days)"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please run App Auto-Patch from the ${organizationSelfServiceMarketingName}, status: fail, statustext: ${days_since_last_run_display}"
        overallHealth+="${humanReadableCheckName}; "
    elif (( days_since_last_run >= aap_warning_threshold )); then
        warning "${humanReadableCheckName}: ${days_since_last_run_display} (exceeds warning threshold of ${aap_warning_threshold} days)"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, subtitle: Please run App Auto-Patch from the ${organizationSelfServiceMarketingName}, status: error, statustext: ${days_since_last_run_display}"
    else
        info "${humanReadableCheckName}: ${days_since_last_run_display}"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: You can run App Auto-Patch at any time from the ${organizationSelfServiceMarketingName}, status: success, statustext: ${days_since_last_run_display}"
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check System Integrity Protection
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkSIP() {

    local humanReadableCheckName="System Integrity Protection"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=checkmark.shield.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    # sipCheck=$( csrutil status )

    case ${bootPoliciesSipStatus} in

        "Enabled" ) 
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
            info "${humanReadableCheckName}: Enabled"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
            errorOut "${humanReadableCheckName} (${1})"
            overallHealth+="${humanReadableCheckName}; "
            ;;

    esac

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Signed System Volume (thanks for the reminder, @hoakley!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkSSV() {

    local humanReadableCheckName="Signed System Volume"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=lock.shield,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    # ssvCheck=$( csrutil authenticated-root status )

    case ${bootPoliciesSsvStatus} in

        "Enabled" ) 
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
            info "${humanReadableCheckName}: Enabled"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
            errorOut "${humanReadableCheckName} (${1})"
            overallHealth+="${humanReadableCheckName}; "
            ;;

    esac

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Gatekeeper / XProtect (thanks for the reminder, @hoakley!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkGatekeeperXProtect() {

    local humanReadableCheckName="Gatekeeper / XProtect"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=bolt.shield.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    gatekeeperXProtectCheck=$( spctl --status )

    case ${gatekeeperXProtectCheck} in

        *"enabled"* ) 
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
            info "${humanReadableCheckName}: Enabled"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
            errorOut "${humanReadableCheckName} (${1})"
            overallHealth+="${humanReadableCheckName}; "
            ;;

    esac

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Firewall
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkFirewall() {

    local humanReadableCheckName="Firewall"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=firewall.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    if [[ "$organizationFirewall" == "socketfilterfw" ]]; then
        firewallCheck=$( /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate )
    elif [[ "$organizationFirewall" == "pf" ]]; then
        firewallCheck=$( /sbin/pfctl -s info )
    fi

    case ${firewallCheck} in

        *"enabled"* | *"Enabled"* | *"is blocking"* ) 
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
            info "${humanReadableCheckName}: Enabled"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
            errorOut "${humanReadableCheckName}: Failed"
            overallHealth+="${humanReadableCheckName}; "
            ;;

    esac

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Uptime
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkUptime() {

    local humanReadableCheckName="Uptime"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=stopwatch,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Calculating time since last reboot …"

    sleep "${anticipationDuration}"

    timestamp="$( date '+%Y-%m-%d-%H%M%S' )"
    lastBootTime=$( sysctl kern.boottime | awk -F'[ |,]' '{print $5}' )
    currentTime=$( date +"%s" )
    upTimeRaw=$((currentTime-lastBootTime))
    upTimeMin=$((upTimeRaw/60))
    upTimeHours=$((upTimeMin/60))
    uptimeDays=$( uptime | awk '{ print $4 }' | sed 's/,//g' )
    uptimeNumber=$( uptime | awk '{ print $3 }' | sed 's/,//g' )

    if [[ "${uptimeDays}" = "day"* ]]; then
        if [[ "${uptimeNumber}" -gt 1 ]]; then
            uptimeHumanReadable="${uptimeNumber} days"
        else
            uptimeHumanReadable="${uptimeNumber} day"
        fi
    elif [[ "${uptimeDays}" == "mins"* ]]; then
        uptimeHumanReadable="${uptimeNumber} mins"
    else
        uptimeHumanReadable="${uptimeNumber} (HH:MM)"
    fi

    if [[ "${upTimeMin}" -gt "${allowedUptimeMinutes}" ]]; then

        case ${excessiveUptimeAlertStyle} in

            "warning" ) 
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, subtitle: Please restart your Mac regularly, status: error, statustext: ${uptimeHumanReadable}"
                warning "${humanReadableCheckName}: ${uptimeHumanReadable}"
                ;;

            "error" | * )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please restart your Mac regularly, status: fail, statustext: ${uptimeHumanReadable}"
                errorOut "${humanReadableCheckName}: ${uptimeHumanReadable}"
                overallHealth+="${humanReadableCheckName}; "
                ;;

        esac
    
    else
    
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: Thanks for restarting your Mac regularly, status: success, statustext: ${uptimeHumanReadable}"
        info "${humanReadableCheckName}: ${uptimeHumanReadable}"
    
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Free Disk Space
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkFreeDiskSpace() {

    local humanReadableCheckName="Free Disk Space"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=externaldrive.fill.badge.checkmark,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    freeSpace=$( diskutil info / | grep -E 'Free Space|Available Space|Container Free Space' | awk -F ":\s*" '{ print $2 }' | awk -F "(" '{ print $1 }' | xargs )
    diskBytes=$( diskutil info / | grep -E 'Total Space' | sed -E 's/.*\(([0-9]+) Bytes\).*/\1/' )
    freeBytes=$( diskutil info / | grep -E 'Free Space|Available Space|Container Free Space' | sed -E 's/.*\(([0-9]+) Bytes\).*/\1/' )
    freePercentage=$( echo "scale=2; ( $freeBytes * 100 ) / $diskBytes" | bc )
    diskSpace="$freeSpace free (${freePercentage}% available)"

    diskMessage="${humanReadableCheckName}: ${diskSpace}"

    if (( $( echo ${freePercentage}'<'${allowedMinimumFreeDiskPercentage} | bc -l ) )); then

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: See KB0080685 Disk Usage to help identify the 50 largest directories, status: fail, statustext: ${diskSpace}"
        errorOut "${humanReadableCheckName}: ${diskSpace}"
        overallHealth+="${humanReadableCheckName}; "

    else

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${diskSpace}"
        info "${humanReadableCheckName}: ${diskSpace}"

    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check User Directory Size and Item Count — Parameter 2: Target Directory; Parameter 3: Icon; Parameter 4: Display Name
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkUserDirectorySizeItems() {

    local targetDirectory="${loggedInUserHomeDirectory}/${2}"
    local humanReadableCheckName="${4}"
    notice "Check ${humanReadableCheckName} directory size and item count …"

    dialogUpdate "icon: SF=${3},${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} directory size and item count …"

    sleep "${anticipationDuration}"

    userDirectorySize=$( du -sh "${targetDirectory}" 2>/dev/null | awk '{ print $1 }' )
    userDirectoryItems=$( find "${targetDirectory}" -mindepth 1 -maxdepth 1 -not -name ".*" 2>/dev/null | wc -l | xargs )

    if [[ "${userDirectoryItems}" == "0" ]]; then
        userDirectoryResult="Empty"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${userDirectoryResult}"
        info "${humanReadableCheckName}: ${userDirectoryResult}"
    else
        dirBlocks=$( du -s "${targetDirectory}" 2>/dev/null | awk '{print $1}' )
        dirBytes=$( echo "${dirBlocks} * 512" | bc 2>/dev/null || echo "0" )
        percentage=$( echo "scale=2; if (${totalDiskBytes} > 0) ${dirBytes} * 100 / ${totalDiskBytes} else 0" | bc -l 2>/dev/null || echo "0" )
        userDirectoryResult="${userDirectorySize} (${userDirectoryItems} items) — ${percentage}% of disk"
        if (( $( echo ${percentage}'>'${allowedMaximumDirectoryPercentage} | bc -l 2>/dev/null ) )); then
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, subtitle: Please contact ${supportTeamName} if you need assistance, status: error, statustext: ${userDirectoryResult}"
            warning "${humanReadableCheckName}: ${userDirectoryResult}"
            # overallHealth+="${humanReadableCheckName}; " # Uncomment to treat as an error
        else
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${userDirectoryResult}"
            info "${humanReadableCheckName}: ${userDirectoryResult}"
        fi
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check the status of the MDM Profile
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkMdmProfile() {
    local humanReadableCheckName="${mdmVendor} MDM Profile"
    notice "Check ${humanReadableCheckName} …"
    dialogUpdate "icon: SF=gear.badge,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"
    sleep "${anticipationDuration}"
    
    # Check for MDM profile
    if [[ -n "${mdmVendorUuid}" ]]; then
        # Try UUID first if provided
        mdmProfileTest=$( profiles show enrollment | grep "${mdmVendorUuid}" 2>/dev/null )
    fi
    
    if [[ -z "${mdmProfileTest}" ]] && [[ -n "${mdmProfileIdentifier}" ]]; then
        # Fall back to profileIdentifier if UUID check fails or isn't provided
        mdmProfileTest=$( profiles show enrollment | grep "profileIdentifier: ${mdmProfileIdentifier}" 2>/dev/null )
    fi
    
    if [[ -n "${mdmProfileTest}" ]]; then
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Installed"
        info "${humanReadableCheckName}: Installed"
    else
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: NOT Installed"
        errorOut "${humanReadableCheckName} (${1})"
        overallHealth+="${humanReadableCheckName}; "
        errorOut "Execute the following command to determine the profileIdentifier of the MDM Profile:"
        errorOut "sudo profiles show enrollment | grep 'profileIdentifier:'"
    fi
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Apple Push Notification service (thanks, @isaacatmann!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkAPNs() {

    local humanReadableCheckName="Apple Push Notification service"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=wave.3.up.circle,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    apnsCheck=$( command log show --last 24h --predicate 'subsystem == "com.apple.ManagedClient" && (eventMessage CONTAINS[c] "Received HTTP response (200) [Acknowledged" || eventMessage CONTAINS[c] "Received HTTP response (200) [NotNow")' | tail -1 | cut -d '.' -f 1 )

    if [[ "${apnsCheck}" == *"Timestamp"* ]] || [[ -z "${apnsCheck}" ]]; then

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
        errorOut "${humanReadableCheckName} (${1}): ${apnsCheck}"
        overallHealth+="${humanReadableCheckName}; "

    else

        apnsStatusEpoch=$( date -j -f "%Y-%m-%d %H:%M:%S" "${apnsCheck}" +"%s" )
        eventDate=$( date -r "${apnsStatusEpoch}" "+%Y-%m-%d" )
        todayDate=$( date "+%Y-%m-%d" )
        if [[ "${eventDate}" == "${todayDate}" ]]; then
            apnsStatus=$( date -r "${apnsStatusEpoch}" "+%-l:%M %p" )
        else
            apnsStatus=$( date -r "${apnsStatusEpoch}" "+%A %-l:%M %p" )
        fi
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${apnsStatus}"
        info "${humanReadableCheckName}: ${apnsCheck}"

    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Extended Network Checks (thanks, @tonyyo11!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Network timeout (in seconds) for all Jamf Extended Network Checks tests 
networkTimeout=5

# Push Notification (combines APNs and on-prem Jamf push)
pushHosts=(
    "courier.push.apple.com,5223"
    "courier.push.apple.com,443"
    "api.push.apple.com,443"
    "api.push.apple.com,2197"
)

# NOTE: The following Push Notification checks are purposely skipped …
#   "feedback.push.apple.com,2196"
#   "gateway.push.apple.com,2195"
# … due to the following:
#   nc -u -z -w 5 gateway.push.apple.com 2195
#   nc -u -z -w 5 feedback.push.apple.com 2196
#   nc: getaddrinfo: nodename nor servname provided, or not known 

# Device Management (combines Device Setup & MDM enrollment/services)
deviceMgmtHosts=(
    "albert.apple.com,443"
    "captive.apple.com,80"
    "captive.apple.com,443"
    "gs.apple.com,443"
    "humb.apple.com,443"
    "static.ips.apple.com,80"
    "static.ips.apple.com,443"
    "sq-device.apple.com,443"
    "tbsc.apple.com,443"
    "time-ios.apple.com,123,UDP"
    "time.apple.com,123,UDP"
    "time-macos.apple.com,123,UDP"
    "deviceenrollment.apple.com,443"
    "deviceservices-external.apple.com,443"
    "gdmf.apple.com,443"
    "identity.apple.com,443"
    "iprofiles.apple.com,443"
    "mdmenrollment.apple.com,443"
    "setup.icloud.com,443"
    "vpp.itunes.apple.com,443"
)

# Software & Carrier Updates
updateHosts=(
    "appldnld.apple.com,80"
    "configuration.apple.com,443"
    "gdmf.apple.com,443"
    "gg.apple.com,80"
    "gg.apple.com,443"
    "gs.apple.com,80"
    "gs.apple.com,443"
    "ig.apple.com,443"
    "mesu.apple.com,80"
    "mesu.apple.com,443"
    "oscdn.apple.com,80"
    "oscdn.apple.com,443"
    "osrecovery.apple.com,80"
    "osrecovery.apple.com,443"
    "skl.apple.com,443"
    "swcdn.apple.com,80"
    "swdist.apple.com,443"
    "swdownload.apple.com,80"
    "appldnld.apple.com.edgesuite.net,80"
    "itunes.com,80"
    "itunes.apple.com,443"
    "updates-http.cdn-apple.com,80"
    "updates.cdn-apple.com,443"
)

# Certificate Validation Hosts
certHosts=(
    "certs.apple.com,80"
    "certs.apple.com,443"
    "crl.apple.com,80"
    "crl.entrust.net,80"
    "crl3.digicert.com,80"
    "crl4.digicert.com,80"
    "ocsp.apple.com,80"
    "ocsp.digicert.cn,80"
    "ocsp.digicert.com,80"
    "ocsp.entrust.net,80"
    "ocsp2.apple.com,443"
    "valid.apple.com,443"
)

# Identity & Content Services (Apple ID, Associated Domains, Additional Content)
idAssocHosts=(
    "appleid.apple.com,443"
    "appleid.cdn-apple.com,443"
    "idmsa.apple.com,443"
    "gsa.apple.com,443"
    "app-site-association.cdn-apple.com,443"
    "app-site-association.networking.apple,443"
    "audiocontentdownload.apple.com,80"
    "audiocontentdownload.apple.com,443"
    "devimages-cdn.apple.com,80"
    "devimages-cdn.apple.com,443"
    "download.developer.apple.com,80"
    "download.developer.apple.com,443"
    "playgrounds-assets-cdn.apple.com,443"
    "playgrounds-cdn.apple.com,443"
    "sylvan.apple.com,80"
    "sylvan.apple.com,443"
)

# Jamf Pro Cloud & On-prem Endpoints
jamfHosts=(
    "jamf.com,443"
    "test.jamfcloud.com,443"
    "use1-jcdsdownloads.services.jamfcloud.com,443"
    "use1-jcds.services.jamfcloud.com,443"
    "euc1-jcdsdownloads.services.jamfcloud.com,443"
    "euc1-jcds.services.jamfcloud.com,443"
    "euw2-jcdsdownloads.services.jamfcloud.com,443"
    "euw2-jcds.services.jamfcloud.com,443"
    "apse2-jcdsdownloads.services.jamfcloud.com,443"
    "apse2-jcds.services.jamfcloud.com,443"
    "apne1-jcdsdownloads.services.jamfcloud.com,443"
    "apne1-jcds.services.jamfcloud.com,443"
)

# Generic network-host tester: uses `nc` for ports or `curl` for URLs
function checkNetworkHosts() {
    local index="$1"
    local name="$2"
    shift 2
    local hosts=("$@")

    notice "Check ${name} …"
    dialogUpdate "icon: SF=network,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${index}, icon: SF=$(printf "%02d" $(($index+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${name} connectivity …"
    sleep "${anticipationDuration}"

    local allOK=true
    local results=""

    for entry in "${hosts[@]}"; do
        # If URL, handle with curl; else nc host:port:proto
        if [[ "${entry}" =~ ^https?:// ]]; then
            # Ensure https:// (as in MTS)
            if [[ "${entry}" != https://* ]]; then
                entry="https://${entry#http://}"
            fi
            local host=$(printf '%s' "${entry}" | sed -E 's#^[a-zA-Z]+://##; s#/.*$##')
            # -sS: silent but show errors, -L: follow redirects
            local http_code=$( curl -sSL --max-time "${networkTimeout}" --connect-timeout 5 -o /dev/null -w "%{http_code}" "${entry}" 2>/dev/null )
            http_code="${http_code:-000}"
            
          # Only treat codes > 0 and < 500 as PASS; "000" (no response) will FAIL
          if [[ "${http_code}" =~ ^[0-9]{3}$ ]] && (( 10#${http_code} > 0 && 10#${http_code} < 500 )); then
            results+="${host} PASS (HTTP ${http_code}); "
          else
            results+="${host} FAIL (HTTP ${http_code}); "
            allOK=false
          fi

        else
            # Original nc logic for host:port:proto
            IFS=',' read -r host port proto <<< "${entry}"
            # Default to TCP if protocol not specified
            if [[ "${proto}" =~ ^[Uu][Dd][Pp] ]]; then
                ncFlags=( -u -z -w "${networkTimeout}" )
            else
                ncFlags=( -z -w "${networkTimeout}" )
            fi

            if nc "${ncFlags[@]}" "${host}" "${port}" &>/dev/null; then
                results+="${host}:${port} PASS; "
            else
                results+="${host}:${port} FAIL; "
                allOK=false
            fi
        fi
    done

    if [[ "${allOK}" == true ]]; then
        dialogUpdate "listitem: index: ${index}, icon: SF=$(printf "%02d" $(($index+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Passed"
        info "${name}: ${results%;; }"
    else
        dialogUpdate "listitem: index: ${index}, icon: SF=$(printf "%02d" $(($index+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: Failed"
        errorOut "${name}: ${results%;; }"
        overallHealth+="${name}; "
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check the expiration date of the MDM Certificate (thanks, @isaacatmann!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkMdmCertificateExpiration() {

    case "${mdmVendor}" in
        "Addigy" )
            certificateName="Addigy"
            ;;
        "Filewave" )
            certificateName="Filewave"
            ;;
        "Fleet" )
            certificateName="Fleet Identity"
            ;;
        "Jamf Pro" )
            certificateName="JSS Built-in Certificate Authority"
            ;;
        "JumpCloud" )
            certificateName="JumpCloud"
            ;;
        "Kandji" )
            certificateName="Kandji"
            ;;
        "Microsoft Intune" )
            certificateName="Microsoft Intune MDM Device CA"
            ;;
        "Mosyle" )
            certificateName="MOSYLE CORPORATION"
            ;;
        * )
            return
            ;;
    esac

    local humanReadableCheckName="${mdmVendor} Certificate Authority"
    notice "Check the expiration date of the ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=mail.and.text.magnifyingglass,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining MDM Certificate expiration date …"

    sleep "${anticipationDuration}"

    expiry=$(security find-certificate -c "${certificateName}" -p /Library/Keychains/System.keychain 2>/dev/null | \
             openssl x509 -noout -enddate | cut -d= -f2)

    if [[ -z "$expiry" ]]; then
        expirationDateFormatted="NOT Installed"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${expirationDateFormatted}"
        errorOut "${humanReadableCheckName} Expiration: ${expirationDateFormatted}"
        overallHealth+="${humanReadableCheckName}; "
        return
    fi

    now_seconds=$(date +%s)
    date_seconds=$(date -j -f "%b %d %T %Y %Z" "$expiry" +%s)
    expirationDateFormatted=$(date -j -f "%b %d %H:%M:%S %Y GMT" "$expiry" "+%d-%b-%Y")

    if (( date_seconds > now_seconds )); then
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${expirationDateFormatted}"
        info "${humanReadableCheckName} Expiration: ${expirationDateFormatted}"
    else
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${expirationDateFormatted}"
        errorOut "${humanReadableCheckName} Expiration: ${expirationDateFormatted}"
        overallHealth+="${humanReadableCheckName}; "
    fi
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Last Jamf Pro Check-In (thanks, @jordywitteman!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkJamfProCheckIn() {

    local humanReadableCheckName="Last Jamf Pro check-in"
    notice "Checking ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=dot.radiowaves.left.and.right,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} …"

    sleep "${anticipationDuration}"

    # Number of seconds since action last occurred (86400 = 1 day)
    check_in_time_old=86400      # 1 day
    check_in_time_aging=28800    # 8 hours

    last_check_in_time=$(grep "Checking for policies triggered by \"recurring check-in\"" "/private/var/log/jamf.log" | tail -n 1 | awk '{ print $2,$3,$4 }')
    if [[ -z "${last_check_in_time}" ]]; then
        last_check_in_time=$( date "+%b %e %H:%M:%S" )
    fi

    # Convert last Jamf Pro check-in time to epoch
    last_check_in_time_epoch=$(date -j -f "%b %d %T" "${last_check_in_time}" +"%s")
    time_since_check_in_epoch=$(($currentTimeEpoch-$last_check_in_time_epoch))

    # Convert last Jamf Pro epoch to something easier to read
    eventDate=$( date -r "${last_check_in_time_epoch}" "+%Y-%m-%d" )
    todayDate=$( date "+%Y-%m-%d" )
    if [[ "${eventDate}" == "${todayDate}" ]]; then
        last_check_in_time_human_readable=$(date -r "${last_check_in_time_epoch}" "+%-l:%M %p" )
    else
        last_check_in_time_human_readable=$(date -r "${last_check_in_time_epoch}" "+%A %-l:%M %p")
    fi

    # Set status indicator for last check-in
    if [ ${time_since_check_in_epoch} -ge ${check_in_time_old} ]; then
        # check_in_status_indicator="🔴"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${last_check_in_time_human_readable}"
        errorOut "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
    elif [ ${time_since_check_in_epoch} -ge ${check_in_time_aging} ]; then
        # check_in_status_indicator="🟠"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${last_check_in_time_human_readable}"
        warning "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
    elif [ ${time_since_check_in_epoch} -lt ${check_in_time_aging} ]; then
        # check_in_status_indicator="🟢"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${last_check_in_time_human_readable}"
        info "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Last Jamf Pro Inventory Update (thanks, @jordywitteman!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkJamfProInventory() {

    local humanReadableCheckName="Last Jamf Pro inventory update"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=checklist,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} …"

    sleep "${anticipationDuration}"

    # Number of seconds since action last occurred (86400 = 1 day)
    inventory_time_old=604800    # 1 week
    inventory_time_aging=259200  # 3 days

    # Get last Jamf Pro inventory time from jamf.log
    last_inventory_time=$(grep "Removing existing launchd task /Library/LaunchDaemons/com.jamfsoftware.task.bgrecon.plist..." "/private/var/log/jamf.log" | tail -n 1 | awk '{ print $2,$3,$4 }')
    if [[ -z "${last_inventory_time}" ]]; then
        last_inventory_time=$( date "+%b %e %H:%M:%S" )
    fi
    
    # Convert last Jamf Pro inventory time to epoch
    last_inventory_time_epoch=$(date -j -f "%b %d %T" "${last_inventory_time}" +"%s")
    time_since_inventory_epoch=$(($currentTimeEpoch-$last_inventory_time_epoch))

    # Convert last Jamf Pro epoch to something easier to read
    eventDate=$( date -r "${last_inventory_time_epoch}" "+%Y-%m-%d" )
    todayDate=$( date "+%Y-%m-%d" )
    if [[ "${eventDate}" == "${todayDate}" ]]; then
        last_inventory_time_human_readable=$(date -r "${last_inventory_time_epoch}" "+%-l:%M %p" )
    else
        last_inventory_time_human_readable=$(date -r "${last_inventory_time_epoch}" "+%A %-l:%M %p")
    fi

    #set status indicator for last inventory
    if [ ${time_since_inventory_epoch} -ge ${inventory_time_old} ]; then
        # inventory_status_indicator="🔴"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${last_inventory_time_human_readable}"
        errorOut "${humanReadableCheckName}: ${last_inventory_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
    elif [ ${time_since_inventory_epoch} -ge ${inventory_time_aging} ]; then
        # inventory_status_indicator="🟠"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${last_inventory_time_human_readable}"
        warning "${humanReadableCheckName}: ${last_inventory_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
    elif [ ${time_since_inventory_epoch} -lt ${inventory_time_aging} ]; then
        # inventory_status_indicator="🟢"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${last_inventory_time_human_readable}"
        info "${humanReadableCheckName}: ${last_inventory_time_human_readable}"
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Last Mosyle Check-In (thanks, @precursorca!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkMosyleCheckIn() {

    local humanReadableCheckName="Last Mosyle check-in"
    notice "Checking ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=dot.radiowaves.left.and.right,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} …"

    sleep "${anticipationDuration}"

    # Number of seconds since action last occurred (86400 = 1 day)
    check_in_time_old=86400      # 1 day
    check_in_time_aging=28800    # 8 hours

	last_check_in_time=$(defaults read com.mosyle.macos.manager.mdm MacCommandsReplyResultsSuccessDate | cut -d. -f1)

    # Convert last Mosyle check-in time to epoch
    last_check_in_time_epoch=$last_check_in_time
    currentTimeEpoch=$(date +%s)
    time_since_check_in_epoch=$(($currentTimeEpoch-$last_check_in_time_epoch))

    # Convert last Mosyle epoch to something easier to read
    eventDate=$( date -r "${last_check_in_time_epoch}" "+%Y-%m-%d" )
    todayDate=$( date "+%Y-%m-%d" )
    if [[ "${eventDate}" == "${todayDate}" ]]; then
        last_check_in_time_human_readable=$(date -r "${last_check_in_time_epoch}" "+%-l:%M %p" )
    else
        last_check_in_time_human_readable=$(date -r "${last_check_in_time_epoch}" "+%A %-l:%M %p")
    fi

    # Set status indicator for last check-in
    if [ ${time_since_check_in_epoch} -ge ${check_in_time_old} ]; then
        # check_in_status_indicator="🔴"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${last_check_in_time_human_readable}"
        errorOut "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
    elif [ ${time_since_check_in_epoch} -ge ${check_in_time_aging} ]; then
        # check_in_status_indicator="🟠"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${last_check_in_time_human_readable}"
        warning "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
    elif [ ${time_since_check_in_epoch} -lt ${check_in_time_aging} ]; then
        # check_in_status_indicator="🟢"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${last_check_in_time_human_readable}"
        info "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check FileVault
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkFileVault() {

    local humanReadableCheckName="FileVault"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=lock.laptopcomputer,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    fileVaultCheck=$( fdesetup isactive )

    if [[ -f /Library/Preferences/com.apple.fdesetup.plist ]] || [[ "$fileVaultCheck" == "true" ]]; then

        fileVaultStatus=$( fdesetup status -extended -verbose 2>&1 )

        case ${fileVaultStatus} in

            *"FileVault is On."* ) 
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
                info "${humanReadableCheckName}: Enabled"
                ;;

            *"Deferred enablement appears to be active for user"* )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled (next login)"
                warning "${humanReadableCheckName}: Enabled (next login)"
                ;;

            *  )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#EB5545, iconalpha: 1, status: fail, statustext: Failed"
                errorOut "${humanReadableCheckName} (${1})"
                overallHealth+="${humanReadableCheckName}; "
                ;;

        esac

    else

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#EB5545, iconalpha: 1, status: fail, statustext: Failed"
        errorOut "${humanReadableCheckName} (${1})"
        overallHealth+="${humanReadableCheckName}; "

    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Internal Validation — Parameter 2: Target File; Parameter 3: Icon; Parameter 4: Display Name
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkInternal() {

    checkInternalTargetFile="${2}"
    checkInternalTargetFileIcon="${3}"
    checkInternalTargetFileDisplayName="${4}"

    notice "Internal Check: ${checkInternalTargetFile} …"

    dialogUpdate "icon: ${checkInternalTargetFileIcon}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining status of ${checkInternalTargetFileDisplayName} …"

    sleep "${anticipationDuration}"

    if [[ -e "${checkInternalTargetFile}" ]]; then

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Installed"
        info "${checkInternalTargetFileDisplayName} installed"
        
    else

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#EB5545, iconalpha: 1, status: fail, statustext: NOT Installed"
        errorOut "${checkInternalTargetFileDisplayName} NOT Installed"
        overallHealth+="${checkInternalTargetFileDisplayName}; "

    fi

    sleep "${anticipationDuration}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Touch ID Status (thanks, @alexfinn!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkTouchID() {

    local humanReadableCheckName="Touch ID"
    notice "Check ${humanReadableCheckName} …"
    
    dialogUpdate "icon: SF=touchid,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    # --- Detect Touch ID–capable hardware (internal or external) ---
    bioOutput=$(ioreg -l 2>/dev/null)

    # Check for the device entry indicating hardware presence
    if [[ $bioOutput == *"+-o AppleBiometricSensor"* ]]; then
        hw="Present"
    else
        # Fallback: Parse IOKitDiagnostics for class instance count
        if [[ $bioOutput =~ '"AppleBiometricSensor"=([0-9]+)' && ${match[1]} -gt 0 ]]; then
            hw="Present"
        # Fallback: Magic Keyboard with Touch ID
        elif system_profiler SPUSBDataType 2>/dev/null | grep -q "Magic Keyboard.*Touch ID"; then
            hw="Present"
        else
            hw="Absent"
        fi
    fi

    if [[ "${hw}" == "Absent" ]]; then

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${hw}"
        info "Touch ID hardware ${hw:l}"

    else

        # Enrollment check
        local enrolled="false"
        local bioCount="0"

        if command -v bioutil >/dev/null 2>&1; then
            bioCount=$(runAsUser bioutil -c 2>/dev/null | awk '/biometric template/{print $3}' | grep -Eo '^[0-9]+$' || echo "0")
            [[ "${bioCount}" -gt 0 ]] && enrolled="true"
        fi

        if [[ "${enrolled}" == "true" ]]; then
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enrolled (${bioCount})"
            info "Touch ID: Enabled & Enrolled (${bioCount})"
        else
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: Not enrolled"
            warning "Touch ID: Hardware present, not enrolled"
        fi

    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check VPN Installation
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkVPN() {

    notice "Check ${vpnAppName} …"

    dialogUpdate "icon: ${vpnAppPath}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining status of ${vpnAppName} …"

    # sleep "${anticipationDuration}"

    case ${vpnStatus} in

        *"NOT installed"* )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
            errorOut "${vpnAppName} Failed"
            overallHealth+="${vpnAppName}; "
            ;;

        *"Idle"* )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: Idle"
            info "${vpnAppName} idle"
            ;;

        "Connected"* | "${ciscoVPNIP}" )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Connected"
            info "${vpnAppName} Connected"
            ;;

        "Disconnected" )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: Disconnected"
            info "${vpnAppName} Disconnected"
            ;;

        "None" )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: No VPN"
            info "No VPN"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: Unknown"
            info "${vpnAppName} Unknown"
            ;;

    esac

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check External Jamf Pro Validation (where Parameter 2 represents the Jamf Pro Policy Custom Trigger)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkExternalJamfPro() {

    trigger="${2}"
    appPath="${3}"
    appDisplayName=$(basename "${appPath}" .app)

    if [[ -n $( defaults read "${organizationDefaultsDomain}" 2>/dev/null ) ]]; then
        defaults delete "${organizationDefaultsDomain}"
        # The defaults binary can be slow; give it a moment to catch-up
        sleep 0.5
    fi

    notice "External Check: ${appPath} …"

    dialogUpdate "icon: ${appPath}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining status of ${appDisplayName} …"

    externalValidation=$( jamf policy -event $trigger | grep "Script result:" )
    
    # Leverage the organization defaults domain
    if [[ -n $( defaults read "${organizationDefaultsDomain}" 2>/dev/null ) ]]; then

        checkStatus=$( defaults read "${organizationDefaultsDomain}" checkStatus )
        checkType=$( defaults read "${organizationDefaultsDomain}" checkType )
        checkExtended=$( defaults read "${organizationDefaultsDomain}" checkExtended )

        case ${checkType} in

            "fail" )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: $checkStatus"
                errorOut "${appDisplayName} Failed"
                overallHealth+="${appDisplayName}; "
                ;;

            "success" )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: $checkStatus"
                info "${appDisplayName} $checkStatus"
                ;;

            "error" | * )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: $checkStatus:$checkExtended"
                errorOut "${appDisplayName} Error:$checkExtended"
                overallHealth+="${appDisplayName}; "
                ;;

        esac

    # Ignore the organization defaults domain
    else

        case ${externalValidation:l} in

            *"failed"* )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
                errorOut "${appDisplayName} Failed"
                overallHealth+="${appDisplayName}; "
                ;;

            *"running"* )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Running"
                info "${appDisplayName} running"
                ;;

            *"error"* | * )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: Error"
                errorOut "${appDisplayName} Error"
                overallHealth+="${appDisplayName}; "
                ;;

        esac

    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Network Quality
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkNetworkQuality() {

    local humanReadableCheckName="Network Quality"
    notice "Check ${humanReadableCheckName} …"    

    dialogUpdate "icon: SF=gauge.with.dots.needle.67percent,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} …"

    # sleep "${anticipationDuration}"

    networkQualityTestFile="/var/tmp/networkQualityTest"

    if [[ -e "${networkQualityTestFile}" ]]; then

        networkQualityTestFileCreationEpoch=$( stat -f "%m" "${networkQualityTestFile}" )
        networkQualityTestMaximumEpoch=$( date -v-"${networkQualityTestMaximumAge}" +%s )

        if [[ "${networkQualityTestFileCreationEpoch}" -gt "${networkQualityTestMaximumEpoch}" ]]; then

            info "Using cached ${humanReadableCheckName} Test"
            testStatus="(cached)"

        else

            unset testStatus
            info "Removing cached result …"
            rm "${networkQualityTestFile}"
            info "Starting ${humanReadableCheckName} Test …"
            networkQuality -s -v -c > "${networkQualityTestFile}"
            info "Completed ${humanReadableCheckName} Test"

        fi

    else

        info "Starting ${humanReadableCheckName} Test …"
        networkQuality -s -v -c > "${networkQualityTestFile}"
        info "Completed ${humanReadableCheckName} Test"

    fi

    networkQualityTest=$( < "${networkQualityTestFile}" )

    case "${osVersion}" in

        11* ) 
            dlThroughput="N/A; macOS ${osVersion}"
            dlResponsiveness="N/A; macOS ${osVersion}"
            ;;

        * )
            dlThroughput=$( get_json_value "$networkQualityTest" "dl_throughput" )
            dlResponsiveness=$( get_json_value "$networkQualityTest" "dl_responsiveness" )
            ;;

    esac

    mbps=$( echo "scale=2; ( $dlThroughput / 1000000 )" | bc )
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, status: success, statustext: ${mbps} Mbps ${testStatus}"
    info "Download: ${mbps} Mbps, Responsiveness: ${dlResponsiveness}; "

    dialogUpdate "icon: ${icon}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Electron Apps for the macOS "Corner Mask" Slowdown Bug (Electron < 36.9.2 on macOS 26+)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkElectronCornerMask() {

    local humanReadableCheckName="Electron Corner Mask"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=cpu.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Scanning for Electron apps …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Checking installed Electron apps …"

    sleep "${anticipationDuration}"

    osMajorVersion=$( echo "${osVersion}" | awk -F '.' '{print $1}' )
    if [[ "${osMajorVersion}" -lt 26 ]]; then
        info "${humanReadableCheckName}: macOS ${osVersion} — not affected."
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Not affected (macOS ${osVersion})"
        return 0
    fi

    # Electron versions where the bug is fixed
    local fixedVersions=( "36.9.2" "37.6.0" "38.2.0" "39.0.0-alpha.7" )

    # Known-safe Electron apps and their verified runtime versions
    declare -A knownSafeElectronApps=(
        ["Visual Studio Code.app"]="37.6.0"
        ["Slack.app"]="38.2.0"
    )

    local foundElectronApps=0
    local vulnerableApps=()
    local safeApps=()

    setopt null_glob

    local appPaths=(
        /Applications/*.app
        /Applications/Utilities/*.app
        /Users/"${loggedInUser}"/Applications/*.app
    )

    for app in "${appPaths[@]}"; do
        [[ ! -d "${app}" ]] && continue
        local appName=$(basename "${app}")

        # If app is pre-known to be fixed, skip file scans
        if [[ -n "${knownSafeElectronApps[$appName]}" ]]; then
            local appVersion="${knownSafeElectronApps[$appName]}"
            ((foundElectronApps++))
            safeApps+=("${appName} (${appVersion}) [known fixed]")
            continue
        fi

        # Detect Electron Framework
        if grep -Rqs "Electron Framework" "${app}/Contents/Frameworks" 2>/dev/null; then
            ((foundElectronApps++))
            local appVersion="Unknown"

            local versionFile="${app}/Contents/Frameworks/Electron Framework.framework/Versions/Current/Resources/version"
            local frameworkPlist="${app}/Contents/Frameworks/Electron Framework.framework/Versions/Current/Resources/Info.plist"
            # Fallback to A if Current doesn't work (common in some bundles)
            if [[ ! -f "${frameworkPlist}" ]]; then
                frameworkPlist="${app}/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist"
            fi
            local pkgJson="${app}/Contents/Resources/app/package.json"
            local asarPkgJson="${app}/Contents/Resources/app.asar.unpacked/package.json"
            local productJson="${app}/Contents/Resources/app/product.json"
            local versionTxt="${app}/Contents/Resources/app/version.txt"

            # 1. Canonical Electron version file
            if [[ -f "${versionFile}" ]]; then
                appVersion=$(tr -d '[:space:]' < "${versionFile}")

            # 1a. Framework Info.plist (reliable for runtime version) – prioritize CFBundleVersion (common in Electron frameworks)
            elif [[ -f "${frameworkPlist}" ]]; then
                appVersion=$(defaults read "${frameworkPlist}" CFBundleVersion 2>/dev/null)
                if [[ -z "${appVersion}" ]]; then
                    appVersion=$(defaults read "${frameworkPlist}" CFBundleShortVersionString 2>/dev/null)
                fi
                # Debug: Uncomment for troubleshooting
                # if [[ -n "${appVersion}" ]]; then
                #     info "${humanReadableCheckName}: Detected Electron version ${appVersion} from framework plist for ${appName}"
                # else
                #     warning "${humanReadableCheckName}: Framework plist found but no version keys for ${appName}"
                # fi

            # 2. package.json electronVersion
            elif [[ -f "${pkgJson}" ]]; then
                appVersion=$(grep -Eo '"electronVersion"[^,]*' "${pkgJson}" | awk -F'"' '{print $4}')

            # 3. asar-unpacked package.json
            elif [[ -f "${asarPkgJson}" ]]; then
                appVersion=$(grep -Eo '"electronVersion"[^,]*' "${asarPkgJson}" | awk -F'"' '{print $4}')

            # 4. product.json (VS Code, Figma, Discord, etc.)
            elif [[ -f "${productJson}" ]]; then
                appVersion=$(grep -Eo '"version"[^,]*' "${productJson}" | awk -F'"' '{print $4}')
                if [[ ! "${appVersion}" =~ ^[0-9]+\.[0-9]+ ]]; then
                    local commit=$(grep -Eo '"commit"[^,]*' "${productJson}" | awk -F'"' '{print $4}')
                    [[ -n "${commit}" ]] && appVersion="custom-${commit:0:7}"
                fi

            # 5. version.txt fallback (Asana, Notion)
            elif [[ -f "${versionTxt}" ]]; then
                appVersion=$(tr -d '[:space:]' < "${versionTxt}")
            fi

            appVersion=$(echo "${appVersion}" | tr -cd '[:print:]' | xargs)

            # 6. If still unknown, fall back to CFBundleShortVersionString (app version, mark Electron as unknown)
            if [[ -z "${appVersion}" || "${appVersion}" == "Unknown" ]]; then
                appVersion=$(defaults read "${app}/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null)
                if [[ -z "${appVersion}" ]]; then
                    warning "${humanReadableCheckName}: ${appName} version unknown"
                    vulnerableApps+=("${appName} (version unknown)")
                else
                    warning "${humanReadableCheckName}: ${appName} Electron version unknown (app ${appVersion})"
                    vulnerableApps+=("${appName} (${appVersion//, /; })")
                fi
                continue
            fi

            # Compare Electron version to fixed thresholds
            local vulnerable=true
            for fixed in "${fixedVersions[@]}"; do
                if is-at-least "${fixed}" "${appVersion}"; then
                    vulnerable=false
                    break
                fi
            done

            if [[ "${vulnerable}" == true ]]; then
                vulnerableApps+=("${appName} (${appVersion})")
            else
                safeApps+=("${appName} (${appVersion})")
            fi
        fi
    done

    unsetopt null_glob

    # Reporting
    if [[ ${foundElectronApps} -eq 0 ]]; then
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: No Electron apps found"
        info "${humanReadableCheckName}: No Electron-based apps detected."
        return 0
    fi

    if [[ ${#vulnerableApps[@]} -gt 0 ]]; then
        local vulnerableList=$(printf '%s; ' "${vulnerableApps[@]}")
        vulnerableList="${vulnerableList%; }"
        info "vulnerableList: ${vulnerableList}"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, subtitle: ${vulnerableList}, status: error, statustext: Susceptible apps found"
        warning "${humanReadableCheckName}: Susceptible Electron apps detected — ${vulnerableList}"
        errorOut "${humanReadableCheckName}: ${vulnerableList}"
        overallHealth+="${humanReadableCheckName}; "
    else
        local safeList=$(printf '%s; ' "${safeApps[@]}")
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: All Electron apps patched"
        info "${humanReadableCheckName}: All Electron apps are running patched versions — ${safeList}"
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Bluetooth Sharing
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkBluetoothSharing() {

    local humanReadableCheckName="Bluetooth Sharing"
    notice "Checking ${humanReadableCheckName} status …"

    dialogUpdate "icon: SF=dot.radiowaves.left.and.right,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Evaluating ${humanReadableCheckName} setting …"

    sleep "${anticipationDuration}"
    
    # Check Bluetooth sharing settings using -currentHost as per macOS Security Compliance Project
    local result=$(runAsUser defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled 2>&1 | grep -v "Run" | tail -1)
    
    # If the key doesn't exist or is 0, Bluetooth sharing is disabled (compliant)
    if [[ "${result}" == "0" ]] || [[ "${result}" =~ "does not exist" ]]; then
        info "${humanReadableCheckName}: Disabled"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Disabled"
    else
        errorOut "${humanReadableCheckName}: Enabled (value: ${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: System Settings > General > Sharing > Accessories & Internet > Bluetooth Sharing > Disable, status: fail, statustext: Enabled"
        overallHealth+="${humanReadableCheckName}; "
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Password Hint
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkPasswordHint() {

    local humanReadableCheckName="Password Hint"
    notice "Checking ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=key.horizontal.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Evaluating ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"
    
    # Check for password hints using dscl as per macOS Security Compliance Project
    local hint=$(dscl . -read /Users/"${loggedInUser}" hint 2>/dev/null | awk '{$1=""; print $0}' | xargs)
    
    # If hint is empty, no password hint is set (compliant)
    if [[ -z "${hint}" ]]; then
        info "${humanReadableCheckName}: No hint set"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Compliant"
    else
        warning "${humanReadableCheckName}: Hint found"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: Found (Non-compliant)"
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check AirPlay Receiver (thanks, @bigdoodr!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkAirPlayReceiver() {

    local humanReadableCheckName="AirPlay Receiver"
    notice "Checking ${humanReadableCheckName} status …"

    dialogUpdate "icon: SF=airplayvideo.circle.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Evaluating ${humanReadableCheckName} configuration …"

    sleep "${anticipationDuration}"
    
    # Check AirPlay Receiver settings
    # Key names have changed across macOS versions:
    # - macOS 26.0: AirplayReceiverAdvertising
    # - macOS 26.1+: AirplayReceiverEnabled (correct spelling)
    # - Older versions: AirplayRecieverEnabled (misspelled)
    
    local result=""
    local keyFound=""
    
    # Try the new correctly-spelled key first (macOS 26.1+)
    result=$(runAsUser /usr/bin/defaults -currentHost read com.apple.controlcenter AirplayReceiverEnabled 2>&1 | grep -v "Run" | tail -1)
    if [[ ! "${result}" =~ "does not exist" ]]; then
        keyFound="AirplayReceiverEnabled"
    else
        # Try the misspelled key (older versions)
        result=$(runAsUser /usr/bin/defaults -currentHost read com.apple.controlcenter AirplayRecieverEnabled 2>&1 | grep -v "Run" | tail -1)
        if [[ ! "${result}" =~ "does not exist" ]]; then
            keyFound="AirplayRecieverEnabled"
        else
            # Try the advertising key (macOS 26.0)
            result=$(runAsUser /usr/bin/defaults -currentHost read com.apple.controlcenter AirplayReceiverAdvertising 2>&1 | grep -v "Run" | tail -1)
            if [[ ! "${result}" =~ "does not exist" ]]; then
                keyFound="AirplayReceiverAdvertising"
            fi
        fi
    fi
    
    # Evaluate the result
    if [[ -z "${keyFound}" ]] || [[ "${result}" =~ "does not exist" ]]; then
        # No key found:
        # - On macOS 15.7.x, this now means "Enabled" (default)
        # - On macOS 15.6.1 and earlier, and on 26.x, your tests show the key
        #   exists and holds 0/1, so "no key" is a safe "Disabled" fallback.
        if [[ "${osMajorVersion}" -eq 15 && "${osMinorVersion}" -ge 7 ]]; then
            # 15.7.x: assume Enabled when key is missing
            errorOut "${humanReadableCheckName}: Enabled (no ${keyFound:-AirplayReceiverEnabled} key; default behavior on macOS ${osMajorVersion}.${osMinorVersion})"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: System Settings > General > AirDrop & Handoff > AirPlay Receiver > Disable, status: fail, statustext: Enabled"
            overallHealth+="${humanReadableCheckName}; "
        else
            # 15.6.1 and earlier, and 26.x+: missing key treated as Disabled/compliant
            info "${humanReadableCheckName}: Disabled (key not found on macOS ${osMajorVersion}.${osMinorVersion})"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Disabled"
        fi

    elif [[ "${result}" == "0" ]]; then
        # Value is 0, disabled (compliant)
        info "${humanReadableCheckName}: Disabled (${keyFound}=${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Disabled"

    elif [[ "${result}" == "1" ]]; then
        # Value is 1, enabled (non-compliant)
        errorOut "${humanReadableCheckName}: Enabled (${keyFound}=${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: System Settings > General > AirDrop & Handoff > AirPlay Receiver > Disable, status: fail, statustext: Enabled"
        overallHealth+="${humanReadableCheckName}; "

    elif [[ "${result}" == "2" ]]; then
        # Value is 2 (Contacts Only mode in some versions)
        info "${humanReadableCheckName}: Contacts Only (${keyFound}=${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Contacts Only"

    else
        # Unexpected value
        warning "${humanReadableCheckName}: Unexpected value (${keyFound}=${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#F8D84A, iconalpha: 1, subtitle: System Settings > General > AirDrop & Handoff > AirPlay Receiver > Disable, status: error, statustext: Status Unknown"
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check AirDrop
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkAirDropSettings() {

    local humanReadableCheckName="AirDrop Settings"
    notice "Checking ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=airplayaudio.circle.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} …"

    sleep "${anticipationDuration}"
    
    # Check AirDrop settings
    local result=$(runAsUser defaults read /Users/"${loggedInUser}"/Library/Preferences/com.apple.sharingd.plist DiscoverableMode 2>&1 | grep -v "Run" | tail -1)
    
    if [[ "${result}" != "Everyone" ]] || [[ -z "${result}" ]]; then
        info "${humanReadableCheckName}: Compliant"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Compliant"
    else
        errorOut "${humanReadableCheckName}: Discoverable by Everyone (value: ${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=#EB5545, iconalpha: 1, subtitle: System Settings > General > AirDrop & Handoff > AirDrop > No One / Contacts Only, status: fail, statustext: Everyone"
        overallHealth+="${humanReadableCheckName}; "
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update Computer Inventory
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function updateComputerInventory() {

    notice "Updating Computer Inventory …"

    dialogUpdate "icon: SF=pencil.and.list.clipboard,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Updating …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Updating Computer Inventory …"

    if [[ "${operationMode}" != "Test" ]]; then

        if [[ -n "${platformSSOeResult}" ]]; then
            jamf recon -endUsername "${platformSSOeResult}"
        else
            jamf recon # -verbose
        fi

    else

        sleep "${anticipationDuration}"

    fi

    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: Latest computer inventory submitted at $( date '+%d-%b-%Y %H:%M:%S' ), status: success, statustext: Updated"

}



####################################################################################################
#
# Program
#
####################################################################################################

notice "Current Elapsed Time: $(printf '%dh:%dm:%ds\n' $((SECONDS/3600)) $((SECONDS%3600/60)) $((SECONDS%60)))"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Generate dialogJSONFile based on Operation Mode and MDM Vendor
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${operationMode}" == "Development" ]]; then
    
    notice "Operation Mode is ${operationMode}; using ${operationMode} dialogJSONFile template."

    # Development List Items

    developmentListitemJSON='
    [
        {"title" : "App Auto-Patch", "subtitle" : "Keep your apps up-to-date to ensure their security and performance", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
    ]
    '
    # Validate developmentListitemJSON is valid JSON
    if ! echo "$developmentListitemJSON" | jq . >/dev/null 2>&1; then
        echo "Error: developmentListitemJSON is invalid JSON"
        echo "$developmentListitemJSON"
        exit 1
    else
        combinedJSON=$( jq -n --argjson dialog "$mainDialogJSON" --argjson listitems "$developmentListitemJSON" '$dialog + { "listitem": $listitems }' )
    fi

else

    notice "Operation Mode is ${operationMode}; using MDM-specific dialogJSONFile."

    case ${mdmVendor} in

        "Addigy"            ) combinedJSON=$( jq -n --argjson dialog "$mainDialogJSON" --argjson listitems "$addigyMdmListitemJSON" '$dialog + { "listitem": $listitems }' ) ;;
        "Filewave"          ) combinedJSON=$( jq -n --argjson dialog "$mainDialogJSON" --argjson listitems "$filewaveMdmListitemJSON" '$dialog + { "listitem": $listitems }' ) ;;
        "Fleet"             ) combinedJSON=$( jq -n --argjson dialog "$mainDialogJSON" --argjson listitems "$fleetMdmListitemJSON" '$dialog + { "listitem": $listitems }' ) ;;
        "Jamf Pro"          ) combinedJSON=$( jq -n --argjson dialog "$mainDialogJSON" --argjson listitems "$jamfProListitemJSON" '$dialog + { "listitem": $listitems }' ) ;;
        "JumpCloud"         ) combinedJSON=$( jq -n --argjson dialog "$mainDialogJSON" --argjson listitems "$jumpcloudMdmListitemJSON" '$dialog + { "listitem": $listitems }' ) ;;
        "Kandji"            ) combinedJSON=$( jq -n --argjson dialog "$mainDialogJSON" --argjson listitems "$kandjiMdmListitemJSON" '$dialog + { "listitem": $listitems }' ) ;;
        "Microsoft Intune"  ) combinedJSON=$( jq -n --argjson dialog "$mainDialogJSON" --argjson listitems "$microsoftMdmListitemJSON" '$dialog + { "listitem": $listitems }' ) ;;
        "Mosyle"            ) combinedJSON=$( jq -n --argjson dialog "$mainDialogJSON" --argjson listitems "$mosyleListitemJSON" '$dialog + { "listitem": $listitems }' ) ;;
        *                   ) warning "Unknown MDM vendor: ${mdmVendor}" ; combinedJSON=$( jq -n --argjson dialog "$mainDialogJSON" --argjson listitems "$genericMdmListitemJSON" '$dialog + { "listitem": $listitems }' ) ;;

    esac

fi

echo "$combinedJSON" > "$dialogJSONFile"

# Set Permissions on dialogJSONFile
chmod 644 "${dialogJSONFile}"

# Verify dialogJSONFile exists and is readable
retryCount=0
maxRetries=5
while [[ ! -f "${dialogJSONFile}" || ! -r "${dialogJSONFile}" ]] && [[ ${retryCount} -lt ${maxRetries} ]]; do
    sleep 0.2
    ((retryCount++))
done
if [[ ! -f "${dialogJSONFile}" || ! -r "${dialogJSONFile}" ]]; then
    fatal "dialogJSONFile (${dialogJSONFile}) is not readable after ${maxRetries} attempts"
else
    info "dialogJSONFile verified: ${dialogJSONFile}"
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Create Dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${operationMode}" != "Silent" ]]; then

    eval ${dialogBinary} --jsonfile ${dialogJSONFile} &
    dialogPID=$!
    info "Dialog PID: ${dialogPID}"
    dialogUpdate "progresstext: Initializing …"

    # Band-Aid for macOS 15+ `withAnimation` SwiftUI bug
    dialogUpdate "list: hide"
    dialogUpdate "list: show"

else

    notice "Operation Mode is 'Silent'; not displaying dialog."

fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Generate Health Checks based on Operation Mode and MDM Vendor (where "n" represents the listitem order)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${operationMode}" == "Development" ]]; then
    
    # Operation Mode: Development
    notice "Operation Mode is ${operationMode}; using ${operationMode}-specific Health Check."
    dialogUpdate "title: ${humanReadableScriptName} (${scriptVersion})<br>Operation Mode: ${operationMode}"
    set -x
    checkAppAutoPatch "0"
    set +x

else

    notice "Operation Mode is ${operationMode}; using MDM-specific Health Checks."

    if [[ "${operationMode}" != "Test" ]]; then

        # Operation Mode: Debug
        if [[ "${operationMode}" == "Debug" ]]; then
            dialogUpdate "title: ${humanReadableScriptName} (${scriptVersion})<br>Operation Mode: ${operationMode}"
        fi

        # Operation Mode: Self Service 
        case ${mdmVendor} in

            "Addigy" )
                checkOS "0"
                checkAvailableSoftwareUpdates "1"
                checkAppAutoPatch "2"
                checkSIP "3"
                checkSSV "4"
                checkFirewall "5"
                checkFileVault "6"
                checkGatekeeperXProtect "7"
                checkTouchID "8"
                checkVPN "9"
                checkUptime "10"
                checkFreeDiskSpace "11"
                checkUserDirectorySizeItems "12" "Desktop" "desktopcomputer.and.macbook" "Desktop"
                checkUserDirectorySizeItems "13" "Downloads" "arrow.down.circle.fill" "Downloads"
                checkUserDirectorySizeItems "14" ".Trash" "trash.fill" "Trash"
                checkPasswordHint "15"
                checkAirDropSettings "16"
                checkAirPlayReceiver "17"
                checkBluetoothSharing "18"
                checkMdmProfile "19"
                checkMdmCertificateExpiration "20"
                checkAPNs "21"
                checkNetworkHosts "22" "Apple Push Notification Hosts"         "${pushHosts[@]}"
                checkNetworkHosts "23" "Apple Device Management"               "${deviceMgmtHosts[@]}"
                checkNetworkHosts "24" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
                checkNetworkHosts "25" "Apple Certificate Validation"          "${certHosts[@]}"
                checkNetworkHosts "26" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
                checkInternal "27" "/Applications/Microsoft Teams.app" "/Applications/Microsoft Teams.app" "Microsoft Teams"
                checkElectronCornerMask "28"
                checkNetworkQuality "29"
                ;;

            "Filewave" )
                checkOS "0"
                checkAvailableSoftwareUpdates "1"
                checkAppAutoPatch "2"
                checkSIP "3"
                checkSSV "4"
                checkFirewall "5"
                checkFileVault "6"
                checkGatekeeperXProtect "7"
                checkTouchID "8"
                checkVPN "9"
                checkUptime "10"
                checkFreeDiskSpace "11"
                checkUserDirectorySizeItems "12" "Desktop" "desktopcomputer.and.macbook" "Desktop"
                checkUserDirectorySizeItems "13" "Downloads" "arrow.down.circle.fill" "Downloads"
                checkUserDirectorySizeItems "14" ".Trash" "trash.fill" "Trash"
                checkPasswordHint "15"
                checkAirDropSettings "16"
                checkAirPlayReceiver "17"
                checkBluetoothSharing "18"
                checkMdmProfile "19"
                checkMdmCertificateExpiration "20"
                checkAPNs "21"
                checkNetworkHosts "22" "Apple Push Notification Hosts"         "${pushHosts[@]}"
                checkNetworkHosts "23" "Apple Device Management"               "${deviceMgmtHosts[@]}"
                checkNetworkHosts "24" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
                checkNetworkHosts "25" "Apple Certificate Validation"          "${certHosts[@]}"
                checkNetworkHosts "26" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
                checkElectronCornerMask "27"
                checkNetworkQuality "28"
                ;;

            "Fleet" )
                checkOS "0"
                checkAvailableSoftwareUpdates "1"
                checkAppAutoPatch "2"
                checkSIP "3"
                checkSSV "4"
                checkFirewall "5"
                checkFileVault "6"
                checkGatekeeperXProtect "7"
                checkTouchID "8"
                checkVPN "9"
                checkUptime "10"
                checkFreeDiskSpace "11"
                checkUserDirectorySizeItems "12" "Desktop" "desktopcomputer.and.macbook" "Desktop"
                checkUserDirectorySizeItems "13" "Downloads" "arrow.down.circle.fill" "Downloads"
                checkUserDirectorySizeItems "14" ".Trash" "trash.fill" "Trash"
                checkPasswordHint "15"
                checkAirDropSettings "16"
                checkAirPlayReceiver "17"
                checkBluetoothSharing "18"
                checkMdmProfile "19"
                checkMdmCertificateExpiration "20"
                checkAPNs "21"
                checkNetworkHosts "22" "Apple Push Notification Hosts"         "${pushHosts[@]}"
                checkNetworkHosts "23" "Apple Device Management"               "${deviceMgmtHosts[@]}"
                checkNetworkHosts "24" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
                checkNetworkHosts "25" "Apple Certificate Validation"          "${certHosts[@]}"
                checkNetworkHosts "26" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
                checkInternal "27" "/opt/orbit/bin/desktop/macos/stable/Fleet Desktop.app" "/opt/orbit/bin/desktop/macos/stable/Fleet Desktop.app" "Fleet Desktop"
                checkElectronCornerMask "28"
                checkNetworkQuality "29"
                ;;

            "Jamf Pro" )
                checkOS "0"
                checkAvailableSoftwareUpdates "1"
                checkSIP "2"
                checkSSV "3"
                checkFirewall "4"
                checkFileVault "5"
                checkGatekeeperXProtect "6"
                checkTouchID "7"
                checkPasswordHint "8"
                checkAirDropSettings "9"
                checkAirPlayReceiver "10"
                checkBluetoothSharing "11"
                checkVPN "12"
                checkUptime "13"
                checkFreeDiskSpace "14"
                checkUserDirectorySizeItems "15" "Desktop" "desktopcomputer.and.macbook" "Desktop"
                checkUserDirectorySizeItems "16" "Downloads" "arrow.down.circle.fill" "Downloads"
                checkUserDirectorySizeItems "17" ".Trash" "trash.fill" "Trash"
                checkMdmProfile "18"
                checkMdmCertificateExpiration "19"
                checkAPNs "20"
                checkJamfProCheckIn "21"
                checkJamfProInventory "22"
                checkNetworkHosts  "23" "Apple Push Notification Hosts"         "${pushHosts[@]}"
                checkNetworkHosts  "24" "Apple Device Management"               "${deviceMgmtHosts[@]}"
                checkNetworkHosts  "25" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
                checkNetworkHosts  "26" "Apple Certificate Validation"          "${certHosts[@]}"
                checkNetworkHosts  "27" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
                checkNetworkHosts  "28" "Jamf Hosts"                            "${jamfHosts[@]}"
                checkAppAutoPatch "29"
                checkElectronCornerMask "30"
                checkInternal "31" "/Applications/Microsoft Teams.app" "/Applications/Microsoft Teams.app" "Microsoft Teams"
                checkExternalJamfPro "32" "symvBeyondTrustPMfM"        "/Applications/PrivilegeManagement.app"
                checkExternalJamfPro "33" "symvCiscoUmbrella"          "/Applications/Cisco/Cisco Secure Client.app"
                checkExternalJamfPro "34" "symvCrowdStrikeFalcon"      "/Applications/Falcon.app"
                checkExternalJamfPro "35" "symvGlobalProtect"          "/Applications/GlobalProtect.app"
                checkNetworkQuality "36"
                updateComputerInventory "37"
                ;;

            "JumpCloud" )
                checkOS "0"
                checkAvailableSoftwareUpdates "1"
                checkAppAutoPatch "2"
                checkSIP "3"
                checkSSV "4"
                checkFirewall "5"
                checkFileVault "6"
                checkGatekeeperXProtect "7"
                checkTouchID "8"
                checkVPN "9"
                checkUptime "10"
                checkFreeDiskSpace "11"
                checkUserDirectorySizeItems "12" "Desktop" "desktopcomputer.and.macbook" "Desktop"
                checkUserDirectorySizeItems "13" "Downloads" "arrow.down.circle.fill" "Downloads"
                checkUserDirectorySizeItems "14" ".Trash" "trash.fill" "Trash"
                checkPasswordHint "15"
                checkAirDropSettings "16"
                checkAirPlayReceiver "17"
                checkBluetoothSharing "18"
                checkMdmProfile "19"
                checkMdmCertificateExpiration "20"
                checkAPNs "21"
                checkNetworkHosts "22" "Apple Push Notification Hosts"         "${pushHosts[@]}"
                checkNetworkHosts "23" "Apple Device Management"               "${deviceMgmtHosts[@]}"
                checkNetworkHosts "24" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
                checkNetworkHosts "25" "Apple Certificate Validation"          "${certHosts[@]}"
                checkNetworkHosts "26" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
                checkInternal "27" "/Applications/Microsoft Teams.app" "/Applications/Microsoft Teams.app" "Microsoft Teams"
                checkElectronCornerMask "28"
                checkNetworkQuality "29"
                ;;

            "Kandji" )
                checkOS "0"
                checkAvailableSoftwareUpdates "1"
                checkAppAutoPatch "2"
                checkSIP "3"
                checkSSV "4"
                checkFirewall "5"
                checkFileVault "6"
                checkGatekeeperXProtect "7"
                checkTouchID "8"
                checkVPN "9"
                checkUptime "10"
                checkFreeDiskSpace "11"
                checkUserDirectorySizeItems "12" "Desktop" "desktopcomputer.and.macbook" "Desktop"
                checkUserDirectorySizeItems "13" "Downloads" "arrow.down.circle.fill" "Downloads"
                checkUserDirectorySizeItems "14" ".Trash" "trash.fill" "Trash"
                checkPasswordHint "15"
                checkAirDropSettings "16"
                checkAirPlayReceiver "17"
                checkBluetoothSharing "18"
                checkMdmProfile "19"
                checkMdmCertificateExpiration "20"
                checkAPNs "21"
                checkNetworkHosts "22" "Apple Push Notification Hosts"         "${pushHosts[@]}"
                checkNetworkHosts "23" "Apple Device Management"               "${deviceMgmtHosts[@]}"
                checkNetworkHosts "24" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
                checkNetworkHosts "25" "Apple Certificate Validation"          "${certHosts[@]}"
                checkNetworkHosts "26" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
                checkInternal "27" "/Applications/Microsoft Teams.app" "/Applications/Microsoft Teams.app" "Microsoft Teams"
                checkElectronCornerMask "28"
                checkNetworkQuality "29"
                ;;

            "Microsoft Intune" )
                checkOS "0"
                checkAvailableSoftwareUpdates "1"
                checkAppAutoPatch "2"
                checkSIP "3"
                checkSSV "4"
                checkFirewall "5"
                checkFileVault "6"
                checkGatekeeperXProtect "7"
                checkTouchID "8"
                checkVPN "9"
                checkUptime "10"
                checkFreeDiskSpace "11"
                checkUserDirectorySizeItems "12" "Desktop" "desktopcomputer.and.macbook" "Desktop"
                checkUserDirectorySizeItems "13" "Downloads" "arrow.down.circle.fill" "Downloads"
                checkUserDirectorySizeItems "14" ".Trash" "trash.fill" "Trash"
                checkPasswordHint "15"
                checkAirDropSettings "16"
                checkAirPlayReceiver "17"
                checkBluetoothSharing "18"
                checkMdmProfile "19"
                checkMdmCertificateExpiration "20"
                checkAPNs "21"
                checkNetworkHosts "22" "Apple Push Notification Hosts"         "${pushHosts[@]}"
                checkNetworkHosts "23" "Apple Device Management"               "${deviceMgmtHosts[@]}"
                checkNetworkHosts "24" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
                checkNetworkHosts "25" "Apple Certificate Validation"          "${certHosts[@]}"
                checkNetworkHosts "26" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
                checkInternal "27" "/Applications/Company Portal.app" "/Applications/Company Portal.app" "Microsoft Company Portal"
                checkElectronCornerMask "28"
                checkNetworkQuality "29"
                ;;

            "Mosyle" )
                checkOS "0"
                checkAvailableSoftwareUpdates "1"
                checkAppAutoPatch "2"
                checkSIP "3"
                checkSSV "4"
                checkFirewall "5"
                checkFileVault "6"
                checkGatekeeperXProtect "7"
                checkTouchID "8"
                checkVPN "9"
                checkUptime "10"
                checkFreeDiskSpace "11"
                checkUserDirectorySizeItems "12" "Desktop" "desktopcomputer.and.macbook" "Desktop"
                checkUserDirectorySizeItems "13" "Downloads" "arrow.down.circle.fill" "Downloads"
                checkUserDirectorySizeItems "14" ".Trash" "trash.fill" "Trash"
                checkPasswordHint "15"
                checkAirDropSettings "16"
                checkAirPlayReceiver "17"
                checkBluetoothSharing "18"
                checkMdmProfile "19"
                checkMdmCertificateExpiration "20"
                checkAPNs "21"
                checkMosyleCheckIn "22"
                checkNetworkHosts "23" "Apple Push Notification Hosts"         "${pushHosts[@]}"
                checkNetworkHosts "24" "Apple Device Management"               "${deviceMgmtHosts[@]}"
                checkNetworkHosts "25" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
                checkNetworkHosts "26" "Apple Certificate Validation"          "${certHosts[@]}"
                checkNetworkHosts "27" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
                checkInternal "28" "/Applications/Self-Service.app" "/Applications/Self-Service.app" "Self-Service"
                checkElectronCornerMask "29"
                checkNetworkQuality "30"
                ;;

            * )
                checkOS "0"
                checkAvailableSoftwareUpdates "1"
                checkSIP "2"
                checkSSV "3"
                checkFirewall "4"
                checkFileVault "5"
                checkGatekeeperXProtect "6"
                checkTouchID "7"
                checkVPN "8"
                checkUptime "9"
                checkFreeDiskSpace "10"
                checkUserDirectorySizeItems "11" "Desktop" "desktopcomputer.and.macbook" "Desktop"
                checkUserDirectorySizeItems "12" "Downloads" "arrow.down.circle.fill" "Downloads"
                checkUserDirectorySizeItems "13" ".Trash" "trash.fill" "Trash"
                checkPasswordHint "14"
                checkAirDropSettings "15"
                checkAirPlayReceiver "16"
                checkBluetoothSharing "17"
                checkAPNs "18"
                checkNetworkHosts "19" "Apple Push Notification Hosts"         "${pushHosts[@]}"
                checkNetworkHosts "20" "Apple Device Management"               "${deviceMgmtHosts[@]}"
                checkNetworkHosts "21" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
                checkNetworkHosts "22" "Apple Certificate Validation"          "${certHosts[@]}"
                checkNetworkHosts "23" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
                checkElectronCornerMask "24"
                checkNetworkQuality "25"
                ;;
        
        esac

        dialogUpdate "icon: ${icon}"
        dialogUpdate "progresstext: Final Analysis …"

        sleep "${anticipationDuration}"

    else

        # Operation Mode: Test
        dialogUpdate "title: ${humanReadableScriptName} (${scriptVersion})<br>Operation Mode: ${operationMode}"
        listitemLength=$(get_json_value "${combinedJSON}" "listitem.length")

        for (( i=0; i<listitemLength; i++ )); do
            notice "[Operation Mode: ${operationMode}] Check ${i} …"
            dialogUpdate "icon: SF=$(printf "%02d" $(($i+1))).square,${organizationColorScheme}"
            dialogUpdate "listitem: index: ${i}, icon: SF=$(printf "%02d" $(($i+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
            dialogUpdate "progress: increment"
            dialogUpdate "progresstext: [Operation Mode: ${operationMode}] • Item No. ${i} …"
            # sleep "${anticipationDuration}"
            dialogUpdate "listitem: index: ${i}, icon: SF=$(printf "%02d" $(($i+1))).circle.fill weight=semibold colour=#63CA56, iconalpha: 0.6, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${operationMode}"
        done

        dialogUpdate "icon: ${icon}"
        dialogUpdate "progresstext: Final Analysis …"

        sleep "${anticipationDuration}"

    fi

fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Quit Script
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

quitScript
