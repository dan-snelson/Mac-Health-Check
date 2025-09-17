#!/bin/zsh --no-rcs
# shellcheck shell=bash

####################################################################################################
#
# Mac Health Check
#
# A practical and user-friendly approach to surfacing Mac compliance information directly to end-users
# via Jamf Pro Self Service
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
# Version 2.4.0, 17-Sep-2025, Dan K. Snelson (@dan-snelson)
#   - Updated SSID code (thanks, ZP!)
#   - Added troubleshooting code for common JSON issues
#   - Additional troubleshooting tweaks
#   - Updates to leverage new features of swiftDialog 3.0.0
#   - Updated listitem icon colour to reflect status
#   - Updated checkOS function
#
####################################################################################################



####################################################################################################
#
# Global Variables
#
####################################################################################################

export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin/

# Script Version
scriptVersion="2.4.0b8"

# Client-side Log
scriptLog="/var/log/org.churchofjesuschrist.log"

# Elapsed Time
SECONDS="0"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Jamf Pro Script Paramters
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Paramter 4: Operation Mode [ test | debug | production ]
operationMode="${4:-"test"}"

    # Enable `set -x` if operation mode is "debug" to help identify variable initialization issues (i.e., SSID)
    [[ "${operationMode}" == "debug" ]] && set -x

# Parameter 5: Microsoft Teams or Slack Webhook URL [ Leave blank to disable (default) | https://microsoftTeams.webhook.com/URL | https://hooks.slack.com/services/URL ]
webhookURL="${5:-""}"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Organization Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Script Human-readable Name
humanReadableScriptName="Mac Health Check"

# Organization's Script Name
organizationScriptName="MHC"

# Organization's Branding Banner URL
organizationBrandingBannerURL="https://img.freepik.com/free-photo/abstract-smooth-orange-background-layout-designstudioroom-web-template-business-report-with-smooth-c_1258-54783.jpg" # [Image by benzoix on Freepik](https://www.freepik.com/author/benzoix)

# Organization's Overlayicon URL
organizationOverlayiconURL=""

# Organization's Color Scheme
organizationColorScheme="weight=semibold,colour1=#ef9d51,colour2=#ef7951"

# Organization's Kerberos Realm (leave blank to disable check)
kerberosRealm=""

# Organization's Firewall Type [ socketfilterfw | pf ]
organizationFirewall="socketfilterfw"

# Organization's VPN client type [ none | paloalto | cisco | tailscale ]
vpnClientVendor="paloalto"

# Organization's VPN data type [ basic | extended ]
vpnClientDataType="extended"

# "Anticipation" Duration (in seconds)
anticipationDuration="2"

# How many previous minor OS versions will be marked as compliant
previousMinorOS="2"

# Allowed minimum percentage of free disk space
allowedMinimumFreeDiskPercentage="10"

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
# Jamf Pro Configuration Profile Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Organization's Client-side Jamf Pro Variables
jamfProVariables="org.churchofjesuschrist.jamfprovariables.plist"

# Property List File
plistFilepath="/Library/Managed Preferences/${jamfProVariables}"

if [[ -e "${plistFilepath}" ]]; then

    # Jamf Pro ID
    jamfProID=$( defaults read "${plistFilepath}" "Jamf Pro ID" 2>/dev/null )

    # Site Name
    jamfProSiteName=$( defaults read "${plistFilepath}" "Site Name" 2>/dev/null )

fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Computer Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

osVersion=$( sw_vers -productVersion )
osVersionExtra=$( sw_vers -productVersionExtra ) 
osBuild=$( sw_vers -buildVersion )
osMajorVersion=$( echo "${osVersion}" | awk -F '.' '{print $1}' )
if [[ -n $osVersionExtra ]] && [[ "${osMajorVersion}" -ge 13 ]]; then osVersion="${osVersion} ${osVersionExtra}"; fi
serialNumber=$( ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformSerialNumber/{print $4}' )
computerName=$( scutil --get ComputerName | sed 's/’//' )
computerModel=$( sysctl -n hw.model )
localHostName=$( scutil --get LocalHostName )
batteryCycleCount=$( ioreg -r -c "AppleSmartBattery" | grep '"CycleCount" = ' | awk '{ print $3 }' | sed s/\"//g )
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
    /bin/rm -f /var/tmp/app-sso.plist
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
        globalProtectTunnelStatus=$( /usr/libexec/PlistBuddy -c "Print :'Palo Alto Networks':GlobalProtect:DEM:'tunnel-status'" /Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist )
        case "$globalProtectTunnelStatus" in
            "connected"* | "internal" )
                globalProtectVpnIP=$( /usr/libexec/PlistBuddy -c 'Print :"Palo Alto Networks":GlobalProtect:DEM:"tunnel-ip"' /Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist 2>/dev/null | sed -nE 's/.*ipv4=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*/\1/p' )
                vpnStatus="Connected ${globalProtectVpnIP}"
                if [[ "${vpnClientDataType}" == "extended" ]]; then
                    globalProtectUserResult=$( defaults read /Users/${loggedInUser}/Library/Preferences/com.paloaltonetworks.GlobalProtect.client User 2>&1 )
                    if [[ "${globalProtectUserResult}"  == *"Does Not Exist" || -z "${globalProtectUserResult}" ]]; then
                        globalProtectUserResult="${loggedInUser} NOT logged-in"
                    elif [[ ! -z "${globalProtectUserResult}" ]]; then
                        globalProtectUserResult="\"${loggedInUser}\" logged-in"
                    fi
                    vpnExtendedStatus="${globalProtectUserResult}"
                fi
                ;;
            "disconnected" )
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
[[ "${operationMode}" == "debug" ]] && dialogBinary="${dialogBinary} --verbose --resizable --debug red"

# swiftDialog JSON File
dialogJSONFile=$( mktemp -u /var/tmp/dialogJSONFile_${organizationScriptName}.XXXX )

# swiftDialog Command File
dialogCommandFile=$( mktemp /var/tmp/dialogCommandFile_${organizationScriptName}.XXXX )

# Set Permissions on Dialog Command Files
chmod 644 "${dialogCommandFile}"

# The total number of steps for the progress bar, plus two (i.e., "progress: increment")
progressSteps="27"

# Set initial icon based on whether the Mac is a desktop or laptop
if system_profiler SPPowerDataType | grep -q "Battery Power"; then
    icon="SF=laptopcomputer.and.arrow.down,${organizationColorScheme}"
else
    icon="SF=desktopcomputer.and.arrow.down,${organizationColorScheme}"
fi

# Download the overlayicon from ${organizationOverlayiconURL}
curl -o "/var/tmp/overlayicon.png" "${organizationOverlayiconURL}" --silent --show-error --fail
if [[ "$?" -ne 0 ]]; then
    echo "Error: Failed to download the overlayicon from '${brandingImageURL}'."
    overlayicon="/System/Library/CoreServices/Finder.app"
else
    overlayicon="/var/tmp/overlayicon.png"
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

helpmessage="For assistance, please contact: **${supportTeamName}**<br>- **Telephone:** ${supportTeamPhone}<br>- **Email:** ${supportTeamEmail}<br>- **Website:** ${supportTeamWebsite}<br>- **Knowledge Base Article:** ${supportKBURL}<br><br>**User Information:**<br>- **Full Name:** ${loggedInUserFullname}<br>- **User Name:** ${loggedInUser}<br>- **User ID:** ${loggedInUserID}<br>- **Secure Token:** ${secureToken}<br>- **Location Services:** ${locationServicesStatus}<br>- **Microsoft OneDrive Sync Date:** ${oneDriveSyncDate}<br>- **Platform SSOe:** ${platformSSOeResult}<br><br>**Computer Information:**<br>- **macOS:** ${osVersion} (${osBuild})<br>- **Dialog:** $(dialog -v)<br>- **Script:** ${scriptVersion}<br>- **Computer Name:** ${computerName}<br>- **Serial Number:** ${serialNumber}<br>- **Wi-Fi:** ${ssid}<br>- ${activeIPAddress}<br>- **VPN IP:** ${vpnStatus}<br><br>**Jamf Pro Information:**<br>- **Site:** ${jamfProSiteName}"

helpimage="qr=${infobuttonaction}"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Main Dialog Window
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

dialogJSON='
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
    "infobox" : "**User:** '"{userfullname}"'<br><br>**Computer Model:** '"{computermodel}"'<br><br>**Serial Number:** '"{serialnumber}"' ",
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
    "width" : "900",
    "messagefont" : "size=14",
    "listitem" : [
        {"title" : "macOS Version", "subtitle" : "Organizational standards are the current and immediately previous versions of macOS", "icon" : "SF=01.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Available Updates", "subtitle" : "Keep your Mac up-to-date to ensure its security and performance", "icon" : "SF=02.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "System Integrity Protection", "subtitle" : "System Integrity Protection (SIP) in macOS protects the entire system by preventing the execution of unauthorized code.", "icon" : "SF=03.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Firewall", "subtitle" : "The built-in macOS firewall helps protect your Mac from unauthorized access.", "icon" : "SF=04.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "FileVault Encryption", "subtitle" : "FileVault is built-in to macOS and provides full-disk encryption to help prevent unauthorized access to your Mac", "icon" : "SF=05.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=06.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=07.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Free Disk Space", "subtitle" : "See KB0080685 Disk Usage to help identify the 50 largest directories", "icon" : "SF=08.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "MDM Profile", "subtitle" : "The presence of the Jamf Pro MDM profile helps ensure your Mac is enrolled", "icon" : "SF=09.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "MDM Certficate Expiration", "subtitle" : "Validate the expiration date of the Jamf Pro MDM certficate", "icon" : "SF=10.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, Jamf Pro and your Mac", "icon" : "SF=11.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Jamf Pro Check-In", "subtitle" : "Your Mac should check-in with the Jamf Pro MDM server multiple times each day", "icon" : "SF=12.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Jamf Pro Inventory", "subtitle" : "Your Mac should submit its inventory to the Jamf Pro MDM server daily", "icon" : "SF=13.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=14.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
        {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=15.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
        {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=16.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
        {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=17.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
        {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Account and content delivery services","icon":"SF=18.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
        {"title" : "Jamf Hosts","subtitle":"Test connectivity to Jamf Pro cloud and on-prem endpoints","icon":"SF=19.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
        {"title" : "Microsoft Teams", "subtitle" : "The hub for teamwork in Microsoft 365.", "icon" : "SF=20.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "BeyondTrust Privilege Management", "subtitle" : "Privilege Management for Mac pairs powerful least-privilege management and application control", "icon" : "SF=21.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Cisco Umbrella", "subtitle" : "Cisco Umbrella combines multiple security functions so you can extend data protection anywhere.", "icon" : "SF=22.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "CrowdStrike Falcon", "subtitle" : "Technology, intelligence, and expertise come together in CrowdStrike Falcon to deliver security that works.", "icon" : "SF=23.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Palo Alto GlobalProtect", "subtitle" : "Virtual Private Network (VPN) connection to Church headquarters", "icon" : "SF=24.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=25.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Computer Inventory", "subtitle" : "The listing of your Mac’s apps and settings", "icon" : "SF=26.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
    ]
}
'

echo "${dialogJSON}" > "${dialogJSONFile}"



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
    sleep 0.3
    echo "$1" >> "$dialogCommandFile"
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

    jamfProURL=$(defaults read /Library/Preferences/com.jamfsoftware.jamf.plist jss_url)

    jamfProComputerURL="${jamfProURL}computers.html?query=${serialNumber}&queryType=COMPUTERS"

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
                        {
                            "type": "mrkdwn",
                            "text": "*Computer Name:*\n$( scutil --get ComputerName )"
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*Serial:*\n${serialNumber}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*Timestamp:*\n${timestamp}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*User:*\n${loggedInUser}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*OS Version:*\n${osVersion} (${osBuild})"
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*Health Failures:*\n${overallHealth%%; }"
                        }
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
                            "url": "${jamfProComputerURL}"
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
                                    {
                                        "title": "Timestamp",
                                        "value": "${timestamp}"
                                    },
                                    {
                                        "title": "User",
                                        "value": "${loggedInUser}"
                                    },
                                    {
                                        "title": "Operating System",
                                        "value": "${osVersion} (${osBuild})"
                                    },
                                    {
                                        "title": "Health Failures",
                                        "value": "${overallHealth%%; }"
                                    }
                                ]
                            }
                        ],
                        "actions": [
                            {
                                "type": "Action.OpenUrl",
                                "title": "View in Jamf Pro",
                                "url": "${jamfProComputerURL}"
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
    info "Send the message Microsoft Teams …"
    # info "${webHookdata}"

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

    notice "${localAdminWarning}User: ${loggedInUserFullname} (${loggedInUser}) [${loggedInUserID}] ${loggedInUserGroupMembership}; ${bootstrapTokenStatus}; sudo Check: ${sudoStatus}; sudoers: ${sudoAllLines}; Kerberos SSOe: ${kerberosSSOeResult}; Platform SSOe: ${platformSSOeResult}; Location Services: ${locationServicesStatus}; SSH: ${sshStatus}; Microsoft OneDrive Sync Date: ${oneDriveSyncDate}; Time Machine Backup Date: ${tmStatus} ${tmLastBackup}; Battery Cycle Count: ${batteryCycleCount}; Wi-Fi: ${ssid}; ${activeIPAddress//\*\*/}; VPN IP: ${vpnStatus} ${vpnExtendedStatus}; ${networkTimeServer}; Jamf Pro Computer ID: ${jamfProID}; Site: ${jamfProSiteName}"

    if [[ -n "${overallHealth}" ]]; then
        dialogUpdate "icon: SF=xmark.circle,weight=bold,colour1=#BB1717,colour2=#F31F1F"
        dialogUpdate "title: Computer Unhealthy (as of $( date '+%Y-%m-%d-%H%M%S' ))"
        if [[ -n "${webhookURL}" ]]; then
            info "Sending webhook message"
            webhookStatus="Failures Detected"
            webHookMessage
        fi
        errorOut "${overallHealth%%; }"
        exitCode="1"
    else
        dialogUpdate "icon: SF=checkmark.circle,weight=bold,colour1=#00ff44,colour2=#075c1e"
        dialogUpdate "title: Computer Healthy (as of $( date '+%Y-%m-%d-%H%M%S' ))"
    fi

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
        if [[ ${completionTimer} -lt 0 ]]; then break; fi;
        if ! kill -0 "${dialogPID}" 2>/dev/null; then break; fi;
    done
    dialogUpdate "quit:"

    # Remove the dialog command file
    rm -f "${dialogCommandFile}"

    # Remove the dialog JSON file
    if [[ "${operationMode}" == "production" ]]; then
        rm -f /var/tmp/dialogJSONFile_*
    else
        notice "${operationMode} mode: NOT deleting dialogJSONFile ${dialogJSONFile}"
    fi

    # Remove overlay icon
    if [[ -f "${overlayicon}" ]] && [[ "${overlayicon}" != "/System/Library/CoreServices/Finder.app" ]]; then
        rm -f "${overlayicon}"
    fi

    # Remove default dialog.log
    rm -f /var/tmp/dialog.log

    # Remove SOFA JSON cache directory
    if [[ "${operationMode}" == "production" ]]; then
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

preFlight "\n\n###\n# $humanReadableScriptName (${scriptVersion})\n# https://snelson.us/mhc\n###\n"
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
# Pre-flight Check: Confirm jamf.log exists
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ ! -f "/private/var/log/jamf.log" ]]; then
    fatal "jamf.log missing; exiting."
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Validate / install swiftDialog (Thanks big bunches, @acodega!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dialogInstall() {

    # Get the URL of the latest PKG From the Dialog GitHub repo
    dialogURL=$(curl -L --silent --fail "https://api.github.com/repos/swiftDialog/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")

    # Expected Team ID of the downloaded PKG
    expectedDialogTeamID="PWA5E9TQ59"

    preFlight "Installing swiftDialog..."

    # Create temporary working directory
    workDirectory=$( basename "$0" )
    tempDirectory=$( mktemp -d "/private/tmp/$workDirectory.XXXXXX" )

    # Download the installer package
    curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"

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
        completionActionOption="Quit"
        exitCode="1"
        quitScript

    fi

    # Remove the temporary working directory when done
    /bin/rm -Rf "$tempDirectory"

}



function dialogCheck() {

    # Check for Dialog and install if not found
    if [ ! -x "/Library/Application Support/Dialog/Dialog.app" ]; then

        preFlight "swiftDialog not found. Installing..."
        dialogInstall

    else

        dialogVersion=$(/usr/local/bin/dialog --version)
        if [[ "${dialogVersion}" < "${swiftDialogMinimumRequiredVersion}" ]]; then
            
            preFlight "swiftDialog version ${dialogVersion} found but swiftDialog ${swiftDialogMinimumRequiredVersion} or newer is required; updating..."
            dialogInstall
            
        else

        preFlight "swiftDialog version ${dialogVersion} found; proceeding..."

        fi
    
    fi

}

dialogCheck



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Forcible-quit for all other running dialogs
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

preFlight "Forcible-quit for all other running dialogs …"
killProcess "Dialog"



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
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${osResult}"
        warning "${osResult}"
    
    else

        # logComment "OS Build, ${osBuild}, ends with a number; proceeding …"

        # N-rule variable [How many previous minor OS path versions will be marked as compliant]
        n="${previousMinorOS}"

        # URL to the online JSON data
        online_json_url="https://sofafeed.macadmins.io/v1/macos_data_feed.json"
        user_agent="Mac-Health-Check-checkOS/2.4.0"

        # local store
        json_cache_dir="/var/tmp/sofa"
        json_cache="$json_cache_dir/macos_data_feed.json"
        etag_cache="$json_cache_dir/macos_data_feed_etag.txt"

        # ensure local cache folder exists
        /bin/mkdir -p "$json_cache_dir"

        # check local vs online using etag
        if [[ -f "$etag_cache" && -f "$json_cache" ]]; then
            # logComment "e-tag stored, will download only if e-tag doesn’t match"
            etag_old=$(/bin/cat "$etag_cache")
            curl --compressed --silent --etag-compare "$etag_cache" --etag-save "$etag_cache" --header "User-Agent: $user_agent" "$online_json_url" --output "$json_cache"
            etag_new=$(/bin/cat "$etag_cache")
            if [[ "$etag_old" == "$etag_new" ]]; then
                # logComment "Cached ETag matched online ETag - cached json file is up to date"
            else
                # logComment "Cached ETag did not match online ETag, so downloaded new SOFA json file"
            fi
        else
            # logComment "No e-tag cached, proceeding to download SOFA json file"
            curl --compressed --location --max-time 3 --silent --header "User-Agent: $user_agent" "$online_json_url" --etag-save "$etag_cache" --output "$json_cache"
        fi

        # 1. Get model (DeviceID)
        model=$(sysctl -n hw.model)
        # logComment "Model Identifier: $model"

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
        # logComment "System Version: $system_version"

        # if [[ $system_version == *".0" ]]; then
        #     system_version=${system_version%.0}
        #     logComment "Corrected System Version: $system_version"
        # fi

        # exit if less than macOS 12
        if [[ "$system_os" -lt 12 ]]; then
            osResult="Unsupported macOS"
            result "$osResult"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${osResult}"
            # return 1
        fi

        # 3. Identify latest compatible major OS
        latest_compatible_os=$(plutil -extract "Models.$model.SupportedOS.0" raw -expect string "$json_cache" | head -n 1)
        # logComment "Latest Compatible macOS: $latest_compatible_os"

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
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: ${osResult}"
            info "${osResult}"
        else
            osResult="macOS ${osVersion} (${osBuild})"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${osResult}"
            errorOut "${osResult}"
            overallHealth+="${humanReadableCheckName}; "
        fi

    fi

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

    sleep "${anticipationDuration}"

    mdmClientAvailableOSUpdates=$( /usr/libexec/mdmclient AvailableOSUpdates | head -n 5 )
    if [[ "${mdmClientAvailableOSUpdates}" == *"OS Update Item"* ]]; then
        notice "MDM Client Available OS Updates"
        info "${mdmClientAvailableOSUpdates}"
    fi

    recommendedUpdates=$( /usr/libexec/PlistBuddy -c "Print :RecommendedUpdates:0" /Library/Preferences/com.apple.SoftwareUpdate.plist 2>/dev/null )
    if [[ -n "${recommendedUpdates}" ]]; then

        SUListRaw=$( softwareupdate --list --include-config-data 2>&1 )

        case "${SUListRaw}" in

            *"Can’t connect"* )
                availableSoftwareUpdates="Can’t connect to the Software Update server"
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${availableSoftwareUpdates}"
                errorOut "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                overallHealth+="${humanReadableCheckName}; "
                ;;

            *"The operation couldn’t be completed."* )
                availableSoftwareUpdates="The operation couldn’t be completed."
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${availableSoftwareUpdates}"
                errorOut "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                overallHealth+="${humanReadableCheckName}; "
                ;;

            *"Deferred: YES"* )
                availableSoftwareUpdates="Deferred software available."
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${availableSoftwareUpdates}"
                warning "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                ;;

            *"No new software available."* )
                availableSoftwareUpdates="No new software available."
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: ${availableSoftwareUpdates}"
                info "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                ;;

            * )
                SUList=$( echo "${SUListRaw}" | grep "*" | sed "s/\* Label: //g" | sed "s/,*$//g" )
                availableSoftwareUpdates="${SUList}"
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${availableSoftwareUpdates}"
                warning "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                ;;

        esac

    else

        availableSoftwareUpdates="None"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: ${availableSoftwareUpdates}"
        info "${humanReadableCheckName}: ${availableSoftwareUpdates}"

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

    sipCheck=$( csrutil status )

    case ${sipCheck} in

        *"enabled"* ) 
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: Enabled"
            info "${humanReadableCheckName}: Enabled"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: Failed"
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
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: Enabled"
            info "${humanReadableCheckName}: Enabled"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: Failed"
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
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${uptimeHumanReadable}"
                warning "${humanReadableCheckName}: ${uptimeHumanReadable}"
                ;;

            "error" | * )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${uptimeHumanReadable}"
                errorOut "${humanReadableCheckName}: ${uptimeHumanReadable}"
                overallHealth+="${humanReadableCheckName}; "
                ;;

        esac
    
    else
    
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: ${uptimeHumanReadable}"
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
    freeBytes=$( diskutil info / | grep -E 'Free Space|Available Space|Container Free Space' | awk -F "(\\\(| Bytes\\\))" '{ print $2 }' )
    diskBytes=$( diskutil info / | grep -E 'Total Space' | awk -F "(\\\(| Bytes\\\))" '{ print $2 }' )
    freePercentage=$( echo "scale=2; ( $freeBytes * 100 ) / $diskBytes" | bc )
    diskSpace="$freeSpace free (${freePercentage}% available)"

    diskMessage="${humanReadableCheckName}: ${diskSpace}"

    if (( $( echo ${freePercentage}'<'${allowedMinimumFreeDiskPercentage} | bc -l ) )); then

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${diskSpace}"
        errorOut "${humanReadableCheckName}: ${diskSpace}"
        overallHealth+="${humanReadableCheckName}; "

    else

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: ${diskSpace}"
        info "${humanReadableCheckName}: ${diskSpace}"

    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check the status of the Jamf Pro MDM Profile
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkJamfProMdmProfile() {

    local humanReadableCheckName="Jamf Pro MDM Profile"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=gear.badge,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    mdmProfileTest=$( profiles list -all | grep "00000000-0000-0000-A000-4A414D460003" )

    if [[ -n "${mdmProfileTest}" ]]; then

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: Installed"
        info "${humanReadableCheckName}: Installed"

    else

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: NOT Installed"
        errorOut "${humanReadableCheckName} (${1})"
        overallHealth+="${humanReadableCheckName}; "

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

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: Failed"
        errorOut "${humanReadableCheckName} (${1}): ${apnsCheck}"
        overallHealth+="${humanReadableCheckName}; "

    else

        apnsStatusEpoch=$( date -j -f "%Y-%m-%d %H:%M:%S" "${apnsCheck}" +"%s" )
        apnsStatus=$( date -r "${apnsStatusEpoch}" "+%A %-l:%M %p" )
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: ${apnsStatus}"
        info "${humanReadableCheckName}: ${apnsCheck}"

    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Jamf Extended Network Checks (thanks, @tonyyo11!)
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

# Generic network-host tester; uses nc to probe host:port and updates swiftDialog
function checkNetworkHosts() {
    local index="$1"
    local name="$2"
    shift 2
    local hosts=("$@")

    notice "Check ${name} …"
    dialogUpdate "icon: SF=network,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${index}, icon: SF=$(printf "%02d" $(($index+1))).circle $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${name} connectivity …"
    sleep "${anticipationDuration}"

    local allOK=true
    local results=""

    for entry in "${hosts[@]}"; do
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
    done

    if [[ "${allOK}" == true ]]; then
        dialogUpdate "listitem: index: ${index}, icon: SF=$(printf "%02d" $(($index+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: Passed"
        info "${name}: ${results%;; }"
    else
        dialogUpdate "listitem: index: ${index}, icon: SF=$(printf "%02d" $(($index+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: Failed"
        errorOut "${name}: ${results%;; }"
        overallHealth+="${name}; "
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check the expiration date of the JSS Built-in Certificate Authority (thanks, @isaacatmann!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkJssCertificateExpiration() {

    local humanReadableCheckName="JSS Built-in Certificate Authority"
    notice "Check the expiration date of the ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=mail.and.text.magnifyingglass,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining MDM Certificate expiration date …"

    sleep "${anticipationDuration}"

    identities=( $( security find-identity -v /Library/Keychains/System.keychain | grep -v "$serialNumber" | grep -v "Jamf" | awk '{print $3}' | tr -d '"' | head -n 1 ) )
    now_seconds=$( date +%s )

    if [[ "${identities}" != "identities" ]]; then

        for i in $identities; do
            if [[ $(security find-certificate -c "$i" | grep issu | tr -d '"') == *"JSS BUILT-IN CERTIFICATE AUTHORITY"* ]] || [[ $(security find-certificate -c "$i" | grep issu | tr -d '"') == *"JSS Built-in Certificate Authority"* ]]; then
                expiry=$(security find-certificate -c "$i" -p | openssl x509 -noout -enddate | cut -f2 -d"=")
                expirationDateFormatted=$( date -j -f "%b %d %H:%M:%S %Y GMT" "${expiry}" "+%d-%b-%Y" )
                date_seconds=$(date -j -f "%b %d %T %Y %Z" "$expiry" +%s)
                if (( date_seconds > now_seconds )); then
                    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: ${expirationDateFormatted}"
                    info "${humanReadableCheckName} Expiration: ${expirationDateFormatted}"
                else
                    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${expirationDateFormatted}"
                    errorOut "${humanReadableCheckName} Expiration: ${expirationDateFormatted}"
                    overallHealth+="${humanReadableCheckName}; "
                fi
            fi
        done
    
    else

        expirationDateFormatted="NOT Installed"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${expirationDateFormatted}"
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

    # Enable 24 hour clock format (12 hour clock enabled by default)
    twenty_four_hour_format="false"

    # Number of seconds since action last occurred (86400 = 1 day)
    check_in_time_old=86400      # 1 day
    check_in_time_aging=28800    # 8 hours

    last_check_in_time=$(grep "Checking for policies triggered by \"recurring check-in\"" "/private/var/log/jamf.log" | tail -n 1 | awk '{ print $2,$3,$4 }')

    # Convert last Jamf Pro check-in time to epoch
    last_check_in_time_epoch=$(date -j -f "%b %d %T" "${last_check_in_time}" +"%s")
    time_since_check_in_epoch=$(($currentTimeEpoch-$last_check_in_time_epoch))

    # Convert last Jamf Pro epoch to something easier to read
    if [[ "${twenty_four_hour_format}" == "true" ]]; then
        # Outputs 24 hour clock format
        last_check_in_time_human_reable=$(date -r "${last_check_in_time_epoch}" "+%A %H:%M")
    else
        # Outputs 12 hour clock format
        last_check_in_time_human_reable=$(date -r "${last_check_in_time_epoch}" "+%A %-l:%M %p")
    fi

    # Set status indicator for last check-in
    if [ ${time_since_check_in_epoch} -ge ${check_in_time_old} ]; then
        # check_in_status_indicator="🔴"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${last_check_in_time_human_reable}"
        errorOut "${humanReadableCheckName}: ${last_check_in_time_human_reable}"
        overallHealth+="${humanReadableCheckName}; "
    elif [ ${time_since_check_in_epoch} -ge ${check_in_time_aging} ]; then
        # check_in_status_indicator="🟠"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${last_check_in_time_human_reable}"
        warning "${humanReadableCheckName}: ${last_check_in_time_human_reable}"
        overallHealth+="${humanReadableCheckName}; "
    elif [ ${time_since_check_in_epoch} -lt ${check_in_time_aging} ]; then
        # check_in_status_indicator="🟢"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: ${last_check_in_time_human_reable}"
        info "${humanReadableCheckName}: ${last_check_in_time_human_reable}"
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

    # Enable 24 hour clock format (12 hour clock enabled by default)
    twenty_four_hour_format="false"

    # Number of seconds since action last occurred (86400 = 1 day)
    inventory_time_old=604800    # 1 week
    inventory_time_aging=259200  # 3 days

    # Get last Jamf Pro inventory time from jamf.log
    last_inventory_time=$(grep "Removing existing launchd task /Library/LaunchDaemons/com.jamfsoftware.task.bgrecon.plist..." "/private/var/log/jamf.log" | tail -n 1 | awk '{ print $2,$3,$4 }')

    # Convert last Jamf Pro inventory time to epoch
    last_inventory_time_epoch=$(date -j -f "%b %d %T" "${last_inventory_time}" +"%s")
    time_since_inventory_epoch=$(($currentTimeEpoch-$last_inventory_time_epoch))

    # Convert last Jamf Pro epoch to something easier to read
    if [[ "${twenty_four_hour_format}" == "true" ]]; then
        # Outputs 24 hour clock format
        last_inventory_time_human_reable=$(date -r "${last_inventory_time_epoch}" "+%A %H:%M")
    else
        # Outputs 12 hour clock format
        last_inventory_time_human_reable=$(date -r "${last_inventory_time_epoch}" "+%A %-l:%M %p")
    fi

    #set status indicator for last inventory
    if [ ${time_since_inventory_epoch} -ge ${inventory_time_old} ]; then
        # inventory_status_indicator="🔴"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: ${last_inventory_time_human_reable}"
        errorOut "${humanReadableCheckName}: ${last_inventory_time_human_reable}"
        overallHealth+="${humanReadableCheckName}; "
    elif [ ${time_since_inventory_epoch} -ge ${inventory_time_aging} ]; then
        # inventory_status_indicator="🟠"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: ${last_inventory_time_human_reable}"
        warning "${humanReadableCheckName}: ${last_inventory_time_human_reable}"
        overallHealth+="${humanReadableCheckName}; "
    elif [ ${time_since_inventory_epoch} -lt ${inventory_time_aging} ]; then
        # inventory_status_indicator="🟢"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: ${last_inventory_time_human_reable}"
        info "${humanReadableCheckName}: ${last_inventory_time_human_reable}"
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
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: Enabled"
                info "${humanReadableCheckName}: Enabled"
                ;;

            *"Deferred enablement appears to be active for user"* )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: Enabled (next login)"
                warning "${humanReadableCheckName}: Enabled (next login)"
                ;;

            *  )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#EB5545, iconalpha: 1, status: fail, statustext: Failed"
                errorOut "${humanReadableCheckName} (${1})"
                overallHealth+="${humanReadableCheckName}; "
                ;;

        esac

    else

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#EB5545, iconalpha: 1, status: fail, statustext: Failed"
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

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: Installed"
        info "${checkInternalTargetFileDisplayName} installed"
        
    else

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#EB5545, iconalpha: 1, status: fail, statustext: NOT Installed"
        errorOut "${checkInternalTargetFileDisplayName} NOT Installed"
        overallHealth+="${checkInternalTargetFileDisplayName}; "

    fi

    sleep "${anticipationDuration}"

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
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: Failed"
            errorOut "${vpnAppName} Failed"
            overallHealth+="${vpnAppName}; "
            ;;

        *"Idle"* )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: Idle"
            info "${vpnAppName} idle"
            ;;

        "Connected"* )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: Connected"
            info "${vpnAppName} Connected"
            ;;

        "Disconnected" )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: Disconnected"
            info "${vpnAppName} Disconnected"
            ;;

        "None" )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: No VPN"
            info "No VPN"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: Unknown"
            info "${vpnAppName} Unknown"
            ;;

    esac

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check External Validation (where Parameter 2 represents the Jamf Pro Policy Custom Trigger)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkExternal() {

    trigger="${2}"
    appPath="${3}"
    appDisplayName=$(basename "${appPath}" .app)

    notice "External Check: ${appPath} …"

    dialogUpdate "icon: ${appPath}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining status of ${appDisplayName} …"

    # sleep "${anticipationDuration}"

    externalValidation=$( /usr/local/bin/jamf policy -event $trigger | grep "Script result:" )

    case ${externalValidation:l} in

        *"failed"* )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#EB5545, iconalpha: 1, status: fail, statustext: Failed"
            errorOut "${appDisplayName} Failed"
            overallHealth+="${appDisplayName}; "
            ;;

        *"running"* ) 
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: Running"
            info "${appDisplayName} running"
            ;;

        *"error"* | * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle weight=bold colour=#F8D84A, iconalpha: 1, status: error, statustext: Error"
            errorOut "${appDisplayName} Error"
            overallHealth+="${appDisplayName}; "
            ;;

    esac

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
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: ${mbps} Mbps ${testStatus}"
    info "Download: ${mbps} Mbps, Responsiveness: ${dlResponsiveness}; "

    dialogUpdate "icon: ${icon}"

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

    if [[ "${operationMode}" != "test" ]]; then

        jamf recon # -verbose

    else

        sleep "${anticipationDuration}"

    fi

    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: Updated"

}



####################################################################################################
#
# Program
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Create Dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

notice "Current Elapsed Time: $(printf '%dh:%dm:%ds\n' $((SECONDS/3600)) $((SECONDS%3600/60)) $((SECONDS%60)))"

eval ${dialogBinary} --jsonfile ${dialogJSONFile} &
dialogPID=$!
info "Dialog PID: ${dialogPID}"

dialogUpdate "progresstext: Initializing …"

# Band-Aid for macOS 15+ `withAnimation` SwiftUI bug
dialogUpdate "list: hide"
dialogUpdate "list: show"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Health Checks (where "n" represents the listitem order)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


if [[ "${operationMode}" != "test" ]]; then

    # Production and Debug Mode

    checkOS "0"
    checkAvailableSoftwareUpdates "1"
    checkSIP "2"
    checkFirewall "3"
    checkFileVault "4"
    checkVPN "5"
    checkUptime "6"
    checkFreeDiskSpace "7"
    checkJamfProMdmProfile "8"
    checkJssCertificateExpiration "9"
    checkAPNs "10"
    checkJamfProCheckIn "11"
    checkJamfProInventory "12"
    checkNetworkHosts  "13" "Apple Push Notification Hosts"         "${pushHosts[@]}"
    checkNetworkHosts  "14" "Apple Device Management"               "${deviceMgmtHosts[@]}"
    checkNetworkHosts  "15" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
    checkNetworkHosts  "16" "Apple Certificate Validation"          "${certHosts[@]}"
    checkNetworkHosts  "17" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
    checkNetworkHosts  "18" "Jamf Hosts"                            "${jamfHosts[@]}"
    checkInternal "19" "/Applications/Microsoft Teams.app"  "/Applications/Microsoft Teams.app"             "Microsoft Teams"
    checkExternal "20" "symvBeyondTrustPMfM"                "/Applications/PrivilegeManagement.app"
    checkExternal "21" "symvCiscoUmbrella"                  "/Applications/Cisco/Cisco Secure Client.app"
    checkExternal "22" "symvCrowdStrikeFalcon"              "/Applications/Falcon.app"
    checkExternal "23" "symvGlobalProtect"                  "/Applications/GlobalProtect.app"
    checkNetworkQuality "24"
    updateComputerInventory "25"

    dialogUpdate "icon: ${icon}"
    dialogUpdate "progresstext: Final Analysis …"

    sleep "${anticipationDuration}"

else

    # Test Mode

    dialogUpdate "title: ${humanReadableScriptName} (${scriptVersion}) [Operation Mode: ${operationMode}]"

    listitemLength=$(get_json_value "${dialogJSON}" "listitem.length")

    for (( i=0; i<listitemLength; i++ )); do

        notice "[Operation Mode: ${operationMode}] Check ${i} …"

        dialogUpdate "icon: SF=$(printf "%02d" $(($i+1))).square,${organizationColorScheme}"
        dialogUpdate "listitem: index: ${i}, icon: SF=$(printf "%02d" $(($i+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
        dialogUpdate "progress: increment"
        dialogUpdate "progresstext: [Operation Mode: ${operationMode}] • Item No. ${i} …"

        # sleep "${anticipationDuration}"

        dialogUpdate "listitem: index: ${i}, icon: SF=$(printf "%02d" $(($i+1))).circle colour=#6BD45F, iconalpha: 0.5, status: success, statustext: ${operationMode}"

    done

    dialogUpdate "icon: ${icon}"
    dialogUpdate "progresstext: Final Analysis …"

    sleep "${anticipationDuration}"

fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Quit Script
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

quitScript
