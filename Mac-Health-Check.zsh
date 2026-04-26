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
# Version 4.0.0b18, 25-Apr-2026, Dan K. Snelson (@dan-snelson)
# - Added JSON health reporting (with optional Splunk HTTP Event Collector (HEC) delivery)
# - Added a stand-alone swiftDialog Inspect Mode-flavored report (i.e., `inspectSummaryPreset="on"`), plus cached replay (i.e., `inspectReplayMaximumAgeSeconds`) for `Self Service` runs
# - Refactored `checkElectronCornerMask` to reduce execution time
# - Many quality-of-life user-interface improvements
# - Raised the minimum required swiftDialog version to `3.1.0.4976`
# - Refactored `checkHomebrewStatus()` to more accurately reflect Homebrew's actual installation status
# - Added "Next Steps" to Inspect Mode-flavored report
# - Added `checkWiFiStrength()`; thanks, @kgolden-code!
# - Removed `displayFailureNotification()` in favor of the Inspect Mode-flavored report
# - Refactored `Silent` when used with `splunkOperationMode=production` to suppress non-Splunk console output and return success when Splunk reporting succeeds, regardless of recorded health findings
# - Refactored Palo Alto GlobalProtect-related code (inspired by @kgolden-code’s PR #88) to add support for connected-non-pa status, safe plist reads and normalized external-check output
# - Refactored the final standard dialog to distinguish warning-only results from failures, showing `Computer Needs Attention` with an amber exclamation mark and returning exit code `0` when no checks failed
# - Update Free Disk Space and (Folder) Size and Item Count reporting Info (thanks for PR #89, @HowardGMac!)
# - Enhanced Wi-Fi Strength test reporting (thanks for PR #90, @HowardGMac!)"
# - Added Client-Side Cache nightly cache generation and Jamf Pro cached Splunk upload optimization
# - Added LaunchDaemon deployment for a local daily `Silent` report refresh with deterministic per-Mac jitter around 1:23 a.m.
# - Sanitized the client-side script copy so it does not perform Jamf inventory submission
#
####################################################################################################



####################################################################################################
#
# Global Variables
#
####################################################################################################

export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin/

# Script Version
scriptVersion="4.0.0b18"

# Client-side Log
scriptLog="/var/log/org.churchofjesuschrist.log"

# Load is-at-least for version comparison
autoload -Uz is-at-least

# Minimum Required Version of swiftDialog
swiftDialogMinimumRequiredVersion="3.1.0.4976"

# Force locale to English (so `date` does not error on localization formatting)
LANG="en_us_88591"

# Elapsed Time
SECONDS="0"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Script Parameters
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Parameter 4: Operation Mode [ Debug | Development | Self Service | Silent | Test ]
operationMode="${4:-"Self Service"}"

    # Enable `set -x` if operation mode is "Debug" to help identify issues
    [[ "${operationMode}" == "Debug" ]] && set -x

# Parameter 5: Microsoft Teams or Slack Webhook URL [ Leave blank to disable (default) | https://microsoftTeams.webhook.com/URL | https://hooks.slack.com/services/URL ]
webhookURL="${5:-""}"



# --- New in `4.0.0` ------------------------------------------------------------------------------

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Client-Side Cache Jitter
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

clientSideJitterEnabled="true"
clientSideMaxJitterSeconds="1800" # +/- 30 minutes
clientSideLaunchDaemonHour="0"
clientSideLaunchDaemonMinute="53"

function calculateClientSideJitterOffset() {

    local maxJitter="${clientSideMaxJitterSeconds}"
    local jitterRange=0
    local hardwareUUID=""
    local serialNumberFallback=""
    local hashSeed=""
    local hexSeed=""
    local jitterOffset=0

    if [[ "${maxJitter}" != <-> ]] || (( maxJitter < 0 )); then
        maxJitter="1800"
    fi

    jitterRange=$(( ( maxJitter * 2 ) + 1 ))

    hardwareUUID=$( ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/ {print $4}' )
    if [[ -n "${hardwareUUID}" ]]; then
        hexSeed="${hardwareUUID: -8}"
    else
        serialNumberFallback=$( ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformSerialNumber/ {print $4}' )
        hashSeed=$( echo -n "${serialNumberFallback:-${HOST:-unknown}}" | md5 -q )
        hexSeed="${hashSeed: -8}"
    fi

    if ! echo "${hexSeed}" | grep -Eq '^[[:xdigit:]]+$'; then
        hexSeed="0"
    fi

    jitterOffset=$(( 16#${hexSeed:u} % jitterRange - maxJitter ))

    echo "${jitterOffset}"

}

if [[ "${launchDaemonRun}" == "true" ]] && [[ "${clientSideJitterEnabled:l}" == "true" ]]; then

    jitterOffset=$( calculateClientSideJitterOffset )
    if [[ "${jitterOffset}" != -<-> && "${jitterOffset}" != <-> ]]; then
        jitterOffset="0"
    fi

    jitterSleepSeconds=$(( jitterOffset + clientSideMaxJitterSeconds ))
    (( jitterSleepSeconds < 0 )) && jitterSleepSeconds="0"
    (( jitterSleepSeconds > ( clientSideMaxJitterSeconds * 2 ) )) && jitterSleepSeconds=$(( clientSideMaxJitterSeconds * 2 ))

    echo "Client-Side Cache: Jitter offset = ${jitterOffset} seconds"
    if [[ -n "${scriptLog}" ]]; then
        printf '%s\n' "Client-Side Cache: Jitter offset = ${jitterOffset} seconds; sleeping ${jitterSleepSeconds} seconds" >> "${scriptLog}" 2>/dev/null
    fi

    if (( jitterSleepSeconds > 0 )); then
        echo "Client-Side Cache: Sleeping ${jitterSleepSeconds} seconds to stagger load..."
        sleep "${jitterSleepSeconds}"
    fi

fi

# Parameter 6: Splunk reporting mode [ off | test | production ]
splunkOperationMode="${6:-"test"}"

# Parameter 7: Splunk HEC URL [ Leave blank to disable (default) | https://splunk.example.com:8088/services/collector ]
splunkHECURL="${7:-""}"

# Parameter 8: Splunk HEC Token [ Leave blank to disable (default) ]
splunkHECToken="${8:-""}"

# Parameter 9: Splunk HEC Index
splunkHECIndex="${9:-""}"

# Parameter 10: Splunk HEC Sourcetype
splunkHECSourcetype="${10:-""}"

# Parameter 11: Reporting debug mode [ true | false ]
reportDebug="${11:-"false"}"



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Organization Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Script Human-readable Name
humanReadableScriptName="Mac Health Check"

# Organization's Script Name
organizationScriptName="MHC"

# Organization's Reverse Domain Name Notation (i.e., com.company.division; used for plist domains)
reverseDomainNameNotation="org.churchofjesuschrist"

# Client-side Deployment
# Organization's Directory (i.e., where client-side scripts reside)
organizationDirectory="/Library/Management/${reverseDomainNameNotation}"
clientSideScriptPath="${organizationDirectory}/${organizationScriptName}.zsh"

# LaunchDaemon Name & Path
launchDaemonLabel="${reverseDomainNameNotation}.${organizationScriptName}"
launchDaemonPath="/Library/LaunchDaemons/${launchDaemonLabel}.plist"
clientSideSkipChecks="false"
clientSideMaximumCacheAgeSeconds="129600"
currentScriptPath="${0:A}"

# Splunk and JSON reporting defaults
splunkJSONReportPath="/var/tmp/MacHealthCheck-Report.json"

case "${splunkOperationMode:l}" in
    "off" )
        splunkOperationMode="off"
        ;;
    "test" )
        splunkOperationMode="test"
        ;;
    * )
        splunkOperationMode="production"
        ;;
esac

if [[ "${operationMode}" == "Silent" ]] && [[ "${splunkOperationMode}" == "production" ]]; then
    suppressNonSplunkConsoleLogging="true"
    if { : >> "${scriptLog}" } 2>/dev/null; then
        exec 2>> "${scriptLog}"
    fi
else
    suppressNonSplunkConsoleLogging="false"
fi

function clientSideEarlyLog() {

    local messageText="${1}"
    local logEntry="${organizationScriptName} (${scriptVersion}): $( date +%Y-%m-%d\ %H:%M:%S ) - [NOTICE]          Client-Side Cache: ${messageText}"

    printf '%s\n' "${logEntry}" >> "${scriptLog}" 2>/dev/null

    if [[ "${suppressNonSplunkConsoleLogging}" != "true" ]]; then
        printf '%s\n' "Client-Side Cache: ${messageText}"
    fi

}

# Client-Side Cache version check
if [[ "${operationMode}" == "Silent" ]] && [[ "${splunkOperationMode}" == "production" ]]; then

    if [[ "${currentScriptPath}" == "${clientSideScriptPath}" ]]; then

        clientSideEarlyLog "Running from client-side script path; skipping cached-upload shortcut."

    elif [[ -f "${clientSideScriptPath}" ]]; then

        clientVersion=$( grep -m1 '^scriptVersion=' "${clientSideScriptPath}" 2>/dev/null | awk -F'"' '{print $2}' )

        if [[ "${clientVersion}" == "${scriptVersion}" ]]; then

            if [[ -f "${splunkJSONReportPath}" ]]; then

                cachedReportModificationEpoch=$( stat -f %m "${splunkJSONReportPath}" 2>/dev/null )
                cachedReportAgeSeconds=$(( $( date +%s ) - ${cachedReportModificationEpoch:-0} ))

                if (( cachedReportModificationEpoch > 0 )) && (( cachedReportAgeSeconds <= clientSideMaximumCacheAgeSeconds )); then

                    if jq -e . "${splunkJSONReportPath}" >/dev/null 2>&1; then
                        clientSideSkipChecks="true"
                        clientSideEarlyLog "Client-side script version matches (${scriptVersion}); cached report is valid and ${cachedReportAgeSeconds}s old. Skipping health checks."
                    else
                        clientSideEarlyLog "Cached report exists but is invalid JSON. Falling back to full health check."
                    fi

                else

                    clientSideEarlyLog "Cached report is stale (${cachedReportAgeSeconds}s old; maximum ${clientSideMaximumCacheAgeSeconds}s). Falling back to full health check."

                fi

            else

                clientSideEarlyLog "Client-side script version matches (${scriptVersion}) but no cached report exists. Falling back to full health check."

            fi

        else

            clientSideEarlyLog "Version mismatch (client=${clientVersion:-not found}, server=${scriptVersion}). Running full health check."

        fi

    else

        clientSideEarlyLog "Client-side script not found at ${clientSideScriptPath}. Running full health check."

    fi

fi

# Organization's Self Service Marketing Name 
organizationSelfServiceMarketingName="Workforce App Store"

# Organization's Boilerplate Compliance Message 
organizationBoilerplateComplianceMessage="Meets organizational standards"

# Organization's Branding Banner URL
organizationBrandingBannerURL="https://img.freepik.com/free-photo/black-wall-texture_1194-5564.jpg" # [Image by rawpixel.com on Freepik](https://www.freepik.com/author/rawpixel-com)

# Organization's Overlayicon URL
organizationOverlayiconURL="/System/Library/CoreServices/Apple Diagnostics.app"

# Enable Dock integration in non-Silent modes [ true | false ]
enableDockIntegration="true"

# Organization's Dock Icon URL / Path [ default | file://path | /local/path | https://... ]
dockIcon="https://usw2.ics.services.jamfcloud.com/icon/hash_08f287b1d7a9da36b733c0784031a4943bef3b82a2981eb937ab2f5b2bd55e91"

# Organization's Defaults Domain for External Checks
organizationDefaultsDomain="org.churchofjesuschrist.external"

# Organization's Color Scheme
if [[ $( defaults read /Users/$(stat -f %Su /dev/console)/Library/Preferences/.GlobalPreferences.plist AppleInterfaceStyle 2>/dev/null ) == "Dark" ]]; then
    # Dark Mode
    organizationColorScheme="weight=semibold,colour1=#D1D5DC,colour2=#F5F5F5"
else
    # Light Mode
    organizationColorScheme="weight=semibold,colour1=#18181B,colour2=#4D4D56"
fi

# Status Colors
statusColorSuccess="#65C466"
statusColorFail="#EB4C46"
statusColorError="#F5BE0A"

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
networkQualityTestMaximumAge="4H"

# SOFA Cache Maximum Age
# Leverages `date -v-`; One of either y, m, w, d, H, M or S
# must be used to specify which part of the date is to be adjusted
sofaCacheMaximumAge="1d"

# Allowed number of uptime minutes
# - 1 day = 24 hours × 60 minutes/hour = 1,440 minutes
# - 7 days, multiply: 7 × 1,440 minutes = 10,080 minutes
allowedUptimeMinutes="10080"

# Should excessive uptime result in a "warning" or "error" ?
excessiveUptimeAlertStyle="warning"

# Completion Timer (in seconds)
completionTimer="60"

# --- New in `4.0.0` ------------------------------------------------------------------------------
# Inspect Mode Defaults
# Toggle detached inspect summary generation and cached replay [ on | off ]
inspectSummaryPreset="on"
inspectConfigPath="/var/tmp/MacHealthCheck-Inspect-Config.json"
inspectLaunchLogPath="/var/tmp/MacHealthCheck-Inspect-Summary.log"
inspectReplayMaximumAgeSeconds="900" # 15 minutes

# Splunk and JSON reporting defaults
splunkPrettyPrintJSON="false"
splunkReportDebug="false"
splunkAllowInsecureTLS="false"

# Result-collection defaults
reportingErrorCount=0
reportingErrors=""
reportGenerated="false"
reportTransmissionStatus="not_configured"
reportTransmissionHttpCode=""
reportTransmissionAttemptCount="0"
reportOverallStatus="healthy"
reportTimestamp=""
reportTimestampEpoch=""
reportFilePayload=""
reportHECPayload=""
reportJSONTool="jq"
exitCode="0"
overallHealth=""
errorCount="0"
currentTimeEpoch=$(date +%s)

typeset -A checkTitleByIndex
typeset -A checkKeyByIndex
typeset -A checkNormalizedStatusByIndex
typeset -A checkStatustextByIndex
typeset -A checkInspectTextByIndex
typeset -A checkMessageByIndex
typeset -A checkRemediationByIndex
typeset -A checkExecutedByIndex
typeset -A checkIndexByTitle

typeset -a reportHealthyChecks
typeset -a reportWarningChecks
typeset -a reportFailChecks
typeset -a reportErrorChecks

case "${reportDebug:l}" in
    "true" | "1" | "yes" | "y" )
        splunkReportDebug="true"
        splunkPrettyPrintJSON="true"
        ;;
    * )
        splunkReportDebug="false"
        ;;
esac

if [[ "${operationMode}" == "Debug" ]]; then
    splunkReportDebug="true"
    splunkPrettyPrintJSON="true"
fi

case "${inspectSummaryPreset:l}" in
    "off" )
        inspectSummaryPreset="off"
        ;;
    * )
        inspectSummaryPreset="on"
        ;;
esac



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
        # mdmProfileIdentifier="io.kandji.mdm.profile"
        mdmProfileIdentifier="com.kandji.profile.mdmprofile.mdm"
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
hardwareUUID=$( ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}' )
computerName=$( scutil --get ComputerName | sed 's/’//' )
computerModel=$( sysctl -n hw.model )
localHostName=$( scutil --get LocalHostName )
hostName=$( scutil --get HostName 2>/dev/null )
[[ -z "${hostName}" ]] && hostName="${localHostName}"
[[ -z "${hostName}" ]] && hostName="$( hostname )"
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
activationLockStatus=$( system_profiler SPHardwareDataType 2>/dev/null | awk '/Activation Lock Status/{print $NF}' )
bootstrapTokenStatus=$( profiles status -type bootstraptoken | awk '{sub(/^profiles: /, ""); printf "%s", $0; if (NR < 2) printf "; "}' | sed 's/; $//' )
sshStatus=$( systemsetup -getremotelogin | awk -F ": " '{ print $2 }' )
networkTimeServer=$( systemsetup -getnetworktimeserver )
locationServices=$( defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled )
locationServicesStatus=$( [ "${locationServices}" = "1" ] && echo "Enabled" || echo "Disabled" )
sudoStatus=$( visudo -c )
sudoAllLines=$( awk '/\(ALL\)/' /etc/sudoers | tr '\t\n#' ' ' )
rosettaRequiredAppsRaw=$(
    comm -23 \
        <( mdfind 'kMDItemExecutableArchitectures == x86_64' | sort ) \
        <( mdfind 'kMDItemExecutableArchitectures == arm64' | sort )
)
if [[ -n "${rosettaRequiredAppsRaw}" ]]; then
    rosettaRequiredApps=$( echo "${rosettaRequiredAppsRaw}" | awk 'NF {printf "%s%s", sep, $0; sep=", "}' )
else
    rosettaRequiredApps="None detected"
fi



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

if [[ "${launchDaemonRun}" == "true" ]]; then
    case "${loggedInUser}" in
        ""|"loginwindow"|"_mbsetupuser")
            lastUser=$( defaults read /Library/Preferences/com.apple.loginwindow.plist lastUserName 2>/dev/null )
            if [[ -n "${lastUser}" ]] && id "${lastUser}" >/dev/null 2>&1; then
                loggedInUser="${lastUser}"
            fi
            ;;
    esac
fi

if [[ -n "${loggedInUser}" ]] && id "${loggedInUser}" >/dev/null 2>&1; then
    loggedInUserFullname=$( id -F "${loggedInUser}" )
    loggedInUserFirstname=$( echo "$loggedInUserFullname" | sed -E 's/^.*, // ; s/([^ ]*).*/\1/' | sed 's/\(.\{25\}\).*/\1…/' | awk '{print ( $0 == toupper($0) ? toupper(substr($0,1,1))substr(tolower($0),2) : toupper(substr($0,1,1))substr($0,2) )}' )
    loggedInUserID=$( id -u "${loggedInUser}" )
    loggedInUserGroupMembership=$( id -Gn "${loggedInUser}" )
    loggedInUserHomeDirectory=$( dscl . read "/Users/${loggedInUser}" NFSHomeDirectory 2>/dev/null | awk -F ' ' '{print $2}' )
else
    loggedInUserFullname="No logged-in user"
    loggedInUserFirstname="User"
    loggedInUserID=""
    loggedInUserGroupMembership=""
    loggedInUserHomeDirectory=""
fi

if [[ ${loggedInUserGroupMembership} == *"admin"* ]]; then localAdminWarning="WARNING: '$loggedInUser' IS A MEMBER OF 'admin'; "; fi

# Volume Owners
volumeOwnerUUIDs=$( diskutil apfs listUsers / 2>/dev/null | awk '/\+-- [-0-9A-F]+$/ {print $2}' )
allLocalUsers=( ${(f)"$( dscl . list /Users | grep -v '^_' )"} )
volumeOwnerUsers=()
for eachUser in "${allLocalUsers[@]}"; do
    userUUID=$( dscl . -read /Users/"${eachUser}" GeneratedUID 2>/dev/null | awk '{print $2}' )
    if [[ -n "${userUUID}" ]]; then
        if echo "${volumeOwnerUUIDs}" | grep -q "${userUUID}"; then
            volumeOwnerUsers+=( "${eachUser}" )
        fi
    fi
done
if [[ ${#volumeOwnerUsers[@]} -eq 0 ]]; then
    volumeOwnerList="None"
else
    volumeOwnerList="${(j:, :)volumeOwnerUsers}"
fi

# Secure Token Status
if [[ -n "${loggedInUser}" ]] && id "${loggedInUser}" >/dev/null 2>&1; then
    secureTokenStatus=$( sysadminctl -secureTokenStatus "${loggedInUser}" 2>&1 )
    case "${secureTokenStatus}" in
        *"ENABLED"*)    secureToken="Enabled"   ;;
        *"DISABLED"*)   secureToken="Disabled"  ;;
        *)              secureToken="Unknown"   ;;
    esac
else
    secureTokenStatus="No local user"
    secureToken="Unknown"
fi

# Initialize Jamf Pro inventory endUsername variable (thanks, @tonyyo11!)
inventoryEndUsername=""
inventoryEndUsernameSource="None"
kerberosSSOeResult="Not configured"

# Kerberos Single Sign-on Extension
if [[ -n "${kerberosRealm}" ]]; then
    su \- "${loggedInUser}" -c "app-sso kerberos --realminfo ${kerberosRealm}" > /var/tmp/app-sso.plist 2>/dev/null
    if [[ -f /var/tmp/app-sso.plist ]] && xmllint --noout /var/tmp/app-sso.plist >/dev/null 2>&1; then
        ssoLoginTest=$( /usr/libexec/PlistBuddy -c "Print:login_date" /var/tmp/app-sso.plist 2>&1 )
        if [[ ${ssoLoginTest} == *"Does Not Exist"* ]]; then
            kerberosSSOeResult="${loggedInUser} NOT logged in"
        else
            username=$( /usr/libexec/PlistBuddy -c "Print:upn" /var/tmp/app-sso.plist 2>/dev/null | awk -F@ '{print $1}' )
            if [[ -n "${username}" ]]; then
                kerberosSSOeResult="${username}"
                inventoryEndUsername="${username}"
                inventoryEndUsernameSource="Kerberos SSOe"
            else
                kerberosSSOeResult="${loggedInUser} NOT logged in"
            fi
        fi
    else
        kerberosSSOeResult="Kerberos SSO not configured"
    fi
    rm -f /var/tmp/app-sso.plist 2>/dev/null
fi

# Platform Single Sign-on Extension
pssoeEmail=$( dscl . read /Users/"${loggedInUser}" dsAttrTypeStandard:AltSecurityIdentities 2>/dev/null | awk -F'SSO:' '/PlatformSSO/ {print $2}' | tail -1 | awk '{$1=$1; print}' )
if [[ -n "${pssoeEmail}" ]]; then
    platformSSOeResult="${pssoeEmail}"
    if [[ -z "${inventoryEndUsername}" ]]; then
        inventoryEndUsername=$( echo "${pssoeEmail}" | awk -F@ '{print $1}' )
        if [[ -n "${inventoryEndUsername}" ]]; then
            inventoryEndUsernameSource="Platform SSOe"
        fi
    fi
else
    platformSSOeResult="Platform SSO not configured"
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

function globalProtectReadPlistValue() {

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

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Palo Alto Networks GlobalProtect VPN Information
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ "${vpnClientVendor}" == "paloalto" ]]; then
    vpnAppName="GlobalProtect VPN Client"
    vpnAppPath="/Applications/GlobalProtect.app"
    globalProtectSettingsPlist="/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist"
    vpnStatus="GlobalProtect is NOT installed"

    if [[ -d "${vpnAppPath}" ]]; then
        vpnStatus="GlobalProtect is Idle"

        globalProtectTunnelStatus=$( globalProtectReadPlistValue "${globalProtectSettingsPlist}" ":'Palo Alto Networks':GlobalProtect:DEM:'tunnel-status'" )

        case "${globalProtectTunnelStatus}" in
            "connected"*|"connected-non-pa")
                globalProtectVpnIP=$( globalProtectReadPlistValue "${globalProtectSettingsPlist}" ':"Palo Alto Networks":GlobalProtect:DEM:"tunnel-ip"' | sed -nE 's/.*ipv4=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*/\1/p' )
                vpnStatus="Connected ${globalProtectVpnIP:-<no-IP>}"

                if [[ "${vpnClientDataType}" == "extended" ]]; then
                    vpnExtendedStatus=$( getGlobalProtectUserStatus )
                fi
                ;;
            "internal")
                vpnStatus="Internal"
                if [[ "${vpnClientDataType}" == "extended" ]]; then
                    vpnExtendedStatus=$( getGlobalProtectUserStatus )
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
dialogAppBundle="/Library/Application Support/Dialog/Dialog.app"
dialogBinary="/usr/local/bin/dialog"

# Enable debugging options for swiftDialog
dialogBinaryDebugArgs=()
[[ "${operationMode}" == "Debug" ]] && dialogBinaryDebugArgs=(--verbose --resizable --debug red)

# Dock-enabled launch defaults
dialogDockNamedApp="/Library/Application Support/Dialog/${humanReadableScriptName}.app"
dialogLaunchBinary="${dialogBinary}"
dialogDockIcon="default"
dialogDockIconFile="/var/tmp/dockicon.png"
dialogOverlayIconFile="/var/tmp/overlayicon_${organizationScriptName}_$$.png"
listitemLength="0"
remainingChecks="0"
completedCheckIndicesCsv=","

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
if system_profiler SPPowerDataType 2>/dev/null | grep -q "Battery Power"; then
    icon="SF=laptopcomputer.and.arrow.down,${organizationColorScheme}"
else
    icon="SF=desktopcomputer.and.arrow.down,${organizationColorScheme}"
fi

# Process the overlayicon from ${organizationOverlayiconURL}
overlayicon="/System/Library/CoreServices/Apple Diagnostics.app"
if [[ -n "${organizationOverlayiconURL}" ]]; then
    # Local file path (file or app bundle)
    if [[ -e "${organizationOverlayiconURL}" ]]; then
        overlayicon="${organizationOverlayiconURL}"

    # file:// URI
    elif [[ "${organizationOverlayiconURL}" == file://* ]]; then
        overlayIconPath="${organizationOverlayiconURL#file://}"
        if [[ -e "${overlayIconPath}" ]]; then
            overlayicon="${overlayIconPath}"
        else
            echo "Error: Failed to locate overlayicon at '${overlayIconPath}'"
            overlayicon="/System/Library/CoreServices/Apple Diagnostics.app"
        fi

    # Remote URL
    else
        curl -o "${dialogOverlayIconFile}" "${organizationOverlayiconURL}" --silent --show-error --fail
        if [[ "$?" -ne 0 ]]; then
            echo "Error: Failed to download the overlayicon"
            overlayicon="/System/Library/CoreServices/Apple Diagnostics.app"
        else
            overlayicon="${dialogOverlayIconFile}"
        fi
    fi
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
infobuttontext="${supportKB}"

# Optional dynamic IT support label/value pairs
# Leave a supportLabel blank (or its matching supportValue blank) to hide that line.
supportLabel1="Telephone"
supportValue1="${supportTeamPhone}"
supportLabel2="Email"
supportValue2="${supportTeamEmail}"
supportLabel3="Website"
supportValue3="${supportTeamWebsite}"
supportLabel4="Knowledge Base Article"
supportValue4="${supportKBURL}"
supportLabel5=""
supportValue5=""
supportLabel6=""
supportValue6=""



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# JSON Helpers
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function validateJson() {

    local jsonPayload="${1}"

    printf '%s' "${jsonPayload}" | jq . >/dev/null 2>&1

}

function compactJson() {

    local jsonPayload="${1}"

    printf '%s' "${jsonPayload}" | jq -c .

}

function prettyPrintJson() {

    local jsonPayload="${1}"

    printf '%s' "${jsonPayload}" | jq .

}

function jsonIsObject() {

    local jsonPayload="${1}"

    printf '%s' "${jsonPayload}" | jq -e 'type == "object"' >/dev/null 2>&1

}

function mergeDialogAndListItems() {

    local dialogJSON="${1}"
    local listitemJSON="${2}"

    jq -n --argjson dialog "${dialogJSON}" --argjson listitems "${listitemJSON}" '$dialog + { "listitem": $listitems }'

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Help Message Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Build support lines dynamically from supportLabelN/supportValueN when configured.
# If all supportLabelN/supportValueN pairs are empty, fall back to legacy supportTeam* values.
supportLines=""
supportFieldsConfigured="false"
supportButtonText=""
supportButtonAction=""

for supportIndex in {1..6}; do
    supportLabelVar="supportLabel${supportIndex}"
    supportValueVar="supportValue${supportIndex}"
    supportLabel="${(P)supportLabelVar}"
    supportValue="${(P)supportValueVar}"

    if [[ -n "${supportLabel}" || -n "${supportValue}" ]]; then
        supportFieldsConfigured="true"
    fi

    if [[ -n "${supportLabel}" && -n "${supportValue}" ]]; then
        supportLines+="- **${supportLabel}:** ${supportValue}<br>"

        if [[ -z "${supportButtonAction}" ]]; then
            case "${supportValue}" in
                http://*|https://*|slack://*|msteams://*|teams://*|zoommtg://*|mailto:* )
                    supportButtonText="${supportLabel}"
                    supportButtonAction="${supportValue}"
                    ;;
            esac
        fi
    fi
done

if [[ "${supportFieldsConfigured}" == "false" ]]; then
    [[ -n "${supportTeamPhone}" ]] && supportLines+="- **Telephone:** ${supportTeamPhone}<br>"
    [[ -n "${supportTeamEmail}" ]] && supportLines+="- **Email:** ${supportTeamEmail}<br>"
    [[ -n "${supportTeamWebsite}" ]] && supportLines+="- **Website:** ${supportTeamWebsite}<br>"
    [[ -n "${supportKBURL}" ]] && supportLines+="- **Knowledge Base Article:** ${supportKBURL}<br>"
fi

# Generic info button: prefer first URL-like dynamic value; otherwise use legacy KB defaults.
if [[ -n "${supportButtonAction}" ]]; then
    infobuttontext="${supportButtonText}"
    infobuttonaction="${supportButtonAction}"
fi

# Disable the button if the resolved action is not URL-like.
case "${infobuttonaction}" in
    http://*|https://*|slack://*|msteams://*|teams://*|zoommtg://*|mailto:* )
        helpimage="qr=${infobuttonaction}"
        ;;
    * )
        infobuttontext=""
        infobuttonaction=""
        helpimage=""
        ;;
esac

helpmessage="For assistance, please contact: **${supportTeamName}**<br>${supportLines}<br>**User Information:**<br>- **Full Name:** ${loggedInUserFullname}<br>- **User Name:** ${loggedInUser}<br>- **User ID:** ${loggedInUserID}<br>- **Volume Owners:** ${volumeOwnerList}<br>- **Secure Token:** ${secureToken}<br>- **Location Services:** ${locationServicesStatus}<br>- **Microsoft OneDrive Sync Date:** ${oneDriveSyncDate}<br>- **Platform SSOe:** ${platformSSOeResult}<br><br>**Computer Information:**<br>- **macOS:** ${osVersion} (${osBuild})<br>- **Dialog:** $(dialog -v)<br>- **Script:** ${scriptVersion}<br>- **Computer Name:** ${computerName}<br>- **Serial Number:** ${serialNumber}<br>- **Wi-Fi:** ${ssid}<br>- ${activeIPAddress}<br>- **VPN IP:** ${vpnStatus}"

case ${mdmVendor} in

    "Jamf Pro" )
        helpmessage+="<br><br>**Jamf Pro Information:**<br>- **Jamf Pro Computer ID:** ${jamfProID}<br>- **Site Name:** ${jamfProSiteName}"
        ;;

esac



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
    "infobuttontext" : "'"${infobuttontext}"'",
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
if ! validateJson "${mainDialogJSON}"; then
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
    {"title" : "Homebrew Status", "subtitle" : "If installed, compares the latest Homebrew release and any outdated packages", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Wi-Fi Strength", "subtitle" : "Checks current Wi-Fi signal strength and gives a simple quality rating.", "icon" : "SF=31.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=32.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'
# Validate addigyMdmListitemJSON is valid JSON
if ! validateJson "${addigyMdmListitemJSON}"; then
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
    {"title" : "Homebrew Status", "subtitle" : "If installed, compares the latest Homebrew release and any outdated packages", "icon" : "SF=28.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Wi-Fi Strength", "subtitle" : "Checks current Wi-Fi signal strength and gives a simple quality rating.", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=31.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'
# Validate filewaveMdmListitemJSON is valid JSON
if ! validateJson "${filewaveMdmListitemJSON}"; then
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
    {"title" : "Homebrew Status", "subtitle" : "If installed, compares the latest Homebrew release and any outdated packages", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Wi-Fi Strength", "subtitle" : "Checks current Wi-Fi signal strength and gives a simple quality rating.", "icon" : "SF=31.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=32.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'
# Validate fleetMdmListitemJSON is valid JSON
if ! validateJson "${fleetMdmListitemJSON}"; then
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
    {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=15.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Certificate Expiration", "subtitle" : "Validate the expiration date of the '${mdmVendor}' MDM certificate", "icon" : "SF=16.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=18.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=19.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=20.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=21.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=22.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Microsoft Teams", "subtitle" : "The hub for teamwork in Microsoft 365.", "icon" : "SF=23.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Microsoft One Drive", "subtitle" : "Microsoft cloud storage for your important files.", "icon" : "SF=24.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Microsoft Outlook", "subtitle" : "Email and Calendar from Microsoft.", "icon" : "SF=25.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Company Portal", "subtitle" : "Required for Platform Single Sign-On.", "icon" : "SF=26.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Zoom", "subtitle" : "Web Conferencing Tool.", "icon" : "SF=27.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Cortex", "subtitle" : "Cortex Security Software.", "icon" : "SF=28.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},    
    {"title" : "Netskope", "subtitle" : "Netskope Connection Software.", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},        
    {"title" : "Wi-Fi Strength", "subtitle" : "Checks current Wi-Fi signal strength and gives a simple quality rating.", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=31.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}]
'
# Validate kandjiMdmListitemJSON is valid JSON
if ! validateJson "${kandjiMdmListitemJSON}"; then
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
    {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=09.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "AirPlay Receiver", "subtitle" : "Ensure AirPlay Receiver is disabled when not needed", "icon" : "SF=10.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Bluetooth Sharing", "subtitle" : "Ensure Bluetooth Sharing is disabled when not needed", "icon" : "SF=11.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "VPN Client", "subtitle" : "Your Mac should have the proper VPN client installed and usable", "icon" : "SF=12.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Last Reboot", "subtitle" : "Restart your Mac regularly — at least once a week — can help resolve many common issues", "icon" : "SF=13.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Free Disk Space", "subtitle" : "Checks for the amount of free disk space on your Mac’s boot volume", "icon" : "SF=14.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Desktop Size and Item Count", "subtitle" : "Checks the size and item count of the Desktop", "icon" : "SF=15.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Downloads Size and Item Count", "subtitle" : "Checks the size and item count of the Downloads folder", "icon" : "SF=16.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Trash Size and Item Count", "subtitle" : "Checks the size and item count of the Trash", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Profile", "subtitle" : "The presence of the '${mdmVendor}' MDM profile helps ensure your Mac is enrolled", "icon" : "SF=18.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "'${mdmVendor}' MDM Certificate Expiration", "subtitle" : "Validate the expiration date of the '${mdmVendor}' MDM certificate", "icon" : "SF=19.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification service", "subtitle" : "Validate communication between Apple, '${mdmVendor}' and your Mac", "icon" : "SF=20.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Jamf Pro Check-In", "subtitle" : "Your Mac should check-in with the Jamf Pro MDM server multiple times each day", "icon" : "SF=21.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Jamf Pro Inventory", "subtitle" : "Your Mac should submit its inventory to the Jamf Pro MDM server daily", "icon" : "SF=22.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Push Notification Hosts","subtitle":"Test connectivity to Apple Push Notification hosts","icon":"SF=23.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Device Management","subtitle":"Test connectivity to Apple device enrollment and MDM services","icon":"SF=24.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Software and Carrier Updates","subtitle":"Test connectivity to Apple software update endpoints","icon":"SF=25.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Certificate Validation","subtitle":"Test connectivity to Apple certificate and OCSP services","icon":"SF=26.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Apple Identity and Content Services","subtitle":"Test connectivity to Apple Identity and Content services","icon":"SF=27.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "Jamf Hosts","subtitle":"Test connectivity to Jamf Pro cloud and on-prem endpoints","icon":"SF=28.circle,'"${organizationColorScheme}"'", "status":"pending","statustext":"Pending …", "iconalpha" : 0.5},
    {"title" : "App Auto-Patch", "subtitle" : "Keep your apps up-to-date to ensure their security and performance", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Homebrew Status", "subtitle" : "If installed, compares the latest Homebrew release and any outdated packages", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=31.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Microsoft Teams", "subtitle" : "The hub for teamwork in Microsoft 365.", "icon" : "SF=32.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "BeyondTrust Privilege Management", "subtitle" : "Privilege Management for Mac pairs powerful least-privilege management and application control", "icon" : "SF=33.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Cisco Umbrella", "subtitle" : "Cisco Umbrella combines multiple security functions so you can extend data protection anywhere.", "icon" : "SF=34.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "CrowdStrike Falcon", "subtitle" : "Technology, intelligence, and expertise come together in CrowdStrike Falcon to deliver security that works.", "icon" : "SF=35.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Palo Alto GlobalProtect", "subtitle" : "Virtual Private Network (VPN) connection to Church headquarters", "icon" : "SF=36.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Wi-Fi Strength", "subtitle" : "Checks current Wi-Fi signal strength and gives a simple quality rating.", "icon" : "SF=37.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=38.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Computer Inventory", "subtitle" : "The listing of your Mac’s apps and settings", "icon" : "SF=39.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'

# Validate jamfProListitemJSON is valid JSON
if ! validateJson "${jamfProListitemJSON}"; then
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
    {"title" : "Homebrew Status", "subtitle" : "If installed, compares the latest Homebrew release and any outdated packages", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Wi-Fi Strength", "subtitle" : "Checks current Wi-Fi signal strength and gives a simple quality rating.", "icon" : "SF=31.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=32.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'

# Validate jumpcloudMdmListitemJSON is valid JSON
if ! validateJson "${jumpcloudMdmListitemJSON}"; then
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
    {"title" : "Homebrew Status", "subtitle" : "If installed, compares the latest Homebrew release and any outdated packages", "icon" : "SF=29.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Wi-Fi Strength", "subtitle" : "Checks current Wi-Fi signal strength and gives a simple quality rating.", "icon" : "SF=31.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=32.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'

# Validate microsoftMdmListitemJSON is valid JSON
if ! validateJson "${microsoftMdmListitemJSON}"; then
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
    {"title" : "Homebrew Status", "subtitle" : "If installed, compares the latest Homebrew release and any outdated packages", "icon" : "SF=30.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=31.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Wi-Fi Strength", "subtitle" : "Checks current Wi-Fi signal strength and gives a simple quality rating.", "icon" : "SF=32.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=33.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'

# Validate mosyleListitemJSON is valid JSON
if ! validateJson "${mosyleListitemJSON}"; then
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
    {"title" : "Homebrew Status", "subtitle" : "If installed, compares the latest Homebrew release and any outdated packages", "icon" : "SF=25.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Electron Corner Mask", "subtitle" : "Detects susceptible Electron apps that may cause GPU slowdowns on macOS 26 Tahoe", "icon" : "SF=26.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Wi-Fi Strength", "subtitle" : "Checks current Wi-Fi signal strength and gives a simple quality rating.", "icon" : "SF=27.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
    {"title" : "Network Quality Test", "subtitle" : "Various networking-related tests of your Mac’s Internet connection", "icon" : "SF=28.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
]
'

# Validate genericMdmListitemJSON is valid JSON
if ! validateJson "${genericMdmListitemJSON}"; then
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
    local logEntry="${organizationScriptName} ($scriptVersion): $( date +%Y-%m-%d\ %H:%M:%S ) - ${1}"

    printf '%s\n' "${logEntry}" >> "${scriptLog}"

    if [[ "${suppressNonSplunkConsoleLogging}" != "true" ]] || [[ "${1}" == *"Splunk Reporting:"* ]]; then
        printf '%s\n' "${logEntry}"
    fi
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
# Dock-enabled swiftDialog helpers
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function resolveDockIcon() {

    local requestedDockIcon="${1}"
    local resolvedDockIcon="default"
    local localDockIconPath=""

    if [[ -z "${requestedDockIcon}" || "${requestedDockIcon:l}" == "default" ]]; then
        echo "${resolvedDockIcon}"
        return
    fi

    if [[ -e "${requestedDockIcon}" ]]; then
        echo "${requestedDockIcon}"
        return
    fi

    if [[ "${requestedDockIcon}" == file://* ]]; then
        localDockIconPath="${requestedDockIcon#file://}"
        if [[ -e "${localDockIconPath}" ]]; then
            echo "${localDockIconPath}"
            return
        fi
        notice "WARNING: Failed to locate dock icon at ${localDockIconPath}; falling back to default."
        echo "${resolvedDockIcon}"
        return
    fi

    if [[ "${requestedDockIcon}" == http://* || "${requestedDockIcon}" == https://* ]]; then
        if curl -o "${dialogDockIconFile}" "${requestedDockIcon}" --silent --show-error --fail; then
            echo "${dialogDockIconFile}"
            return
        fi
        notice "WARNING: Failed to download dock icon from ${requestedDockIcon}; falling back to default."
        echo "${resolvedDockIcon}"
        return
    fi

    notice "WARNING: Invalid dockIcon value (${requestedDockIcon}); falling back to default."
    echo "${resolvedDockIcon}"

}

function writeDockBadge() {

    local requestedBadgeValue="${1}"

    if [[ "${enableDockIntegration:l}" != "true" ]]; then
        return
    fi

    if [[ -z "${requestedBadgeValue}" ]] || [[ "${requestedBadgeValue:l}" == "remove" ]]; then
        echo "dockiconbadge: remove" >> "${dialogCommandFile}"
    else
        echo "dockiconbadge: ${requestedBadgeValue}" >> "${dialogCommandFile}"
    fi

}

function prepareDockNamedDialogApp() {

    local sourceApp="${dialogAppBundle}"
    local destinationApp="${dialogDockNamedApp}"
    local destinationMacOSDirectory="${destinationApp}/Contents/MacOS"
    local destinationDialogCliBinary="${destinationApp}/Contents/MacOS/dialogcli"
    local destinationDialogBinary="${destinationMacOSDirectory}/Dialog"
    local destinationExpectedBinary="${destinationMacOSDirectory}/${humanReadableScriptName}"

    if [[ ! -d "${sourceApp}" ]]; then
        notice "WARNING: swiftDialog app bundle not found at ${sourceApp}; using ${dialogBinary}." 1>&2
        echo "${dialogBinary}"
        return
    fi

    if [[ "${destinationApp}" != "${sourceApp}" ]]; then
        if [[ -e "${destinationApp}" ]]; then
            rm -rf "${destinationApp}" 2>/dev/null
            if [[ -e "${destinationApp}" ]]; then
                notice "WARNING: Unable to replace ${destinationApp}; using ${dialogBinary}." 1>&2
                echo "${dialogBinary}"
                return
            fi
        fi

        if ! cp -R "${sourceApp}" "${destinationApp}" 2>/dev/null; then
            notice "WARNING: Failed to copy ${sourceApp} to ${destinationApp}; using ${dialogBinary}." 1>&2
            echo "${dialogBinary}"
            return
        fi

        # Remove resource forks and Finder metadata copied from the source bundle;
        # codesign refuses to sign bundles containing such detritus.
        xattr -cr "${destinationApp}" 2>/dev/null
    fi

    if [[ -x "${destinationDialogCliBinary}" && -x "${destinationDialogBinary}" ]]; then
        # dialogcli resolves the app binary by app-name; provide that expected name.
        if [[ ! -x "${destinationExpectedBinary}" ]]; then
            ln -s "Dialog" "${destinationExpectedBinary}" 2>/dev/null || \
                cp -f "${destinationDialogBinary}" "${destinationExpectedBinary}" 2>/dev/null
        fi

        if [[ ! -x "${destinationExpectedBinary}" ]]; then
            notice "WARNING: Failed to create ${destinationExpectedBinary}; using ${dialogBinary}." 1>&2
            echo "${dialogBinary}"
            return
        fi

        # Adding a file to Contents/MacOS invalidates the bundle's sealed resources;
        # re-sign with an ad-hoc identity to restore a valid seal before launching.
        # --deep is intentionally omitted: inner binaries retain their original signatures;
        # only the outer bundle seal needs to be updated to include the new symlink.
        if ! codesign --force --sign - "${destinationApp}" 2>/dev/null; then
            notice "WARNING: Failed to re-sign ${destinationApp}; using ${dialogBinary}." 1>&2
            echo "${dialogBinary}"
            return
        fi

        echo "${destinationDialogCliBinary}"
    else
        notice "WARNING: Required dialog binaries missing in ${destinationMacOSDirectory}; using ${dialogBinary}." 1>&2
        echo "${dialogBinary}"
    fi

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update the running dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dialogUpdate(){
    local dialogCommand="${1}"
    local listItemIndex=""
    local listItemStatus=""

    if [[ "${dialogCommand}" == listitem:* ]]; then
        listItemIndex="$( getDialogListItemIndex "${dialogCommand}" )"
        listItemStatus="$( getDialogListItemStatus "${dialogCommand}" )"

        if [[ -n "${listItemIndex}" ]] && [[ -n "${listItemStatus}" ]] && [[ "${listItemStatus}" != "wait" ]] && [[ "${listItemStatus}" != "pending" ]]; then
            recordHealthCheckResult "${listItemIndex}" "${dialogCommand}"
        fi
    fi

    if [[ "${operationMode}" != "Silent" ]]; then
        sleep 0.1
        echo "${dialogCommand}" >> "${dialogCommandFile}"

        # Track check completion from listitem status transitions and update dock badge.
        if [[ -n "${listItemIndex}" ]] && [[ -n "${listItemStatus}" ]] && [[ "${listItemStatus}" != "wait" ]] && [[ "${listItemStatus}" != "pending" ]]; then
            if [[ "${remainingChecks}" != <-> ]]; then
                remainingChecks="0"
            fi

            if [[ "${completedCheckIndicesCsv}" != *",${listItemIndex},"* ]]; then
                completedCheckIndicesCsv="${completedCheckIndicesCsv}${listItemIndex},"
                (( remainingChecks > 0 )) && (( remainingChecks-- ))

                if (( remainingChecks > 0 )); then
                    writeDockBadge "${remainingChecks}"
                else
                    writeDockBadge "remove"
                fi
            fi
        fi
    fi
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Run command as logged-in user (thanks, @scriptingosx!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function runAsUser() {

    info "Run \"$@\" as \"$loggedInUserID\" … " 1>&2
    launchctl asuser "$loggedInUserID" sudo -u "$loggedInUser" "$@"

}

function runHomebrewAsUser() {

    local brewBinary="${1}"
    shift
    local homebrewPath="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

    info "Run Homebrew \"${brewBinary} $*\" as \"${loggedInUserID}\" … " 1>&2
    launchctl asuser "${loggedInUserID}" sudo -H -u "${loggedInUser}" env \
        HOME="${loggedInUserHomeDirectory}" \
        USER="${loggedInUser}" \
        LOGNAME="${loggedInUser}" \
        PATH="${homebrewPath}" \
        zsh -lc '
            export HOME="$1"
            export USER="$2"
            export LOGNAME="$2"
            export PATH="$3"
            export HOMEBREW_NO_AUTO_UPDATE=1
            shift 3
            "$@"
        ' zsh "${loggedInUserHomeDirectory}" "${loggedInUser}" "${homebrewPath}" "${brewBinary}" "$@"

}

function launchAsUserInBackground() {
    local user="$1"
    shift
    local userID=""

    if [[ -z "${user}" ]]; then
        "$@" &
        dialogPID=$!
        return 0
    fi

    userID="$( id -u "${user}" 2>/dev/null )"
    if [[ ! "${userID}" == <-> ]]; then
        errorOut "Unable to resolve user ID for '${user}' while launching background process"
        return 1
    fi

    launchctl asuser "${userID}" sudo -u "${user}" "$@" &
    dialogPID=$!
    return 0

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
# --- New in `4.0.0` ------------------------------------------------------------------------------
# Result-collection Helpers
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function sanitizeCheckKey() {

    local rawValue="${1:l}"

    rawValue="${rawValue//[^a-z0-9]/_}"
    rawValue="${rawValue//__/_}"
    rawValue="${rawValue##_}"
    rawValue="${rawValue%%_}"
    [[ -z "${rawValue}" ]] && rawValue="check"

    echo "${rawValue}"

}

function getDialogListItemIndex() {

    local dialogCommand="${1}"
    local listItemIndexRaw=""
    local listItemIndex=""

    listItemIndexRaw="${dialogCommand#*index: }"
    listItemIndex="${listItemIndexRaw%%,*}"
    listItemIndex="${listItemIndex//[^0-9]/}"

    echo "${listItemIndex}"

}

function getDialogListItemStatus() {

    local dialogCommand="${1}"
    local listItemStatusRaw=""
    local listItemStatus=""

    if [[ "${dialogCommand}" != *"status: "* ]]; then
        echo ""
        return
    fi

    listItemStatusRaw="${dialogCommand#*status: }"
    listItemStatus="${listItemStatusRaw%%,*}"
    listItemStatus="${listItemStatus//[[:space:]]/}"
    listItemStatus="${listItemStatus:l}"

    echo "${listItemStatus}"

}

function getDialogListItemStatustext() {

    local dialogCommand="${1}"
    local statustext=""

    if [[ "${dialogCommand}" != *"statustext: "* ]]; then
        echo ""
        return
    fi

    statustext="${dialogCommand#*statustext: }"
    echo "${statustext}"

}

function getDialogListItemSubtitle() {

    local dialogCommand="${1}"
    local subtitle=""

    if [[ "${dialogCommand}" != *"subtitle: "* ]]; then
        echo ""
        return
    fi

    subtitle="${dialogCommand#*subtitle: }"
    subtitle="${subtitle%%, status:*}"
    echo "${subtitle}"

}

function normalizeCheckStatus() {

    case "${1:l}" in
        "success" )
            echo "healthy"
            ;;
        "error" )
            echo "warning"
            ;;
        "fail" )
            echo "fail"
            ;;
        "warning" )
            echo "warning"
            ;;
        "healthy" | "error_internal" )
            echo "${1:l}"
            ;;
        * )
            echo "error"
            ;;
    esac

}

function recordHealthCheckResult() {

    local listItemIndex="${1}"
    local dialogCommand="${2}"
    local title="${checkTitleByIndex[${listItemIndex}]}"
    local normalizedStatus=""
    local statusText=""
    local remediationText=""
    local messageText=""

    [[ -z "${title}" ]] && title="Check ${listItemIndex}"
    [[ -z "${checkKeyByIndex[${listItemIndex}]}" ]] && checkKeyByIndex[${listItemIndex}]="$( sanitizeCheckKey "${title}" )"

    normalizedStatus="$( normalizeCheckStatus "$( getDialogListItemStatus "${dialogCommand}" )" )"
    statusText="$( getDialogListItemStatustext "${dialogCommand}" )"
    remediationText="$( getDialogListItemSubtitle "${dialogCommand}" )"
    messageText="${remediationText:-${statusText}}"

    if [[ "${messageText}" == "${organizationBoilerplateComplianceMessage}" ]] && [[ -n "${statusText}" ]]; then
        messageText="${statusText}"
    fi

    checkNormalizedStatusByIndex[${listItemIndex}]="${normalizedStatus}"
    checkStatustextByIndex[${listItemIndex}]="${statusText}"
    checkInspectTextByIndex[${listItemIndex}]="${statusText}"
    checkRemediationByIndex[${listItemIndex}]="${remediationText}"
    checkMessageByIndex[${listItemIndex}]="${messageText}"
    checkExecutedByIndex[${listItemIndex}]="true"
    checkIndexByTitle[${title}]="${listItemIndex}"

}

function initializeCheckMetadataFromCombinedJSON() {

    local title=""

    for (( i=0; i<listitemLength; i++ )); do
        title="$( get_json_value "${combinedJSON}" "listitem[${i}].title" 2>/dev/null )"
        [[ -z "${title}" ]] && title="Check ${i}"
        checkTitleByIndex[${i}]="${title}"
        checkKeyByIndex[${i}]="$( sanitizeCheckKey "${title}" )"
        checkIndexByTitle[${title}]="${i}"
    done

}

function rebuildResultBuckets() {

    reportHealthyChecks=()
    reportWarningChecks=()
    reportFailChecks=()
    reportErrorChecks=()

    for (( i=0; i<listitemLength; i++ )); do
        if [[ "${checkExecutedByIndex[${i}]}" == "true" ]]; then
            case "${checkNormalizedStatusByIndex[${i}]}" in
                "healthy" )
                    reportHealthyChecks+=( "${checkTitleByIndex[${i}]}" )
                    ;;
                "warning" )
                    reportWarningChecks+=( "${checkTitleByIndex[${i}]}" )
                    ;;
                "fail" )
                    reportFailChecks+=( "${checkTitleByIndex[${i}]}" )
                    ;;
                * )
                    reportErrorChecks+=( "${checkTitleByIndex[${i}]}" )
                    ;;
            esac
        fi
    done

}

function rebuildOverallHealthFromRecordedResults() {

    overallHealth=""
    rebuildResultBuckets

    for (( i=0; i<listitemLength; i++ )); do
        if [[ "${checkExecutedByIndex[${i}]}" == "true" ]] && [[ "${checkNormalizedStatusByIndex[${i}]}" != "healthy" ]]; then
            overallHealth+="${checkTitleByIndex[${i}]}; "
        fi
    done

}

function addReportingError() {

    local messageText="${1}"

    (( reportingErrorCount++ ))
    if [[ -n "${reportingErrors}" ]]; then
        reportingErrors+="; ${messageText}"
    else
        reportingErrors="${messageText}"
    fi

    warning "Splunk Reporting: ${messageText}"

}

function calculateOverallReportStatus() {

    rebuildResultBuckets

    if (( reportingErrorCount > 0 )) || (( ${#reportErrorChecks[@]} > 0 )); then
        reportOverallStatus="error"
    elif (( ${#reportFailChecks[@]} > 0 )); then
        reportOverallStatus="fail"
    elif (( ${#reportWarningChecks[@]} > 0 )); then
        reportOverallStatus="warning"
    else
        reportOverallStatus="healthy"
    fi

}

function getCheckRawValueByTitle() {

    local title="${1}"
    local index="${checkIndexByTitle[${title}]}"

    echo "${checkStatustextByIndex[${index}]}"

}

function getCheckMessageByTitle() {

    local title="${1}"
    local index="${checkIndexByTitle[${title}]}"

    echo "${checkMessageByIndex[${index}]}"

}

function getCheckStatusByTitle() {

    local title="${1}"
    local index="${checkIndexByTitle[${title}]}"

    echo "${checkNormalizedStatusByIndex[${index}]}"

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# --- New in `4.0.0` ------------------------------------------------------------------------------
# Splunk Reporting Helpers
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function jsonEscape() {

    local escapedValue="${1}"

    escapedValue="${escapedValue//\\/\\\\}"
    escapedValue="${escapedValue//\"/\\\"}"
    escapedValue="${escapedValue//$'\n'/\\n}"
    escapedValue="${escapedValue//$'\r'/\\r}"
    escapedValue="${escapedValue//$'\t'/\\t}"
    escapedValue="${escapedValue//$'\f'/\\f}"
    escapedValue="${escapedValue//$'\b'/\\b}"

    printf '%s' "${escapedValue}"

}

function jsonString() {
    printf '"%s"' "$( jsonEscape "${1}" )"
}

function buildJSONStringArray() {

    local values=( "$@" )
    local arrayJSON="["
    local separator=""

    for value in "${values[@]}"; do
        arrayJSON+="${separator}$( jsonString "${value}" )"
        separator=","
    done

    arrayJSON+="]"
    printf '%s' "${arrayJSON}"

}

function generateReportTimestamp() {

    reportTimestampEpoch="$( date +%s )"
    reportTimestamp="$( date '+%Y-%m-%dT%H:%M:%S%z' | sed -E 's/(..)$/:\1/' )"

}

function buildChecksJSONArray() {

    local checksJSON="["
    local separator=""
    local title=""
    local key=""
    local normalizedStatus=""
    local message=""
    local rawValue=""
    local remediation=""

    for (( i=0; i<listitemLength; i++ )); do
        if [[ "${checkExecutedByIndex[${i}]}" == "true" ]]; then
            title="${checkTitleByIndex[${i}]}"
            key="${checkKeyByIndex[${i}]}"
            normalizedStatus="${checkNormalizedStatusByIndex[${i}]}"
            message="${checkMessageByIndex[${i}]}"
            rawValue="${checkStatustextByIndex[${i}]}"
            remediation="${checkRemediationByIndex[${i}]}"

            checksJSON+="${separator}{"
            checksJSON+="\"index\":${i},"
            checksJSON+="\"key\":$( jsonString "${key}" ),"
            checksJSON+="\"name\":$( jsonString "${title}" ),"
            checksJSON+="\"status\":$( jsonString "${normalizedStatus}" ),"
            checksJSON+="\"message\":$( jsonString "${message}" ),"
            checksJSON+="\"rawValue\":$( jsonString "${rawValue}" ),"
            checksJSON+="\"remediation\":$( jsonString "${remediation}" )"
            checksJSON+="}"
            separator=","
        fi
    done

    checksJSON+="]"
    printf '%s' "${checksJSON}"

}

function buildMacHealthReportJSON() {

    local mdmProfileTitle="${mdmVendor} MDM Profile"
    local mdmCertificateTitle="${mdmVendor} MDM Certificate Expiration"
    local mdmProfileStatus="not_run"
    local mdmProfileResult=""
    local mdmCertificateResult=""
    local mdmLastCheckIn=""
    local mdmLastInventory=""
    local apnsResult=""
    local lastRebootResult=""
    local fileVaultResult=""
    local diskSpaceResult=""
    local sipResult=""
    local ssvResult=""
    local firewallResult=""
    local checksJSON=""
    local metadataJSON=""
    local summaryJSON=""
    local systemInfoJSON=""
    local mdmJSON=""
    local -a reportingErrorItems

    if [[ -n "${reportingErrors}" ]]; then
        reportingErrorItems=( "${(@s/; /)reportingErrors}" )
    else
        reportingErrorItems=()
    fi

    if [[ "${mdmVendor}" != "None" ]]; then
        mdmProfileStatus="$( getCheckStatusByTitle "${mdmProfileTitle}" )"
        mdmProfileResult="$( getCheckRawValueByTitle "${mdmProfileTitle}" )"
        mdmCertificateResult="$( getCheckRawValueByTitle "${mdmCertificateTitle}" )"
    fi

    apnsResult="$( getCheckRawValueByTitle "Apple Push Notification service" )"
    lastRebootResult="$( getCheckRawValueByTitle "Last Reboot" )"
    fileVaultResult="$( getCheckRawValueByTitle "FileVault Encryption" )"
    diskSpaceResult="$( getCheckRawValueByTitle "Free Disk Space" )"
    sipResult="$( getCheckRawValueByTitle "System Integrity Protection" )"
    ssvResult="$( getCheckRawValueByTitle "Signed System Volume" )"
    firewallResult="$( getCheckRawValueByTitle "Firewall" )"

    case "${mdmVendor}" in
        "Jamf Pro" )
            mdmLastCheckIn="$( getCheckRawValueByTitle "Jamf Pro Check-In" )"
            mdmLastInventory="$( getCheckRawValueByTitle "Jamf Pro Inventory" )"
            ;;
        "Mosyle" )
            mdmLastCheckIn="$( getCheckRawValueByTitle "Mosyle Check-In" )"
            ;;
    esac

    checksJSON="$( buildChecksJSONArray )"

    metadataJSON="{"
    metadataJSON+="\"scriptVersion\":$( jsonString "${scriptVersion}" ),"
    metadataJSON+="\"timestamp\":$( jsonString "${reportTimestamp}" ),"
    metadataJSON+="\"hostname\":$( jsonString "${hostName}" ),"
    metadataJSON+="\"localHostName\":$( jsonString "${localHostName}" ),"
    metadataJSON+="\"serialNumber\":$( jsonString "${serialNumber}" ),"
    metadataJSON+="\"hardwareUUID\":$( jsonString "${hardwareUUID}" ),"
    metadataJSON+="\"operationMode\":$( jsonString "${operationMode}" ),"
    metadataJSON+="\"reportingMode\":$( jsonString "${splunkOperationMode}" ),"
    metadataJSON+="\"jsonTool\":$( jsonString "${reportJSONTool}" )"
    metadataJSON+="}"

    summaryJSON="{"
    summaryJSON+="\"overallStatus\":$( jsonString "${reportOverallStatus}" ),"
    summaryJSON+="\"healthyCount\":${#reportHealthyChecks[@]},"
    summaryJSON+="\"warningCount\":${#reportWarningChecks[@]},"
    summaryJSON+="\"failCount\":${#reportFailChecks[@]},"
    summaryJSON+="\"errorCount\":$(( ${#reportErrorChecks[@]} + reportingErrorCount )),"
    summaryJSON+="\"elapsedSeconds\":${SECONDS},"
    summaryJSON+="\"warningChecks\":$( buildJSONStringArray "${reportWarningChecks[@]}" ),"
    summaryJSON+="\"failedChecks\":$( buildJSONStringArray "${reportFailChecks[@]}" ),"
    summaryJSON+="\"reportingErrors\":$( buildJSONStringArray "${reportingErrorItems[@]}" )"
    summaryJSON+="}"

    systemInfoJSON="{"
    systemInfoJSON+="\"computerName\":$( jsonString "${computerName}" ),"
    systemInfoJSON+="\"computerModel\":$( jsonString "${computerModel}" ),"
    systemInfoJSON+="\"macOSVersion\":$( jsonString "${osVersion}" ),"
    systemInfoJSON+="\"macOSBuild\":$( jsonString "${osBuild}" ),"
    systemInfoJSON+="\"systemMemory\":$( jsonString "${systemMemory}" ),"
    systemInfoJSON+="\"systemStorage\":$( jsonString "${systemStorage}" ),"
    systemInfoJSON+="\"totalDiskBytes\":${totalDiskBytes:-0},"
    systemInfoJSON+="\"freeDiskSpace\":$( jsonString "${diskSpaceResult}" ),"
    systemInfoJSON+="\"lastReboot\":$( jsonString "${lastRebootResult}" ),"
    systemInfoJSON+="\"sipStatus\":$( jsonString "${sipResult:-${bootPoliciesSipStatus}}" ),"
    systemInfoJSON+="\"signedSystemVolumeStatus\":$( jsonString "${ssvResult:-${bootPoliciesSsvStatus}}" ),"
    systemInfoJSON+="\"firewallStatus\":$( jsonString "${firewallResult}" ),"
    systemInfoJSON+="\"fileVaultStatus\":$( jsonString "${fileVaultResult}" ),"
    systemInfoJSON+="\"ssid\":$( jsonString "${ssid}" ),"
    systemInfoJSON+="\"activeIPAddress\":$( jsonString "${activeIPAddress//\*\*/}" ),"
    systemInfoJSON+="\"vpnStatus\":$( jsonString "${vpnStatus} ${vpnExtendedStatus}" ),"
    systemInfoJSON+="\"networkTimeServer\":$( jsonString "${networkTimeServer}" ),"
    systemInfoJSON+="\"locationServicesStatus\":$( jsonString "${locationServicesStatus}" ),"
    systemInfoJSON+="\"bootstrapTokenStatus\":$( jsonString "${bootstrapTokenStatus}" ),"
    systemInfoJSON+="\"sshStatus\":$( jsonString "${sshStatus}" ),"
    systemInfoJSON+="\"oneDriveSyncDate\":$( jsonString "${oneDriveSyncDate}" ),"
    systemInfoJSON+="\"apnsStatus\":$( jsonString "${apnsResult}" )"
    systemInfoJSON+="}"

    mdmJSON="{"
    mdmJSON+="\"vendor\":$( jsonString "${mdmVendor}" ),"
    mdmJSON+="\"enrollmentStatus\":$( jsonString "${mdmProfileStatus:-unknown}" ),"
    mdmJSON+="\"serverURL\":$( jsonString "${serverURL}" ),"
    mdmJSON+="\"profileResult\":$( jsonString "${mdmProfileResult}" ),"
    mdmJSON+="\"profileUUID\":$( jsonString "${mdmVendorUuid}" ),"
    mdmJSON+="\"profileIdentifier\":$( jsonString "${mdmProfileIdentifier}" ),"
    mdmJSON+="\"certificateExpiration\":$( jsonString "${mdmCertificateResult}" ),"
    mdmJSON+="\"lastCheckIn\":$( jsonString "${mdmLastCheckIn}" ),"
    mdmJSON+="\"lastInventory\":$( jsonString "${mdmLastInventory}" ),"
    mdmJSON+="\"jamfProID\":$( jsonString "${jamfProID}" ),"
    mdmJSON+="\"jamfProSiteName\":$( jsonString "${jamfProSiteName}" )"
    mdmJSON+="}"

    printf '%s' "{"
    printf '%s' "\"metadata\":${metadataJSON},"
    printf '%s' "\"summary\":${summaryJSON},"
    printf '%s' "\"systemInfo\":${systemInfoJSON},"
    printf '%s' "\"mdm\":${mdmJSON},"
    printf '%s' "\"checks\":${checksJSON}"
    printf '%s' "}"

}

function buildFallbackReportJSON() {

    local -a reportingErrorItems

    if [[ -n "${reportingErrors}" ]]; then
        reportingErrorItems=( "${(@s/; /)reportingErrors}" )
    else
        reportingErrorItems=()
    fi

    printf '%s' "{"
    printf '%s' "\"metadata\":{"
    printf '%s' "\"scriptVersion\":$( jsonString "${scriptVersion}" ),"
    printf '%s' "\"timestamp\":$( jsonString "${reportTimestamp}" ),"
    printf '%s' "\"hostname\":$( jsonString "${hostName}" ),"
    printf '%s' "\"serialNumber\":$( jsonString "${serialNumber}" ),"
    printf '%s' "\"hardwareUUID\":$( jsonString "${hardwareUUID}" ),"
    printf '%s' "\"operationMode\":$( jsonString "${operationMode}" ),"
    printf '%s' "\"reportingMode\":$( jsonString "${splunkOperationMode}" )"
    printf '%s' "},"
    printf '%s' "\"summary\":{"
    printf '%s' "\"overallStatus\":\"error\","
    printf '%s' "\"errorCount\":$(( reportingErrorCount > 0 ? reportingErrorCount : 1 )),"
    printf '%s' "\"reportingErrors\":$( buildJSONStringArray "${reportingErrorItems[@]}" )"
    printf '%s' "},"
    printf '%s' "\"systemInfo\":{},"
    printf '%s' "\"mdm\":{},"
    printf '%s' "\"checks\":[]"
    printf '%s' "}"

}

function writeSecureJSONFile() {

    local targetPath="${1}"
    local jsonPayload="${2}"
    local previousUmask=""

    previousUmask="$( umask )"
    umask 077
    printf '%s\n' "${jsonPayload}" > "${targetPath}"
    umask "${previousUmask}"

    chmod 600 "${targetPath}" 2>/dev/null
    if [[ $(id -u) -eq 0 ]]; then
        chown root:wheel "${targetPath}" 2>/dev/null
    fi

}

function writeReadableTextFile() {

    local targetPath="${1}"
    local filePayload="${2}"
    local previousUmask=""

    previousUmask="$( umask )"
    umask 022
    printf '%s\n' "${filePayload}" > "${targetPath}"
    umask "${previousUmask}"

    chmod 644 "${targetPath}" 2>/dev/null
    if [[ $(id -u) -eq 0 ]]; then
        chown root:wheel "${targetPath}" 2>/dev/null
    fi

}

function sanitizeSplunkURLForLog() {

    local sanitizedURL="${1}"

    sanitizedURL="${sanitizedURL%%\?*}"
    sanitizedURL="${sanitizedURL%%#*}"

    printf '%s' "${sanitizedURL}"

}

function buildSplunkHECPayload() {

    local reportJSON="${1}"
    local hecPayload="{"
    local separator=""

    if [[ -n "${splunkHECSourcetype}" ]]; then
        hecPayload+="\"sourcetype\":$( jsonString "${splunkHECSourcetype}" )"
        separator=","
    fi

    if [[ -n "${splunkHECIndex}" ]]; then
        hecPayload+="${separator}\"index\":$( jsonString "${splunkHECIndex}" )"
        separator=","
    fi

    hecPayload+="${separator}\"event\":${reportJSON}}"

    printf '%s' "${hecPayload}"

}

function sendSplunkHECPayload() {

    local hecPayload="${1}"
    local payloadFile=""
    local responseFile=""
    local sanitizedURL=""
    local httpCode=""
    local curlExitCode=0
    local retryDelay=1
    local curlArgs=()

    sanitizedURL="$( sanitizeSplunkURLForLog "${splunkHECURL}" )"
    payloadFile="$( mktemp /var/tmp/mhc-splunk-payload.XXXXXX )"
    responseFile="$( mktemp /var/tmp/mhc-splunk-response.XXXXXX )"

    writeSecureJSONFile "${payloadFile}" "${hecPayload}"

    if [[ "${splunkAllowInsecureTLS:l}" == "true" ]] && [[ "${splunkReportDebug}" == "true" ]]; then
        curlArgs+=( --insecure )
        warning "Splunk Reporting: TLS verification override enabled for debug reporting."
    fi

    for attempt in 1 2 3; do
        reportTransmissionAttemptCount="${attempt}"
        info "Splunk Reporting: POST attempt ${attempt} to ${sanitizedURL}"

        httpCode="$(
            curl --silent --fail-with-body --max-time 15 \
                --header "Authorization: Splunk ${splunkHECToken}" \
                --header "Content-Type: application/json" \
                --data-binary "@${payloadFile}" \
                --output "${responseFile}" \
                --write-out "%{http_code}" \
                "${curlArgs[@]}" \
                "${splunkHECURL}" 2>/dev/null
        )"
        curlExitCode=$?
        reportTransmissionHttpCode="${httpCode}"

        if (( curlExitCode == 0 )) && [[ "${httpCode}" == 2* ]]; then
            reportTransmissionStatus="success"
            notice "Splunk Reporting: payload delivered successfully (HTTP ${httpCode})"
            rm -f "${payloadFile}" "${responseFile}"
            return 0
        fi

        if [[ "${httpCode}" == 5* ]] || [[ "${httpCode:-000}" == "000" ]]; then
            warning "Splunk Reporting: attempt ${attempt} failed (HTTP ${httpCode:-000}, curl ${curlExitCode}); retrying in ${retryDelay}s."
            if (( attempt < 3 )); then
                sleep "${retryDelay}"
                retryDelay=$(( retryDelay * 2 ))
                continue
            fi
        else
            warning "Splunk Reporting: request failed without retry (HTTP ${httpCode:-000}, curl ${curlExitCode})."
            break
        fi
    done

    reportTransmissionStatus="failed"
    addReportingError "Splunk HEC delivery failed after ${reportTransmissionAttemptCount} attempt(s) (HTTP ${reportTransmissionHttpCode:-000}, curl ${curlExitCode})"

    rm -f "${payloadFile}" "${responseFile}"
    return 1

}

function generateAndSendSplunkReport() {

    local reportJSON=""

    notice "Generating Splunk JSON report …"

    rebuildOverallHealthFromRecordedResults
    calculateOverallReportStatus
    generateReportTimestamp

    reportJSON="$( buildMacHealthReportJSON )"

    if ! validateJson "${reportJSON}"; then
        addReportingError "Generated report JSON failed validation; writing fallback error report."
        reportOverallStatus="error"
        reportJSON="$( buildFallbackReportJSON )"
    fi

    if [[ "${splunkPrettyPrintJSON}" == "true" ]]; then
        reportFilePayload="$( prettyPrintJson "${reportJSON}" )"
    else
        reportFilePayload="$( compactJson "${reportJSON}" )"
    fi

    reportHECPayload="$( compactJson "$( buildSplunkHECPayload "$( compactJson "${reportJSON}" )" )" )"

    writeSecureJSONFile "${splunkJSONReportPath}" "${reportFilePayload}"
    if [[ -f "${splunkJSONReportPath}" ]]; then
        reportGenerated="true"
        notice "Splunk Reporting: local report written to ${splunkJSONReportPath}"
    else
        addReportingError "Failed to write local JSON report to ${splunkJSONReportPath}"
        warning "Splunk Reporting: failed to write local report to ${splunkJSONReportPath}"
    fi

    if [[ "${splunkOperationMode}" == "off" ]]; then
        reportTransmissionStatus="disabled"
        info "Splunk Reporting: splunkOperationMode is off; local report only."
        return 0
    fi

    if [[ "${splunkOperationMode}" == "test" ]]; then
        reportTransmissionStatus="skipped_test_mode"
        notice "Splunk Reporting: test mode enabled; skipping Splunk HEC transmission."
        return 0
    fi

    if [[ -z "${splunkHECURL}" || -z "${splunkHECToken}" ]]; then
        reportTransmissionStatus="not_configured"
        info "Splunk Reporting: HEC URL or token not configured; local report only."
        return 0
    fi

    sendSplunkHECPayload "${reportHECPayload}"

}

function sendCachedSplunkReport() {

    local cachedReportJSON=""
    local cachedReportModificationEpoch=""
    local cachedReportAgeSeconds=0

    notice "Client-Side Cache: uploading cached Splunk JSON report from ${splunkJSONReportPath}"

    if [[ ! -f "${splunkJSONReportPath}" ]]; then
        warning "Client-Side Cache: cached report missing; unable to upload cached report."
        return 1
    fi

    cachedReportModificationEpoch=$( stat -f %m "${splunkJSONReportPath}" 2>/dev/null )
    cachedReportAgeSeconds=$(( $( date +%s ) - ${cachedReportModificationEpoch:-0} ))
    if (( cachedReportModificationEpoch <= 0 )) || (( cachedReportAgeSeconds > clientSideMaximumCacheAgeSeconds )); then
        warning "Client-Side Cache: cached report is stale (${cachedReportAgeSeconds}s old; maximum ${clientSideMaximumCacheAgeSeconds}s); unable to upload cached report."
        return 1
    fi

    cachedReportJSON="$( < "${splunkJSONReportPath}" )"

    if ! validateJson "${cachedReportJSON}"; then
        warning "Client-Side Cache: cached report failed JSON validation; unable to upload cached report."
        return 1
    fi

    if [[ -z "${splunkHECURL}" || -z "${splunkHECToken}" ]]; then
        reportTransmissionStatus="not_configured"
        warning "Client-Side Cache: HEC URL or token not configured; unable to upload cached report."
        return 1
    fi

    reportGenerated="true"
    reportHECPayload="$( compactJson "$( buildSplunkHECPayload "$( compactJson "${cachedReportJSON}" )" )" )"

    sendSplunkHECPayload "${reportHECPayload}"

}

function installClientSideScript() {

    local temporaryClientScript=""

    notice "Client-Side Cache: installing client-side script at ${clientSideScriptPath}"

    if [[ "${currentScriptPath}" == "${clientSideScriptPath}" ]]; then
        notice "Client-Side Cache: running from client-side script path; install skipped."
        return 0
    fi

    if [[ ! -r "${currentScriptPath}" ]]; then
        warning "Client-Side Cache: current script path is not readable (${currentScriptPath}); install skipped."
        return 1
    fi

    mkdir -p "${organizationDirectory}" || {
        warning "Client-Side Cache: unable to create ${organizationDirectory}"
        return 1
    }
    chown root:wheel "${organizationDirectory}" 2>/dev/null
    chmod 755 "${organizationDirectory}" 2>/dev/null

    temporaryClientScript="$( mktemp "/var/tmp/${organizationScriptName}.client.XXXXXX" )"
    cp "${currentScriptPath}" "${temporaryClientScript}" || {
        warning "Client-Side Cache: unable to copy ${currentScriptPath} to temporary client script."
        rm -f "${temporaryClientScript}"
        return 1
    }

    sed -i '' 's|operationMode="${4:-"Self Service"}"|operationMode="${4:-"Silent"}"|' "${temporaryClientScript}"

    awk '
        /^# Update Computer Inventory$/ { skipInventoryFunction=1; next }
        /^# Program$/ {
            if (skipInventoryFunction == 1) {
                skipInventoryFunction=0
                print
                next
            }
        }
        skipInventoryFunction == 1 { next }
        /"title" : "Computer Inventory"/ { next }
        /updateComputerInventory/ { next }
        /jamf[[:space:]]recon/ { next }
        { print }
    ' "${temporaryClientScript}" > "${clientSideScriptPath}" || {
        warning "Client-Side Cache: unable to write sanitized client-side script."
        rm -f "${temporaryClientScript}"
        return 1
    }

    sed -i '' '/"title" : "Network Quality Test"/ s/},$/}/' "${clientSideScriptPath}"

    rm -f "${temporaryClientScript}"

    if grep -q "jamf"" recon" "${clientSideScriptPath}" 2>/dev/null; then
        warning "Client-Side Cache: sanitized client-side script still contains Jamf inventory command text; install failed."
        rm -f "${clientSideScriptPath}"
        return 1
    fi

    chown root:wheel "${clientSideScriptPath}" 2>/dev/null
    chmod 755 "${clientSideScriptPath}" 2>/dev/null

    cat > "${launchDaemonPath}" <<ENDOFLAUNCHDAEMON
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${launchDaemonLabel}</string>
    <key>UserName</key>
    <string>root</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/zsh</string>
        <string>--no-rcs</string>
        <string>${clientSideScriptPath}</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/bin:/bin:/usr/sbin:/sbin:/usr/local:/usr/local/bin</string>
        <key>launchDaemonRun</key>
        <string>true</string>
    </dict>
    <key>StartCalendarInterval</key>
    <array>
        <dict>
            <key>Hour</key>
            <integer>${clientSideLaunchDaemonHour}</integer>
            <key>Minute</key>
            <integer>${clientSideLaunchDaemonMinute}</integer>
        </dict>
    </array>
    <key>StandardErrorPath</key>
    <string>${scriptLog}</string>
    <key>StandardOutPath</key>
    <string>${scriptLog}</string>
</dict>
</plist>
ENDOFLAUNCHDAEMON

    if ! plutil -lint "${launchDaemonPath}" >> "${scriptLog}" 2>&1; then
        warning "Client-Side Cache: generated LaunchDaemon plist failed validation at ${launchDaemonPath}"
        return 1
    fi

    chown root:wheel "${launchDaemonPath}" 2>/dev/null
    chmod 644 "${launchDaemonPath}" 2>/dev/null

    if launchctl print "system/${launchDaemonLabel}" >/dev/null 2>&1; then
        launchctl bootout "system/${launchDaemonLabel}" >> "${scriptLog}" 2>&1 || true
    fi
    launchctl enable "system/${launchDaemonLabel}" >> "${scriptLog}" 2>&1 || true
    if ! launchctl bootstrap system "${launchDaemonPath}" >> "${scriptLog}" 2>&1; then
        warning "Client-Side Cache: unable to bootstrap ${launchDaemonPath}"
        return 1
    fi
    launchctl enable "system/${launchDaemonLabel}" >> "${scriptLog}" 2>&1

    notice "Client-Side Cache: installed client-side script and LaunchDaemon ${launchDaemonLabel}."
    return 0

}

function xmlEscape() {

    local escapedValue="${1}"

    escapedValue="${escapedValue//&/&amp;}"
    escapedValue="${escapedValue//</&lt;}"
    escapedValue="${escapedValue//>/&gt;}"
    escapedValue="${escapedValue//\"/&quot;}"
    escapedValue="${escapedValue//\'/&apos;}"

    printf '%s' "${escapedValue}"

}

function getInspectWindowTitle() {

    echo "${humanReadableScriptName} (${scriptVersion})"

}

function getInspectOverallStatusLabel() {

    case "${reportOverallStatus}" in
        "healthy" )
            echo "Healthy"
            ;;
        "warning" )
            echo "Needs Attention"
            ;;
        "fail" )
            echo "Unhealthy"
            ;;
        * )
            echo "Check Incomplete"
            ;;
    esac

}

function getDisplayStatusLabelFromNormalizedStatus() {

    local normalizedStatus="${1}"

    case "${normalizedStatus}" in
        "healthy" )
            echo "Healthy"
            ;;
        "warning" )
            echo "Warning"
            ;;
        "fail" )
            echo "Failed"
            ;;
        * )
            echo "Error"
            ;;
    esac

}

function getInspectSectionIcon() {

    if [[ -n "${dockIcon}" && "${dockIcon}" != "default" ]]; then
        echo "${dockIcon}"
    elif [[ -n "${organizationOverlayiconURL}" ]]; then
        echo "${organizationOverlayiconURL}"
    else
        echo "/System/Library/CoreServices/Apple Diagnostics.app"
    fi

}

function getInspectSupportButtonIcon() {

    local buttonAction="${1:-${supportButtonAction}}"

    case "${buttonAction}" in
        mailto:* )
            echo "envelope.fill"
            ;;
        slack://*|msteams://*|teams://*|zoommtg://* )
            echo "message.fill"
            ;;
        * )
            echo "safari.fill"
            ;;
    esac

}

function getInspectSupportButtonURL() {

    case "${supportTeamWebsite}" in
        http://*|https://* )
            echo "${supportTeamWebsite}"
            ;;
        * )
            echo "${supportButtonAction}"
            ;;
    esac

}

function getInspectSupportButtonText() {

    local buttonURL="${1:-$( getInspectSupportButtonURL )}"

    if [[ -n "${supportTeamWebsite}" ]] && [[ "${buttonURL}" == "${supportTeamWebsite}" ]]; then
        echo "Website"
    else
        echo "${supportButtonText:-${buttonURL}}"
    fi

}

function normalizeInspectSupportValue() {

    local supportValue="${1}"
    local linkText=""
    local linkURL=""

    if [[ "${supportValue}" == \[*\]\(*\) ]]; then
        linkText="${supportValue#\[}"
        linkText="${linkText%%\]*}"
        linkURL="${supportValue#*\(}"
        linkURL="${linkURL%\)}"
        supportValue="${linkText}: ${linkURL}"
    fi

    printf '%s' "${supportValue}"

}

function getInspectIntroductionText() {

    case "${reportOverallStatus}" in
        "healthy" )
            echo "Your recent Mac Health Check results are ready to review. All executed checks completed with healthy results."
            ;;
        "warning" )
            echo "Your recent Mac Health Check results are ready to review. Some executed checks need attention."
            ;;
        "fail" )
            echo "Your recent Mac Health Check results are ready to review. One or more executed checks failed."
            ;;
        * )
            echo "Your recent Mac Health Check results are ready to review. One or more executed checks could not be evaluated cleanly."
            ;;
    esac

}

function formatInspectTimestampForDisplay() {

    local rawTimestamp="${1}"
    local parsedTimestamp="${rawTimestamp}"
    local formattedTimestamp=""

    if [[ -z "${rawTimestamp}" ]]; then
        return
    fi

    if [[ "${rawTimestamp}" == *[+-]??:?? ]]; then
        parsedTimestamp="${rawTimestamp%:*}${rawTimestamp##*:}"
        formattedTimestamp="$( date -j -f '%Y-%m-%dT%H:%M:%S%z' "${parsedTimestamp}" '+%A, %B %d at %I:%M %p %Z' 2>/dev/null )"
    elif [[ "${rawTimestamp}" == *Z ]]; then
        formattedTimestamp="$( date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "${rawTimestamp}" '+%A, %B %d at %I:%M %p %Z' 2>/dev/null )"
    fi

    if [[ -n "${formattedTimestamp}" ]]; then
        echo "${formattedTimestamp}"
    else
        echo "${rawTimestamp}"
    fi

}

function getInspectResultsTimestampText() {

    local inspectDisplayTimestamp=""

    if [[ -n "${reportTimestamp}" ]]; then
        inspectDisplayTimestamp="$( formatInspectTimestampForDisplay "${reportTimestamp}" )"
        echo "Results as of: ${inspectDisplayTimestamp}"
    else
        echo "Results as of: $( date '+%A, %B %d at %I:%M %p %Z' )"
    fi

}

function getInspectUnhealthyCount() {

    echo $(( ${#reportWarningChecks[@]} + ${#reportFailChecks[@]} + ${#reportErrorChecks[@]} ))

}

function getInspectResultsSummaryText() {

    local healthyCount="${#reportHealthyChecks[@]}"
    local warningCount="${#reportWarningChecks[@]}"
    local failCount="${#reportFailChecks[@]}"
    local errorCountLocal="${#reportErrorChecks[@]}"
    local executedCount=$(( healthyCount + warningCount + failCount + errorCountLocal ))

    echo "${executedCount} checks executed. Healthy: ${healthyCount}. Warnings: ${warningCount}. Failures: ${failCount}. Errors: ${errorCountLocal}. Only healthy results count as compliant. Overall status: $( getInspectOverallStatusLabel )."

}

function getInspectUnhealthyResultsSummaryText() {

    local warningCount="${#reportWarningChecks[@]}"
    local failCount="${#reportFailChecks[@]}"
    local errorCountLocal="${#reportErrorChecks[@]}"
    local unhealthyCount=$(( warningCount + failCount + errorCountLocal ))

    echo "${unhealthyCount} checks need attention. Warnings: ${warningCount}. Failures: ${failCount}. Errors: ${errorCountLocal}. Overall status: $( getInspectOverallStatusLabel )."

}

function getInspectHealthyResultsSummaryText() {

    local healthyCount="${#reportHealthyChecks[@]}"

    echo "${healthyCount} checks completed successfully and remain compliant."

}

function getInspectPreferredResultTextByIndex() {

    local index="${1}"
    local rawValue="${checkInspectTextByIndex[${index}]}"
    local message="${checkMessageByIndex[${index}]}"

    if [[ -n "${rawValue}" && "${rawValue}" != "Pending ..." && "${rawValue}" != "Pending …" ]]; then
        echo "${rawValue}"
    elif [[ -n "${message}" ]]; then
        echo "${message}"
    else
        echo "Result unavailable"
    fi

}

function getInspectExpectedComparisonTextByIndex() {

    local index="${1}"
    local title="${checkTitleByIndex[${index}]}"
    local normalizedStatus="${checkNormalizedStatusByIndex[${index}]}"
    local rawValue="${checkStatustextByIndex[${index}]}"
    local message="${checkMessageByIndex[${index}]}"
    local remediation="${checkRemediationByIndex[${index}]}"

    case "${title}" in
        "macOS Version" )
            echo "Supported macOS release"
            return
            ;;
        "Available Updates" )
            echo "No updates pending"
            return
            ;;
        "System Integrity Protection" | "Signed System Volume" | "Firewall" | "FileVault Encryption" | "Gatekeeper / XProtect" )
            echo "Enabled"
            return
            ;;
        "Touch ID" )
            echo "Enrolled"
            return
            ;;
        "VPN Client" )
            echo "Connected when required"
            return
            ;;
        "Last Reboot" )
            echo "Restarted within policy"
            return
            ;;
        "Free Disk Space" )
            echo "At least ${allowedMinimumFreeDiskPercentage}% free"
            return
            ;;
        "Desktop Size and Item Count" )
            echo "At most ${allowedMaximumDirectoryPercentage}% of disk"
            return
            ;;
        "Downloads Size and Item Count" )
            echo "At most ${allowedMaximumDirectoryPercentage}% of disk"
            return
            ;;
        "Trash Size and Item Count" )
            echo "At most ${allowedMaximumDirectoryPercentage}% of disk"
            return
            ;;
        "Password Hint" )
            echo "Not set"
            return
            ;;
        "AirDrop" )
            echo "No One / Contacts Only"
            return
            ;;
        "AirPlay Receiver" | "Bluetooth Sharing" )
            echo "Disabled"
            return
            ;;
        *"MDM Profile" )
            echo "Installed"
            return
            ;;
        *"MDM Certificate Expiration" )
            echo "Certificate not expired"
            return
            ;;
        "Apple Push Notification service" )
            echo "Recent APNS communication"
            return
            ;;
        *"Check-In" )
            echo "Checked in recently"
            return
            ;;
        *"Inventory" )
            echo "Inventory updated recently"
            return
            ;;
        "Apple Push Notification Hosts" | "Apple Device Management" | "Apple Software and Carrier Updates" | "Apple Certificate Validation" | "Apple Identity and Content Services" )
            echo "Reachable"
            return
            ;;
        "Homebrew Status" )
            echo "Current or not installed"
            return
            ;;
        "Electron Corner Mask" )
            echo "No susceptible Electron apps detected"
            return
            ;;
        "Network Quality Test" )
            echo "Network quality passed"
            return
            ;;
        "Microsoft Teams" | "Fleet Desktop" )
            echo "Installed"
            return
            ;;
        "Wi-Fi Strength" )
            printf '%s\n' "Excellent >= -55" "Good >= -65" "Fair >= -75, Poor < -75"
            return
            ;;
    esac

    if [[ -n "${remediation}" && "${remediation}" != "${organizationBoilerplateComplianceMessage}" && "${remediation}" != "${message}" && "${remediation}" != "${rawValue}" ]]; then
        echo "${remediation}"
    elif [[ "${normalizedStatus}" == "healthy" ]]; then
        echo "$( getInspectPreferredResultTextByIndex "${index}" )"
    else
        echo "${organizationBoilerplateComplianceMessage}"
    fi

}

function getInspectComparisonActualTextByIndex() {

    local index="${1}"
    local normalizedStatus="${checkNormalizedStatusByIndex[${index}]}"
    local preferredValue="$( getInspectPreferredResultTextByIndex "${index}" )"

    if [[ "${normalizedStatus}" == "healthy" ]]; then
        echo "${preferredValue}"
    else
        echo "$( getDisplayStatusLabelFromNormalizedStatus "${normalizedStatus}" ): ${preferredValue}"
    fi

}

function getInspectStatusColor() {

    case "${1}" in
        "healthy" )
            echo "#65C466"
            ;;
        "warning" )
            echo "#F5BE0A"
            ;;
        "fail" | "error" )
            echo "#EB4C46"
            ;;
        * )
            echo "#8E8E93"
            ;;
    esac

}

function getInspectStatusIcon() {

    case "${1}" in
        "healthy" )
            echo "checkmark.circle.fill"
            ;;
        "warning" )
            echo "exclamationmark.triangle.fill"
            ;;
        "fail" )
            echo "xmark.circle.fill"
            ;;
        * )
            echo "exclamationmark.circle.fill"
            ;;
    esac

}

function getInspectFailureSymbolByIndex() {

    local index="${1}"
    local title="${checkTitleByIndex[${index}]:-}"

    case "${title:l}" in
        *gatekeeper*|*xprotect* )
            echo "lock.trianglebadge.exclamationmark"
            ;;
        *push*notification*hosts*|*network*quality* )
            echo "wifi.exclamationmark"
            ;;
        *device*management* )
            echo "desktopcomputer.trianglebadge.exclamationmark"
            ;;
        * )
            echo ""
            ;;
    esac

}

function getInspectCheckSymbolByIndex() {

    local index="${1}"
    local title="${checkTitleByIndex[${index}]:-}"
    local normalizedStatus="${checkNormalizedStatusByIndex[${index}]:-}"
    local failureSymbol=""

    if [[ "${normalizedStatus}" == "fail" ]] || [[ "${normalizedStatus}" == "error" ]]; then
        failureSymbol="$( getInspectFailureSymbolByIndex "${index}" )"
        if [[ -n "${failureSymbol}" ]]; then
            echo "${failureSymbol}"
        else
            echo "xmark.circle.fill"
        fi
        return
    fi

    case "${title:l}" in
        *macos*version* )
            echo "apple.logo"
            ;;
        *available*update* )
            echo "arrow.down.circle"
            ;;
        *system*integrity*protection* )
            echo "shield.lefthalf.filled"
            ;;
        *signed*system*volume* )
            echo "checkmark.seal"
            ;;
        *firewall* )
            echo "firewall"
            ;;
        *filevault* )
            echo "lock.shield"
            ;;
        *gatekeeper*|*xprotect* )
            echo "lock.circle"
            ;;
        *touch*id* )
            echo "touchid"
            ;;
        *vpn* )
            echo "lock.circle"
            ;;
        *reboot* )
            echo "power.circle"
            ;;
        *disk*space*|*storage* )
            echo "internaldrive"
            ;;
        *desktop* )
            echo "desktopcomputer"
            ;;
        *downloads* )
            echo "folder.fill.badge.plus"
            ;;
        *trash* )
            echo "trash"
            ;;
        *password*hint* )
            echo "key"
            ;;
        *airdrop* )
            echo "airdrop"
            ;;
        *airplay*receiver* )
            echo "airplayaudio"
            ;;
        *bluetooth*sharing* )
            echo "bluetooth"
            ;;
        *mdm*profile* )
            echo "checkmark.shield"
            ;;
        *certificate*expiration*|*certificate*validation* )
            echo "checkmark.seal"
            ;;
        *push*notification*service* )
            echo "bell.badge"
            ;;
        *check-in*|*inventory* )
            echo "arrow.triangle.2.circlepath"
            ;;
        *push*notification*hosts*|*network*quality* )
            echo "wifi"
            ;;
        *device*management* )
            echo "desktopcomputer.badge.shield.checkmark"
            ;;
        *software*and*carrier*updates* )
            echo "square.and.arrow.down"
            ;;
        *identity*and*content*services* )
            echo "person.text.rectangle"
            ;;
        *homebrew* )
            echo "shippingbox"
            ;;
        *electron* )
            echo "bolt.circle"
            ;;
        *teams* )
            echo "folder.fill.badge.plus"
            ;;
        * )
            echo "$( getInspectStatusIcon "${checkNormalizedStatusByIndex[${index}]}" )"
            ;;
    esac

}

function buildInspectComparisonTableJSONByIndex() {

    local index="${1}"
    local title="${checkTitleByIndex[${index}]}"
    local normalizedStatus="${checkNormalizedStatusByIndex[${index}]}"

    printf '%s' "{"
    printf '%s' "\"content\":$( jsonString "${title}" ),"
    printf '%s' "\"comparisonStyle\":\"columns\","
    printf '%s' "\"expectedLabel\":\"Expected\","
    printf '%s' "\"expected\":$( jsonString "$( getInspectExpectedComparisonTextByIndex "${index}" )" ),"
    printf '%s' "\"expectedColor\":\"#34C759\","
    printf '%s' "\"expectedIcon\":\"checkmark.circle.fill\","
    printf '%s' "\"actualLabel\":\"Actual\","
    printf '%s' "\"actual\":$( jsonString "$( getInspectComparisonActualTextByIndex "${index}" )" ),"
    printf '%s' "\"actualColor\":$( jsonString "$( getInspectStatusColor "${normalizedStatus}" )" ),"
    printf '%s' "\"actualIcon\":$( jsonString "$( getInspectCheckSymbolByIndex "${index}" )" ),"
    printf '%s' "\"type\":\"comparison-table\""
    printf '%s' "}"

}

function buildInspectComparisonEntriesJSONFromTitles() {

    local title=""
    local index=""
    local separator=""

    for title in "$@"; do
        index="${checkIndexByTitle[${title}]}"

        if [[ "${index}" == <-> ]]; then
            printf '%s' "${separator}$( buildInspectComparisonTableJSONByIndex "${index}" )"
            separator=","
        fi
    done

}

function buildInspectSummaryComparisonTableJSON() {

    local healthyCount="${#reportHealthyChecks[@]}"
    local unhealthyCount="$( getInspectUnhealthyCount )"

    printf '%s' "{"
    printf '%s' "\"content\":$( jsonString "$( getInspectResultsTimestampText )" ),"
    printf '%s' "\"comparisonStyle\":\"columns\","
    printf '%s' "\"expectedLabel\":\"Healthy\","
    printf '%s' "\"expected\":$( jsonString "${healthyCount} checks passed" ),"
    printf '%s' "\"expectedColor\":\"#34C759\","
    printf '%s' "\"expectedIcon\":\"checkmark.shield\","
    printf '%s' "\"actualLabel\":\"Unhealthy\","
    printf '%s' "\"actual\":$( jsonString "${unhealthyCount} checks need attention" ),"
    printf '%s' "\"actualColor\":$( jsonString "$( getInspectStatusColor "${reportOverallStatus}" )" ),"
    printf '%s' "\"actualIcon\":$( jsonString "$( getInspectStatusIcon "${reportOverallStatus}" )" ),"
    printf '%s' "\"type\":\"comparison-table\""
    printf '%s' "}"

}

function buildInspectOverviewGuidanceContentJSON() {

    printf '%s' "["
    printf '%s' "{\"content\":\"Mac Health Check Flow\",\"phases\":[\"Checks Complete\",\"Report Written\",\"Summary Available\",\"Cached Report Expires\"],\"currentPhase\":3,\"style\":\"stepper\",\"type\":\"phase-tracker\"},"
    printf '%s' "{\"content\":$( jsonString "$( getInspectIntroductionText )" ),\"type\":\"text\"},"
    printf '%s' "$( buildInspectSummaryComparisonTableJSON ),"
    printf '%s' "{\"content\":$( jsonString "$( getInspectReplayExpirationMessage )" ),\"type\":\"info\"}"
    printf '%s' "]"

}

function buildInspectSupportLineItemsJSON() {

    local inspectSupportItems=()
    local inspectButtonURL="$( getInspectSupportButtonURL )"
    local supportLabelVar=""
    local supportValueVar=""
    local supportLabel=""
    local supportValue=""

    for supportIndex in {1..6}; do
        supportLabelVar="supportLabel${supportIndex}"
        supportValueVar="supportValue${supportIndex}"
        supportLabel="${(P)supportLabelVar}"
        supportValue="${(P)supportValueVar}"

        if [[ -n "${supportLabel}" && -n "${supportValue}" ]]; then
            if [[ -n "${inspectButtonURL}" ]] && [[ "${supportValue}" == "${inspectButtonURL}" || "${supportValue}" == *"(${inspectButtonURL})"* ]]; then
                continue
            fi

            inspectSupportItems+=( "${supportLabel}: ${supportValue}" )
        fi
    done

    if (( ${#inspectSupportItems[@]} == 0 )); then
        [[ -n "${supportTeamPhone}" ]] && inspectSupportItems+=( "Telephone: ${supportTeamPhone}" )
        [[ -n "${supportTeamEmail}" ]] && inspectSupportItems+=( "Email: ${supportTeamEmail}" )
        if [[ -n "${supportTeamWebsite}" ]] && [[ "${supportTeamWebsite}" != "${inspectButtonURL}" ]]; then
            inspectSupportItems+=( "Website: ${supportTeamWebsite}" )
        fi
        [[ -n "${supportKBURL}" ]] && inspectSupportItems+=( "Knowledge Base Article: ${supportKBURL}" )
    fi

    buildJSONStringArray "${inspectSupportItems[@]}"

}

function buildInspectUserInformationItemsJSON() {

    local userInformationItems=(
        "**Full Name:** ${loggedInUserFullname}"
        "**User Name:** ${loggedInUser}"
        "**User ID:** ${loggedInUserID}"
        "**Volume Owners:** ${volumeOwnerList}"
        "**Secure Token:** ${secureToken}"
        "**Location Services:** ${locationServicesStatus}"
        "**Microsoft OneDrive Sync Date:** ${oneDriveSyncDate}"
        "**Platform SSOe:** ${platformSSOeResult}"
    )

    buildJSONStringArray "${userInformationItems[@]}"

}

function buildInspectComputerInformationItemsJSON() {

    local computerInformationItems=(
        "**macOS:** ${osVersion} (${osBuild})"
        "**Dialog:** $(dialog -v)"
        "**Script:** ${scriptVersion}"
        "**Computer Name:** ${computerName}"
        "**Serial Number:** ${serialNumber}"
        "**Wi-Fi:** ${ssid}"
        "${activeIPAddress}"
        "**VPN IP:** ${vpnStatus}"
    )

    buildJSONStringArray "${computerInformationItems[@]}"

}

function getInspectReplayExpirationMessage() {

    local replayMinutes=$(( inspectReplayMaximumAgeSeconds / 60 ))
    local expirationEpoch=$(( $( date +%s ) + inspectReplayMaximumAgeSeconds ))
    local expirationTimestamp=""

    expirationTimestamp="$( date -r "${expirationEpoch}" '+%A, %B %d at %I:%M %p %Z' 2>/dev/null )"

    if [[ -n "${expirationTimestamp}" ]]; then
        echo "These cached results may be reused for up to ${replayMinutes} minutes and will no longer be used after approximately ${expirationTimestamp}."
    else
        echo "These cached results may be reused for up to ${replayMinutes} minutes before they are refreshed."
    fi

}

function getInspectNextStepsText() {

    echo "Click **Finish** to close this report. $( getInspectReplayExpirationMessage )"

}

function buildInspectIntroductionGuidanceContentJSON() {

    buildInspectOverviewGuidanceContentJSON

}

function inspectSummaryIsEnabled() {

    [[ "${inspectSummaryPreset}" == "on" ]]

}

function inspectUnhealthyResultsExist() {

    (( ${#reportWarningChecks[@]} + ${#reportFailChecks[@]} + ${#reportErrorChecks[@]} > 0 ))

}

function inspectHealthyResultsExist() {

    (( ${#reportHealthyChecks[@]} > 0 ))

}

function buildInspectUnhealthyResultsGuidanceContentJSON() {

    local unhealthyResultTitles=()
    local comparisonEntriesJSON=""

    unhealthyResultTitles+=( "${reportErrorChecks[@]}" )
    unhealthyResultTitles+=( "${reportFailChecks[@]}" )
    unhealthyResultTitles+=( "${reportWarningChecks[@]}" )
    comparisonEntriesJSON="$( buildInspectComparisonEntriesJSONFromTitles "${unhealthyResultTitles[@]}" )"

    printf '%s' "["
    printf '%s' "{\"content\":$( jsonString "$( getInspectUnhealthyResultsSummaryText )" ),\"type\":\"warning\"}"
    if [[ -n "${comparisonEntriesJSON}" ]]; then
        printf '%s' ",${comparisonEntriesJSON}"
    fi
    printf '%s' "]"

}

function buildInspectHealthyResultsGuidanceContentJSON() {

    local comparisonEntriesJSON="$( buildInspectComparisonEntriesJSONFromTitles "${reportHealthyChecks[@]}" )"

    printf '%s' "["
    printf '%s' "{\"content\":$( jsonString "$( getInspectHealthyResultsSummaryText )" ),\"type\":\"success\"}"
    if [[ -n "${comparisonEntriesJSON}" ]]; then
        printf '%s' ",${comparisonEntriesJSON}"
    fi
    printf '%s' "]"

}

function buildInspectFallbackResultsGuidanceContentJSON() {

    printf '%s' "["
    printf '%s' "{\"content\":$( jsonString "$( getInspectResultsSummaryText )" ),\"type\":\"text\"},"
    printf '%s' "{\"content\":\"No executed checks were recorded for this run.\",\"type\":\"info\"}"
    printf '%s' "]"

}

function buildInspectSupportText() {

    local supportText="For assistance, please contact ${supportTeamName}."
    local supportFieldsFound="false"
    local supportLabelVar=""
    local supportValueVar=""
    local supportLabel=""
    local supportValue=""

    for supportIndex in {1..6}; do
        supportLabelVar="supportLabel${supportIndex}"
        supportValueVar="supportValue${supportIndex}"
        supportLabel="${(P)supportLabelVar}"
        supportValue="${(P)supportValueVar}"

        if [[ -n "${supportLabel}" && -n "${supportValue}" ]]; then
            supportFieldsFound="true"
            supportText+=$'\n'
            supportText+="${supportLabel}: $( normalizeInspectSupportValue "${supportValue}" )"
        fi
    done

    if [[ "${supportFieldsFound}" == "false" ]]; then
        [[ -n "${supportTeamPhone}" ]] && supportText+=$'\n'"Telephone: ${supportTeamPhone}"
        [[ -n "${supportTeamEmail}" ]] && supportText+=$'\n'"Email: ${supportTeamEmail}"
        [[ -n "${supportTeamWebsite}" ]] && supportText+=$'\n'"Website: ${supportTeamWebsite}"
        [[ -n "${supportKB}" && -n "${infobuttonaction}" ]] && supportText+=$'\n'"Knowledge Base Article: ${supportKB} (${infobuttonaction})"
    fi

    printf '%s' "${supportText}"

}

function buildInspectHelpGuidanceContentJSON() {

    local helpText="For assistance, please contact: **${supportTeamName}**"
    local buttonURL="$( getInspectSupportButtonURL )"
    local buttonText="$( getInspectSupportButtonText "${buttonURL}" )"
    local supportItemsJSON="$( buildInspectSupportLineItemsJSON )"
    local userInformationItemsJSON="$( buildInspectUserInformationItemsJSON )"
    local computerInformationItemsJSON="$( buildInspectComputerInformationItemsJSON )"

    printf '%s' "["
    printf '%s' "{\"content\":$( jsonString "${helpText}" ),\"type\":\"info\"}"

    if [[ "${supportItemsJSON}" != "[]" ]]; then
        printf '%s' ","
        printf '%s' "{\"items\":${supportItemsJSON},\"type\":\"bullets\"}"
    fi

    if [[ -n "${buttonURL}" ]]; then
        printf '%s' ","
        printf '%s' "{\"action\":\"url\",\"content\":$( jsonString "${buttonText}" ),\"icon\":$( jsonString "$( getInspectSupportButtonIcon "${buttonURL}" )" ),\"type\":\"button\",\"url\":$( jsonString "${buttonURL}" )}"
    fi

    printf '%s' ","
    printf '%s' "{\"content\":\"User Information:\",\"type\":\"info\"}"
    printf '%s' ","
    printf '%s' "{\"items\":${userInformationItemsJSON},\"type\":\"bullets\"}"
    printf '%s' ","
    printf '%s' "{\"content\":\"Computer Information:\",\"type\":\"info\"}"
    printf '%s' ","
    printf '%s' "{\"items\":${computerInformationItemsJSON},\"type\":\"bullets\"}"

    printf '%s' "]"

}

function buildInspectNextStepsGuidanceContentJSON() {

    printf '%s' "["
    printf '%s' "{\"content\":\"Mac Health Check Flow\",\"phases\":[\"Checks Complete\",\"Report Written\",\"Summary Available\",\"Cached Report Expires\"],\"currentPhase\":4,\"style\":\"stepper\",\"type\":\"phase-tracker\"},"
    printf '%s' "{\"content\":$( jsonString "$( getInspectNextStepsText )" ),\"type\":\"info\"},"
    printf '%s' "$( buildInspectSummaryComparisonTableJSON )"
    printf '%s' "]"

}

function buildInspectItemsJSONArray() {

    local sectionIcon="$( getInspectSectionIcon )"
    local separator=""

    printf '%s' "["
    printf '%s' "{\"displayName\":\"Overview\",\"guidanceContent\":$( buildInspectIntroductionGuidanceContentJSON ),\"guidanceTitle\":\"Results Overview\",\"icon\":$( jsonString "${sectionIcon}" ),\"id\":\"overview\"}"
    separator=","

    if inspectUnhealthyResultsExist; then
        printf '%s' "${separator}{\"displayName\":\"Unhealthy\",\"guidanceContent\":$( buildInspectUnhealthyResultsGuidanceContentJSON ),\"guidanceTitle\":\"Unhealthy Results\",\"icon\":$( jsonString "${sectionIcon}" ),\"id\":\"unhealthy\"}"
    fi

    if inspectHealthyResultsExist; then
        printf '%s' "${separator}{\"displayName\":\"Healthy\",\"guidanceContent\":$( buildInspectHealthyResultsGuidanceContentJSON ),\"guidanceTitle\":\"Healthy Results\",\"icon\":$( jsonString "${sectionIcon}" ),\"id\":\"healthy\"}"
    fi

    if ! inspectUnhealthyResultsExist && ! inspectHealthyResultsExist; then
        printf '%s' "${separator}{\"displayName\":\"Results\",\"guidanceContent\":$( buildInspectFallbackResultsGuidanceContentJSON ),\"guidanceTitle\":\"Results\",\"icon\":$( jsonString "${sectionIcon}" ),\"id\":\"results\"}"
    fi

    printf '%s' "${separator}{\"displayName\":\"Help & Support\",\"guidanceContent\":$( buildInspectHelpGuidanceContentJSON ),\"guidanceTitle\":\"Help & Support\",\"icon\":$( jsonString "${sectionIcon}" ),\"id\":\"help\"}"
    printf '%s' "${separator}{\"displayName\":\"Next Steps\",\"guidanceContent\":$( buildInspectNextStepsGuidanceContentJSON ),\"guidanceTitle\":\"Next Steps\",\"icon\":$( jsonString "${sectionIcon}" ),\"id\":\"nextSteps\"}"
    printf '%s' "]"

}

function buildInspectConfigJSON() {

    local inspectHighlightColor="#F69325"
    local inspectWindowHeight="750"
    local inspectWindowWidth="975"

    printf '%s' "{"
    printf '%s' "\"preset\":\"6\","
    printf '%s' "\"title\":$( jsonString "$( getInspectWindowTitle )" ),"
    printf '%s' "\"highlightColor\":$( jsonString "${inspectHighlightColor}" ),"
    printf '%s' "\"moveable\":true,"
    printf '%s' "\"items\":$( buildInspectItemsJSONArray ),"
    printf '%s' "\"height\":${inspectWindowHeight},"
    printf '%s' "\"width\":${inspectWindowWidth}"
    printf '%s' "}"

}

function validateInspectConfigFile() {

    local inspectConfigToValidate="${1:-${inspectConfigPath}}"

    jq -e \
        '.preset == "6"
        and (.title | type == "string")
        and (.title | length > 0)
        and (.highlightColor | type == "string")
        and (.highlightColor | length > 0)
        and (.height == 750)
        and (.width == 975)
        and (.items | type == "array")
        and (.items | length >= 3)
        and all(.items[];
            (.displayName | type == "string")
            and (.displayName | length > 0)
            and (.guidanceTitle | type == "string")
            and (.guidanceTitle | length > 0)
            and (.icon | type == "string")
            and (.icon | length > 0)
            and (.id | type == "string")
            and (.id | length > 0)
            and (.guidanceContent | type == "array")
            and (.guidanceContent | length > 0)
            and all(.guidanceContent[];
                (.type | type == "string")
                and (.type | length > 0)
                and (if .type == "bullets" then
                        (.items | type == "array") and (.items | length > 0)
                    elif .type == "button" then
                        (.action == "url")
                        and (.content | type == "string") and (.content | length > 0)
                        and (.url | type == "string") and (.url | length > 0)
                    elif .type == "comparison-table" then
                        (.content | type == "string") and (.content | length > 0)
                        and (.expectedLabel | type == "string") and (.expectedLabel | length > 0)
                        and (.expected | type == "string") and (.expected | length > 0)
                        and (.actualLabel | type == "string") and (.actualLabel | length > 0)
                        and (.actual | type == "string") and (.actual | length > 0)
                    elif .type == "phase-tracker" then
                        (.content | type == "string") and (.content | length > 0)
                        and (.phases | type == "array") and (.phases | length > 0)
                        and all(.phases[]; (type == "string") and (length > 0))
                        and (.currentPhase | type == "number")
                    else
                        (.content | type == "string") and (.content | length > 0)
                    end)
            )
        )' \
        "${inspectConfigToValidate}" >/dev/null 2>&1

}

function prepareInspectConfigForUser() {

    local inspectConfigToPrepare="${1:-${inspectConfigPath}}"

    if [[ ! -e "${inspectConfigToPrepare}" ]]; then
        warning "Inspect Summary: config file is unavailable at ${inspectConfigToPrepare}."
        return 1
    fi

    if ! chown "${loggedInUser}" "${inspectConfigToPrepare}" 2>/dev/null; then
        warning "Inspect Summary: failed to set ownership on ${inspectConfigToPrepare} for ${loggedInUser}."
        return 1
    fi

    if ! chmod 600 "${inspectConfigToPrepare}" 2>/dev/null; then
        warning "Inspect Summary: failed to set permissions on ${inspectConfigToPrepare} for ${loggedInUser}."
        return 1
    fi

    return 0

}

function prepareInspectLaunchLogForUser() {

    if ! : > "${inspectLaunchLogPath}" 2>/dev/null; then
        warning "Inspect Summary: failed to create ${inspectLaunchLogPath}."
        return 1
    fi

    if ! chown "${loggedInUser}" "${inspectLaunchLogPath}" 2>/dev/null; then
        warning "Inspect Summary: failed to set ownership on ${inspectLaunchLogPath} for ${loggedInUser}."
        return 1
    fi

    if ! chmod 600 "${inspectLaunchLogPath}" 2>/dev/null; then
        warning "Inspect Summary: failed to set permissions on ${inspectLaunchLogPath} for ${loggedInUser}."
        return 1
    fi

    return 0

}

function generateInspectSummaryAssets() {

    local inspectConfigJSON=""

    if ! inspectSummaryIsEnabled; then
        return 1
    fi

    inspectConfigJSON="$( buildInspectConfigJSON )"

    if ! validateJson "${inspectConfigJSON}"; then
        warning "Inspect Summary: generated inspect config JSON failed validation."
        return 1
    fi

    writeReadableTextFile "${inspectConfigPath}" "${inspectConfigJSON}"
    if ! validateInspectConfigFile "${inspectConfigPath}"; then
        warning "Inspect Summary: failed to validate ${inspectConfigPath}."
        return 1
    fi

    if ! prepareInspectConfigForUser "${inspectConfigPath}"; then
        return 1
    fi

    notice "Inspect Summary: wrote ${inspectConfigPath}."
    return 0

}

function launchInspectSummary() {

    local inspectConfigToLaunch="${1:-${inspectConfigPath}}"
    local inspectPID=""
    local launchCommand=""

    if ! inspectSummaryIsEnabled; then
        return 1
    fi

    if [[ ! -r "${inspectConfigToLaunch}" ]]; then
        warning "Inspect Summary: config file is not readable at ${inspectConfigToLaunch}."
        return 1
    fi

    if ! prepareInspectConfigForUser "${inspectConfigToLaunch}"; then
        return 1
    fi

    if ! prepareInspectLaunchLogForUser; then
        return 1
    fi

    launchCommand="/usr/bin/nohup /usr/bin/env DIALOG_INSPECT_CONFIG=${(q)inspectConfigToLaunch} DIALOG_DEBUG=1 ${(q)dialogBinary} --inspect-mode --inspect-config ${(q)inspectConfigToLaunch} >${(q)inspectLaunchLogPath} 2>&1 </dev/null & print -r -- \$!"
    inspectPID="$( runAsUser /bin/zsh -lc "${launchCommand}" 2>/dev/null | tr -d '[:space:]' )"

    if [[ ! "${inspectPID}" == <-> ]]; then
        warning "Inspect Summary: detached launch did not return a valid PID. Review ${inspectLaunchLogPath}."
        return 1
    fi

    notice "Inspect Summary: launched detached Preset 6 summary (PID ${inspectPID}; log ${inspectLaunchLogPath})."
    return 0

}

function replayCachedInspectSummaryIfEligible() {

    local configJSON=""
    local configFileEpoch=""
    local configFileAgeSeconds="0"

    if ! inspectSummaryIsEnabled; then
        return 1
    fi

    if [[ "${operationMode}" != "Self Service" ]]; then
        return 1
    fi

    if [[ ! -r "${inspectConfigPath}" ]]; then
        return 1
    fi

    configFileEpoch="$( stat -f "%m" "${inspectConfigPath}" 2>/dev/null )"
    if [[ ! "${configFileEpoch}" == <-> ]]; then
        warning "Inspect Summary Replay: unable to determine config age; running full health check."
        return 1
    fi

    configFileAgeSeconds=$(( $( date +%s ) - configFileEpoch ))
    if (( configFileAgeSeconds < 0 || configFileAgeSeconds >= inspectReplayMaximumAgeSeconds )); then
        info "Inspect Summary Replay: cached config is older than ${inspectReplayMaximumAgeSeconds} seconds; running full health check."
        return 1
    fi

    configJSON="$(<"${inspectConfigPath}")"
    if ! validateJson "${configJSON}"; then
        warning "Inspect Summary Replay: cached config JSON is invalid for Preset 6; running full health check."
        return 1
    fi

    if ! validateInspectConfigFile "${inspectConfigPath}"; then
        warning "Inspect Summary Replay: cached config structure is invalid for Preset 6; running full health check."
        return 1
    fi

    notice "Inspect Summary Replay: launching cached Preset 6 summary from the last ${inspectReplayMaximumAgeSeconds} seconds."
    if launchInspectSummary "${inspectConfigPath}"; then
        return 0
    fi

    warning "Inspect Summary Replay: detached launch failed for Preset 6; running full health check."
    return 1

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
                        { "type": "mrkdwn", "text": "*Health Issues:*\n${overallHealth%%; }" }
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
                                    { "title": "Health Issues", "value": "${overallHealth%%; }" }
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

    local problemCheckCount=0
    local warningCheckCount=0
    local failureCheckCount=0
    local inspectSummaryLaunched="false"

    rebuildOverallHealthFromRecordedResults
    calculateOverallReportStatus
    warningCheckCount="${#reportWarningChecks[@]}"
    failureCheckCount=$(( ${#reportFailChecks[@]} + ${#reportErrorChecks[@]} ))
    problemCheckCount=$(( warningCheckCount + failureCheckCount ))

    quitOut "Exiting …"

    notice "${localAdminWarning}User: ${loggedInUserFullname} (${loggedInUser}) [${loggedInUserID}] ${loggedInUserGroupMembership}; Security Mode: ${bootPoliciesSecurityMode}; DEP-allowed MDM Control: ${bootPoliciesDepAllowedMdmControl}; Activation Lock: ${activationLockStatus}; ${bootstrapTokenStatus}; sudo Check: ${sudoStatus}; sudoers: ${sudoAllLines}; Kerberos SSOe: ${kerberosSSOeResult}; Platform SSOe: ${platformSSOeResult}; Location Services: ${locationServicesStatus}; SSH: ${sshStatus}; Microsoft OneDrive Sync Date: ${oneDriveSyncDate}; Time Machine Backup Date: ${tmStatus} ${tmLastBackup}; Battery Cycle Count: ${batteryCycleCount}; Rosetta-required apps: ${rosettaRequiredApps}; Wi-Fi: ${ssid}; ${activeIPAddress//\*\*/}; VPN IP: ${vpnStatus} ${vpnExtendedStatus}; ${networkTimeServer}"

    case ${mdmVendor} in

        "Jamf Pro" )
            notice "Jamf Pro Computer ID: ${jamfProID}; Site: ${jamfProSiteName}"
            ;;

    esac

    case "${reportOverallStatus}" in

        "warning" )
            if [[ "${operationMode}" != "Silent" ]]; then
                dialogUpdate "icon: SF=exclamationmark.triangle.fill, weight=bold, colour1=${statusColorError}, colour2=${statusColorError}"
                dialogUpdate "title: Computer Needs Attention <br>as of $( date '+%A, %B %d at %I:%M %p %Z' )"
            fi
            if [[ -n "${webhookURL}" ]]; then
                info "Sending webhook message"
                webhookStatus="Warnings Detected (${problemCheckCount} issues)"
                webHookMessage
            fi
            warning "${overallHealth%%; }"
            exitCode="0"
            ;;

        "fail" | "error" )
            if [[ "${operationMode}" != "Silent" ]]; then
                dialogUpdate "icon: SF=xmark.circle, weight=bold, colour1=#BB1717, colour2=#F31F1F"
                dialogUpdate "title: Computer Unhealthy <br>as of $( date '+%A, %B %d at %I:%M %p %Z' )"
            fi
            if [[ -n "${webhookURL}" ]]; then
                info "Sending webhook message"
                webhookStatus="Failures Detected (${problemCheckCount} issues)"
                webHookMessage
            fi
            errorOut "${overallHealth%%; }"
            exitCode="1"
            ;;

        * )
            if [[ "${operationMode}" != "Silent" ]]; then
                dialogUpdate "icon: SF=checkmark.circle, weight=bold, colour1=#00ff44, colour2=#075c1e"
                dialogUpdate "title: Computer Healthy <br>as of $( date '+%A, %B %d at %I:%M %p %Z' )"
            fi
            exitCode="0"
            ;;

    esac

    generateAndSendSplunkReport

    if [[ "${suppressNonSplunkConsoleLogging}" == "true" ]]; then
        if (( reportingErrorCount > 0 )); then
            exitCode="1"
        elif [[ "${reportGenerated}" == "true" ]] && [[ "${reportTransmissionStatus}" == "success" ]]; then
            exitCode="0"
        else
            exitCode="1"
        fi
    fi

    if [[ "${operationMode}" == "Self Service" ]] && inspectSummaryIsEnabled; then
        if generateInspectSummaryAssets && launchInspectSummary; then
            inspectSummaryLaunched="true"
        else
            info "Inspect Summary: continuing with the standard completion countdown."
        fi
    fi

    if [[ "${operationMode}" != "Silent" ]]; then
        dialogUpdate "progress: 100"
        dialogUpdate "progresstext: Elapsed Time: $(printf '%dh:%dm:%ds\n' $((SECONDS/3600)) $((SECONDS%3600/60)) $((SECONDS%60)))"
        dialogUpdate "button1text: Close"
        dialogUpdate "button1: enable"

        if [[ "${inspectSummaryLaunched}" == "true" ]]; then
            notice "Inspect Summary: detached Preset 6 summary launched; retaining the existing completion countdown on the main dialog."
        fi
        
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
        writeDockBadge "remove"
        dialogUpdate "quit:"
    fi

    # Remove runtime artifacts created by this script.
    rm -f "${dialogCommandFile}"
    rm -f -- /var/tmp/dialogCommandFile_${organizationScriptName}.*(N)

    rm -f "${dialogJSONFile}"
    rm -f -- /var/tmp/dialogJSONFile_${organizationScriptName}.*(N)

    rm -f "${dialogOverlayIconFile}"
    rm -f "${dialogDockIconFile}"

    # Remove copied Dock-named swiftDialog app bundle (never remove source Dialog.app).
    if [[ -n "${dialogDockNamedApp}" ]] && [[ "${dialogDockNamedApp}" != "${dialogAppBundle}" ]] && [[ -d "${dialogDockNamedApp}" ]]; then
        rm -Rf "${dialogDockNamedApp}"
    fi

    rm -f "/var/tmp/app-sso.plist"
    rm -f /var/tmp/dialog.log

    notice "Total Elapsed Time: $(printf '%dh:%dm:%ds\n' $((SECONDS/3600)) $((SECONDS%3600/60)) $((SECONDS%60)))"

    quitOut "Good manners don’t cost nothing, do they, eh?"

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
# Pre-flight Check: Confirm JSON tooling availability
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if command -v jq &> /dev/null; then
    preFlight "jq found; using jq for JSON validation and formatting."
    reportJSONTool="jq"
else
    fatal "jq is required for JSON validation and formatting; install jq before running Mac Health Check on Macs that do not bundle it by default."
fi

if [[ "${clientSideSkipChecks}" == "true" ]]; then

    notice "Client-Side Cache: cache is current; skipping health checks and uploading cached report only."
    if sendCachedSplunkReport; then
        quitOut "Client-Side Cache: cached Splunk report upload complete."
        exit 0
    else
        errorOut "Client-Side Cache: cached Splunk report upload failed."
        exit 1
    fi

fi

if [[ "${operationMode}" != "Silent" ]] || [[ "${splunkOperationMode}" == "production" ]]; then
    if ! installClientSideScript; then
        warning "Client-Side Cache: client-side script installation did not complete; continuing with current run."
    fi
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
    if [[ ! -d "${dialogAppBundle}" ]]; then

        preFlight "swiftDialog not found; installing …"
        dialogInstall
        if [[ ! -x "${dialogBinary}" ]]; then
            fatal "swiftDialog still not found; are downloads from GitHub blocked on this Mac?"
        fi

    else

        dialogVersion=$("${dialogBinary}" --version)
        if ! is-at-least "${swiftDialogMinimumRequiredVersion}" "${dialogVersion}"; then
            
            preFlight "swiftDialog version ${dialogVersion} found but swiftDialog ${swiftDialogMinimumRequiredVersion} or newer is required; updating …"
            dialogInstall
            if [[ ! -x "${dialogBinary}" ]]; then
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

if replayCachedInspectSummaryIfEligible; then
    quitOut "Replayed cached inspect summary."
    exit 0
fi



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
    local footerStatusColor="${statusColorSuccess}"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=desktopcomputer.and.macbook,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Comparing installed OS version with compliant version …"

    sleep "${anticipationDuration}"

    # Check if this is a beta build vs. a Background Security Improvement (BSI) release
    # Beta builds: osVersionExtra is empty AND osBuild ends with a letter (e.g., "25D771280a" with no ProductVersionExtra)
    # BSI releases: osVersionExtra is populated (e.g., "(a)") AND osBuild ends with a letter (e.g., "25D771280a")
    # BSI releases are production versions and should proceed through normal SOFA compliance checking

    if [[ -z "${osVersionExtra}" ]] && [[ "${osBuild}" =~ [a-zA-Z]$ ]]; then

        logComment "OS Build, ${osBuild}, ends with a letter and ProductVersionExtra is empty; treating as beta"
        osResult="Beta macOS ${osVersion} (${osBuild})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: Beta builds of macOS are purposely marked as unsupported, status: error, statustext: ${osResult}"
        footerStatusColor="${statusColorError}"
        warning "${osResult}"
    
    else

        if [[ -n "${osVersionExtra}" ]]; then
            logComment "OS Build, ${osBuild}, is a Background Security Improvement release (ProductVersionExtra: ${osVersionExtra}); proceeding with SOFA compliance check …"
        else
            logComment "OS Build, ${osBuild}, ends with a number; proceeding with SOFA compliance check …"
        fi

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

        # use cached SOFA data if still fresh; otherwise fall through to ETag check or download
        sofaDataCached="false"
        if [[ -f "$json_cache" ]]; then
            sofaCacheFileEpoch=$( stat -f "%m" "$json_cache" )
            sofaCacheMaximumEpoch=$( date -v-"${sofaCacheMaximumAge}" +%s )
            if [[ "${sofaCacheFileEpoch}" -gt "${sofaCacheMaximumEpoch}" ]]; then
                logComment "Using cached SOFA data (age within ${sofaCacheMaximumAge})"
                sofaDataCached="true"
            else
                logComment "Cached SOFA data is stale; removing …"
                rm -Rf "$json_cache_dir"
                mkdir -p "$json_cache_dir"
            fi
        fi

        # check local vs online using etag (skipped if using fresh cache)
        if [[ "${sofaDataCached}" != "true" ]]; then
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
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: ${osResult}"
            footerStatusColor="${statusColorError}"
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
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${osResult}"
            footerStatusColor="${statusColorSuccess}"
            info "${osResult}"
        else
            osResult="macOS ${osVersion} (${osBuild})"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please update to a supported macOS version via System Settings > General > Software Update, status: fail, statustext: ${osResult}"
            footerStatusColor="${statusColorFail}"
            errorOut "${osResult}"
            overallHealth+="${humanReadableCheckName}; "
        fi

    fi

    dialogUpdate "icon: SF=desktopcomputer.and.macbook,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

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
# Resolve DDM Enforcement from install.log
# Adapted from DDM OS Reminder 3.1.0b3
# Returns tab-separated: sourceType, logTimestamp, enforcedInstallDate, versionString, buildVersionString
# Fails closed (non-zero) when no trustworthy DDM enforcement state can be resolved
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function resolveDDMEnforcementFromInstallLog() {

    local installLogPath="/var/log/install.log"
    local ddmResolverLookbackLines="4000"

    if [[ ! -r "${installLogPath}" ]]; then
        return 1
    fi

    /usr/bin/tail -n "${ddmResolverLookbackLines}" "${installLogPath}" 2>/dev/null | /usr/bin/awk '
        function extractField(line, field,    needle, rest, pos) {
            needle = "|" field ":"
            pos = index(line, needle)
            if (!pos) {
                return ""
            }

            rest = substr(line, pos + length(needle))
            pos = index(rest, "|")
            if (pos) {
                return substr(rest, 1, pos - 1)
            }

            return rest
        }

        function extractRequestedVersion(line,    pos, rest) {
            pos = index(line, "requestedPMV=")
            if (!pos) {
                return ""
            }

            rest = substr(line, pos + 13)
            if (match(rest, /^[0-9]+\.[0-9]+(\.[0-9]+)?/)) {
                return substr(rest, RSTART, RLENGTH)
            }

            return ""
        }

        {
            if (index($0, "requestedPMV=")) {
                activeRequestedVersion = extractRequestedVersion($0)
                next
            }

            if (activeRequestedVersion != "" && (index($0, "MADownloadNoMatchFound") || index($0, "pallasNoPMVMatchFound=true") || index($0, "No available updates found. Please try again later."))) {
                noMatchVersion[activeRequestedVersion] = 1
            }

            sourceType = ""
            sourcePriority = 0

            if (index($0, "declarationFromKeys]: Found currently applicable declaration")) {
                sourceType = "currentApplicableDeclaration"
                sourcePriority = 4
            } else if (index($0, "declarationFromKeys]: Falling back to default applicable declaration")) {
                sourceType = "defaultApplicableDeclaration"
                sourcePriority = 3
            } else if (index($0, "Found DDM enforced install (")) {
                sourceType = "foundDdmEnforcedInstall"
                sourcePriority = 2
            } else if (index($0, "EnforcedInstallDate:")) {
                sourceType = "genericEnforcedInstallDate"
                sourcePriority = 1
            } else {
                next
            }

            logTimestamp = substr($0, 1, 22)
            if (logTimestamp !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}$/) {
                next
            }

            enforcedInstallDate = extractField($0, "EnforcedInstallDate")
            versionString = extractField($0, "VersionString")
            buildVersionString = extractField($0, "BuildVersionString")

            if (enforcedInstallDate == "" || versionString == "" || buildVersionString == "") {
                next
            }

            candidateKey = sourceType SUBSEP enforcedInstallDate SUBSEP versionString SUBSEP buildVersionString
            if (!(candidateKey in candidateTimestamp) || logTimestamp > candidateTimestamp[candidateKey]) {
                candidateTimestamp[candidateKey] = logTimestamp
                candidateSourceType[candidateKey] = sourceType
                candidateEnforcedInstallDate[candidateKey] = enforcedInstallDate
                candidateVersionString[candidateKey] = versionString
                candidateBuildVersionString[candidateKey] = buildVersionString
                candidatePriority[candidateKey] = sourcePriority
            }
        }

        END {
            latestTimestamp = ""
            for (candidateKey in candidateTimestamp) {
                if (latestTimestamp == "" || candidateTimestamp[candidateKey] > latestTimestamp) {
                    latestTimestamp = candidateTimestamp[candidateKey]
                }
            }

            if (latestTimestamp == "") {
                exit 20
            }

            highestPriority = 0
            filteredCount = 0
            for (candidateKey in candidateTimestamp) {
                if (candidateTimestamp[candidateKey] == latestTimestamp && candidatePriority[candidateKey] > highestPriority) {
                    highestPriority = candidatePriority[candidateKey]
                }
            }

            for (candidateKey in candidateTimestamp) {
                if (candidateTimestamp[candidateKey] == latestTimestamp && candidatePriority[candidateKey] == highestPriority) {
                    filteredCount++
                    filteredCandidate[filteredCount] = candidateKey
                }
            }

            if (filteredCount != 1) {
                exit 21
            }

            candidateKey = filteredCandidate[1]
            versionString = candidateVersionString[candidateKey]

            if (versionString !~ /^[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3})?$/) {
                exit 22
            }

            if (versionString in noMatchVersion) {
                exit 23
            }

            printf "%s\t%s\t%s\t%s\t%s\n", \
                candidateSourceType[candidateKey], \
                candidateTimestamp[candidateKey], \
                candidateEnforcedInstallDate[candidateKey], \
                candidateVersionString[candidateKey], \
                candidateBuildVersionString[candidateKey]
        }
    '

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Resolve Padded DDM Enforcement Date from install.log
# Returns a raw padded enforcement date only when it matches the selected declaration and is still future-valid
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function resolvePaddedEnforcementDateForCandidate() {

    local declarationTimestamp="${1}"
    local declarationSignature="${2}"
    local installLogPath="/var/log/install.log"
    local ddmResolverLookbackLines="4000"
    local paddedDateRaw=""
    local paddedEpoch=""
    local nowEpoch=""

    paddedDateRaw="$(
        /usr/bin/tail -n "${ddmResolverLookbackLines}" "${installLogPath}" 2>/dev/null | /usr/bin/awk -v chosenTimestamp="${declarationTimestamp}" -v chosenSignature="${declarationSignature}" '
            function extractField(line, field,    needle, rest, pos) {
                needle = "|" field ":"
                pos = index(line, needle)
                if (!pos) {
                    return ""
                }

                rest = substr(line, pos + length(needle))
                pos = index(rest, "|")
                if (pos) {
                    return substr(rest, 1, pos - 1)
                }

                return rest
            }

            {
                logTimestamp = substr($0, 1, 22)
                if (logTimestamp !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}$/) {
                    next
                }

                if (logTimestamp < chosenTimestamp) {
                    next
                }

                if (index($0, "EnforcedInstallDate:")) {
                    enforcedInstallDate = extractField($0, "EnforcedInstallDate")
                    versionString = extractField($0, "VersionString")
                    buildVersionString = extractField($0, "BuildVersionString")

                    if (enforcedInstallDate != "" && versionString != "" && buildVersionString != "") {
                        if (enforcedInstallDate "|" versionString "|" buildVersionString != chosenSignature) {
                            conflictDetected = 1
                        }
                    }
                }

                if (index($0, "setPastDuePaddedEnforcementDate is set: ")) {
                    paddedDateRaw = substr($0, index($0, "setPastDuePaddedEnforcementDate is set: ") + 39)
                    sub(/^[[:space:]]+/, "", paddedDateRaw)
                    sub(/[[:space:]]+$/, "", paddedDateRaw)
                }
            }

            END {
                if (!conflictDetected && paddedDateRaw != "") {
                    print paddedDateRaw
                }
            }
        '
    )"

    if [[ -z "${paddedDateRaw}" ]]; then
        return 1
    fi

    paddedEpoch="$(
        /bin/date -jf "%a %b %d %H:%M:%S %Y" "${paddedDateRaw}" "+%s" 2>/dev/null \
        || echo ""
    )"
    nowEpoch="$(/bin/date +%s)"

    if [[ -z "${paddedEpoch}" || ! "${paddedEpoch}" =~ ^[0-9]+$ ]] || (( paddedEpoch <= nowEpoch )); then
        return 1
    fi

    printf '%s\n' "${paddedDateRaw}"
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Available Software Updates
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkAvailableSoftwareUpdates() {

    local humanReadableCheckName="Available Software Updates"
    local footerStatusColor="${statusColorSuccess}"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=arrow.down.circle.dotted,${organizationColorScheme}"
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

    # DDM-enforced OS Version (priority-ranked resolver; fails closed on ambiguous or conflicting state)
    local ddmResolvedCandidate=""
    local ddmResolverExitCode=0
    ddmResolvedCandidate="$( resolveDDMEnforcementFromInstallLog )"
    ddmResolverExitCode=$?

    local ddmResolverSource="" ddmDeclarationLogTimestamp="" ddmEnforcedInstallDate="" ddmVersionString="" ddmBuildVersionString=""
    local ddmPaddedEnforcementDateRaw="" ddmEnforcedInstallDateDisplay="" ddmEnforcedInstallDateHumanReadable="" ddmDateSource="raw"
    if (( ddmResolverExitCode == 0 )) && [[ -n "${ddmResolvedCandidate}" ]]; then
        IFS=$'\t' read -r ddmResolverSource ddmDeclarationLogTimestamp ddmEnforcedInstallDate ddmVersionString ddmBuildVersionString <<< "${ddmResolvedCandidate}"
        ddmEnforcedInstallDateDisplay="${ddmEnforcedInstallDate}"
        ddmPaddedEnforcementDateRaw="$( resolvePaddedEnforcementDateForCandidate "${ddmDeclarationLogTimestamp}" "${ddmEnforcedInstallDate}|${ddmVersionString}|${ddmBuildVersionString}" )"
        if [[ -n "${ddmPaddedEnforcementDateRaw}" ]]; then
            ddmEnforcedInstallDateDisplay="${ddmPaddedEnforcementDateRaw}"
            ddmDateSource="padded"
            ddmEnforcedInstallDateHumanReadable="$(date -jf "%a %b %d %H:%M:%S %Y" "${ddmPaddedEnforcementDateRaw}" "+%d-%b-%Y" 2>/dev/null)"
        else
            ddmEnforcedInstallDateHumanReadable="$(date -jf "%Y-%m-%dT%H:%M:%S" "${ddmEnforcedInstallDate%Z}" "+%d-%b-%Y" 2>/dev/null)"
        fi

        [[ -z "${ddmEnforcedInstallDateHumanReadable}" ]] && ddmEnforcedInstallDateHumanReadable="${ddmEnforcedInstallDateDisplay}"
        info "DDM Resolver: source=${ddmResolverSource} | date=${ddmEnforcedInstallDateDisplay} | dateSource=${ddmDateSource} | version=${ddmVersionString} | build=${ddmBuildVersionString}"
    else
        info "DDM Resolver: no trustworthy DDM enforcement state resolved (exit ${ddmResolverExitCode})"
    fi

    # Software Update Recommended Updates
    recommendedUpdates=$( /usr/libexec/PlistBuddy -c "Print :RecommendedUpdates:0" /Library/Preferences/com.apple.SoftwareUpdate.plist 2>/dev/null )
    if [[ -n "${recommendedUpdates}" ]]; then
        SUListRaw=$( softwareupdate --list 2>&1 )
        case "${SUListRaw}" in
            *"Can’t connect"* )
                availableSoftwareUpdates="Can’t connect to the Software Update server"
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: System Settings > General > Software Update, status: fail, statustext: ${availableSoftwareUpdates}"
                errorOut "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                overallHealth+="${humanReadableCheckName}; "
                footerStatusColor="${statusColorFail}"
                ;;
            *"The operation couldn’t be completed."* )
                availableSoftwareUpdates="The operation couldn’t be completed."
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: System Settings > General > Software Update, status: fail, statustext: ${availableSoftwareUpdates}"
                errorOut "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                overallHealth+="${humanReadableCheckName}; "
                footerStatusColor="${statusColorFail}"
                ;;
            *"Deferred: YES"* )
                availableSoftwareUpdates="Deferred software available."
                checkStagedUpdate
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: System Settings > General > Software Update; ${stagingMessage}, status: error, statustext: ${availableSoftwareUpdates}"
                warning "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                footerStatusColor="${statusColorError}"
                ;;
            *"No new software available."* )
                availableSoftwareUpdates="No new software available."
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: Thanks for keeping your Mac up-to-date, status: success, statustext: ${availableSoftwareUpdates}"
                info "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                footerStatusColor="${statusColorSuccess}"
                ;;
            * )
                SUList=$( echo "${SUListRaw}" | grep "*" | sed "s/\* Label: //g" | sed "s/,*$//g" )
                availableSoftwareUpdates="${SUList}"
                checkStagedUpdate
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: System Settings > General > Software Update; ${stagingMessage}, status: error, statustext: ${availableSoftwareUpdates}"
                warning "${humanReadableCheckName}: ${availableSoftwareUpdates}"
                footerStatusColor="${statusColorError}"
                ;;
        esac

    else

        # Treat a DDM-enforced OS Updates which contains the current OS as if there are no updates
        if [[ -z "$ddmEnforcedInstallDate" ]]; then
            availableSoftwareUpdates="None"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: Thanks for keeping your Mac up-to-date, status: success, statustext: ${availableSoftwareUpdates}"
            info "${humanReadableCheckName}: ${availableSoftwareUpdates}"
            footerStatusColor="${statusColorSuccess}"
        elif [[ -n "${ddmBuildVersionString}" && "${ddmBuildVersionString}" != "(null)" && "${osBuild}" == "${ddmBuildVersionString}" ]]; then
            availableSoftwareUpdates="Up-to-date"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: Thanks for keeping your Mac up-to-date, status: success, statustext: ${availableSoftwareUpdates}"
            info "${humanReadableCheckName}: ${availableSoftwareUpdates} (build match)"
            footerStatusColor="${statusColorSuccess}"
        elif is-at-least "${ddmVersionString}" "${osVersion}"; then
            availableSoftwareUpdates="Up-to-date"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: Thanks for keeping your Mac up-to-date, status: success, statustext: ${availableSoftwareUpdates}"
            info "${humanReadableCheckName}: ${availableSoftwareUpdates}"
            footerStatusColor="${statusColorSuccess}"
        else
            availableSoftwareUpdates="macOS ${ddmVersionString} (${ddmEnforcedInstallDateHumanReadable})"
            checkStagedUpdate
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: System Settings > General > Software Update; ${stagingMessage}, status: error, statustext: ${availableSoftwareUpdates}"
            info "${humanReadableCheckName}: ${availableSoftwareUpdates}"
            footerStatusColor="${statusColorError}"
        fi

    fi

    dialogUpdate "icon: SF=arrow.down.circle.dotted,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Last App Auto-Patch Run
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkAppAutoPatch() {

    local humanReadableCheckName="App Auto-Patch last run"
    local footerStatusColor="${statusColorSuccess}"
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
    local canEvaluateLastRun="true"

    # Check if log file exists
    if [[ ! -f "${aap_log_path}" ]]; then
        errorOut "${humanReadableCheckName}: Log file not found"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please run App Auto-Patch from the ${organizationSelfServiceMarketingName}, status: fail, statustext: Log not found"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorFail}"
        canEvaluateLastRun="false"
    fi

    # Preferred: pull the last machine timestamp from the log (YYYYMMDDHHMMSS)
    local aap_ts_line aap_ts last_run_epoch now_epoch seconds_since_last_run days_since_last_run

    if [[ "${canEvaluateLastRun}" == "true" ]]; then
        aap_ts_line=$(grep -E "Current time stamp:" "${aap_log_path}" | tail -1)
    fi

    if [[ "${canEvaluateLastRun}" == "true" && -z "${aap_ts_line}" ]]; then
        # Fallback: use log mtime if the timestamp line is missing
        last_run_epoch=$(stat -f %m "${aap_log_path}" 2>/dev/null)
    elif [[ "${canEvaluateLastRun}" == "true" ]]; then
        aap_ts=$(echo "${aap_ts_line}" | awk '{print $NF}')

        # Validate expected format (14 digits)
        if [[ ! "${aap_ts}" =~ ^[0-9]{14}$ ]]; then
            errorOut "${humanReadableCheckName}: Unable to parse AAP timestamp"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please run App Auto-Patch from the ${organizationSelfServiceMarketingName}, status: fail, statustext: Invalid timestamp format"
            overallHealth+="${humanReadableCheckName}; "
            footerStatusColor="${statusColorFail}"
            canEvaluateLastRun="false"
        else

            # Convert YYYYMMDDHHMMSS -> epoch seconds (macOS date)
            last_run_epoch=$(date -j -f "%Y%m%d%H%M%S" "${aap_ts}" "+%s" 2>/dev/null)
        fi
    fi

    if [[ "${canEvaluateLastRun}" == "true" && ( -z "${last_run_epoch}" || ! "${last_run_epoch}" =~ ^[0-9]+$ ) ]]; then
        errorOut "${humanReadableCheckName}: Unable to determine last run time"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please run App Auto-Patch from the ${organizationSelfServiceMarketingName}, status: fail, statustext: Unable to determine last run"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorFail}"
        canEvaluateLastRun="false"
    fi

    if [[ "${canEvaluateLastRun}" == "true" ]]; then
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
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please run App Auto-Patch from the ${organizationSelfServiceMarketingName}, status: fail, statustext: ${days_since_last_run_display}"
            overallHealth+="${humanReadableCheckName}; "
            footerStatusColor="${statusColorFail}"
        elif (( days_since_last_run >= aap_warning_threshold )); then
            warning "${humanReadableCheckName}: ${days_since_last_run_display} (exceeds warning threshold of ${aap_warning_threshold} days)"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: Please run App Auto-Patch from the ${organizationSelfServiceMarketingName}, status: error, statustext: ${days_since_last_run_display}"
            footerStatusColor="${statusColorError}"
        else
            info "${humanReadableCheckName}: ${days_since_last_run_display}"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: You can run App Auto-Patch at any time from the ${organizationSelfServiceMarketingName}, status: success, statustext: ${days_since_last_run_display}"
            footerStatusColor="${statusColorSuccess}"
        fi
    fi

    dialogUpdate "icon: SF=arrow.triangle.2.circlepath.circle,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check System Integrity Protection
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkSIP() {

    local humanReadableCheckName="System Integrity Protection"
    local footerStatusColor="${statusColorSuccess}"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=checkmark.shield.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    # sipCheck=$( csrutil status )

    case ${bootPoliciesSipStatus} in

        "Enabled" ) 
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
            footerStatusColor="${statusColorSuccess}"
            info "${humanReadableCheckName}: Enabled"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
            footerStatusColor="${statusColorFail}"
            errorOut "${humanReadableCheckName} (${1})"
            overallHealth+="${humanReadableCheckName}; "
            ;;

    esac

    dialogUpdate "icon: SF=checkmark.shield.fill,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Signed System Volume (thanks for the reminder, @hoakley!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkSSV() {

    local humanReadableCheckName="Signed System Volume"
    local footerStatusColor="${statusColorSuccess}"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=lock.shield,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    # ssvCheck=$( csrutil authenticated-root status )

    case ${bootPoliciesSsvStatus} in

        "Enabled" ) 
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
            footerStatusColor="${statusColorSuccess}"
            info "${humanReadableCheckName}: Enabled"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
            footerStatusColor="${statusColorFail}"
            errorOut "${humanReadableCheckName} (${1})"
            overallHealth+="${humanReadableCheckName}; "
            ;;

    esac

    dialogUpdate "icon: SF=lock.shield,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Gatekeeper / XProtect (thanks for the reminder, @hoakley!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkGatekeeperXProtect() {

    local humanReadableCheckName="Gatekeeper / XProtect"
    local footerStatusColor="${statusColorSuccess}"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=bolt.shield.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    gatekeeperXProtectCheck=$( spctl --status )

    case ${gatekeeperXProtectCheck} in

        *"enabled"* ) 
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
            footerStatusColor="${statusColorSuccess}"
            info "${humanReadableCheckName}: Enabled"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
            footerStatusColor="${statusColorFail}"
            errorOut "${humanReadableCheckName} (${1})"
            overallHealth+="${humanReadableCheckName}; "
            ;;

    esac

    dialogUpdate "icon: SF=bolt.shield.fill,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Firewall
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkFirewall() {

    local humanReadableCheckName="Firewall"
    local footerStatusColor="${statusColorSuccess}"
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
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
            footerStatusColor="${statusColorSuccess}"
            info "${humanReadableCheckName}: Enabled"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
            footerStatusColor="${statusColorFail}"
            errorOut "${humanReadableCheckName}: Failed"
            overallHealth+="${humanReadableCheckName}; "
            ;;

    esac

    dialogUpdate "icon: SF=firewall.fill,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Uptime
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkUptime() {

    local humanReadableCheckName="Uptime"
    local footerStatusColor="${statusColorSuccess}"
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
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: Please restart your Mac regularly, status: error, statustext: ${uptimeHumanReadable}"
                footerStatusColor="${statusColorError}"
                warning "${humanReadableCheckName}: ${uptimeHumanReadable}"
                ;;

            "error" | * )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please restart your Mac regularly, status: fail, statustext: ${uptimeHumanReadable}"
                footerStatusColor="${statusColorFail}"
                errorOut "${humanReadableCheckName}: ${uptimeHumanReadable}"
                overallHealth+="${humanReadableCheckName}; "
                ;;

        esac
    
    else
    
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: Thanks for restarting your Mac regularly, status: success, statustext: ${uptimeHumanReadable}"
        footerStatusColor="${statusColorSuccess}"
        info "${humanReadableCheckName}: ${uptimeHumanReadable}"
    
    fi

    dialogUpdate "icon: SF=stopwatch,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Free Disk Space
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkFreeDiskSpace() {

    local humanReadableCheckName="Free Disk Space"
    local footerStatusColor="${statusColorSuccess}"
    local diskRawValues=""
    local diskutilInfo=""
    local freeSpace=""
    local diskBytes=""
    local freeBytes=""
    local freePercentage=""
    local diskSpace=""
    local canEvaluateDiskSpace="true"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=externaldrive.fill.badge.checkmark,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    diskRawValues=$( osascript -l JavaScript -e "ObjC.import('Foundation'); var url = \$.NSURL.fileURLWithPath('/'); var result = url.resourceValuesForKeysError(['NSURLVolumeAvailableCapacityForImportantUsageKey','NSURLVolumeTotalCapacityKey'], null); [result.valueForKey('NSURLVolumeAvailableCapacityForImportantUsageKey').js, result.valueForKey('NSURLVolumeTotalCapacityKey').js].join(' ');" 2>/dev/null )
    read freeBytes diskBytes <<< "${diskRawValues}"

    if [[ "${freeBytes}" == <-> && "${diskBytes}" == <-> ]] && (( freeBytes > 0 && diskBytes >= freeBytes )); then

        freeSpace=$( echo "scale=1; ${freeBytes} / 1000000000" | bc )
        freeSpace="${freeSpace} GB"
        freePercentage=$( echo "scale=2; (${freeBytes} * 100) / ${diskBytes}" | bc )

    else

        warning "JXA disk space query returned invalid data; falling back to diskutil. diskBytes=${diskBytes}, freeBytes=${freeBytes}"
        diskutilInfo=$( diskutil info / 2>/dev/null )
        freeSpace=$( echo "${diskutilInfo}" | grep -E 'Free Space|Available Space|Container Free Space' | awk -F ":\s*" '{ print $2 }' | awk -F "(" '{ print $1 }' | xargs )
        diskBytes=$( echo "${diskutilInfo}" | grep -E 'Total Space' | sed -E 's/.*\(([0-9]+) Bytes\).*/\1/' )
        freeBytes=$( echo "${diskutilInfo}" | grep -E 'Free Space|Available Space|Container Free Space' | sed -E 's/.*\(([0-9]+) Bytes\).*/\1/' )

        if [[ "${freeBytes}" == <-> && "${diskBytes}" == <-> ]] && (( diskBytes > 0 && diskBytes >= freeBytes )); then

            freePercentage=$( echo "scale=2; (${freeBytes} * 100) / ${diskBytes}" | bc )

        else

            warning "Invalid disk space data: diskBytes=${diskBytes}, freeBytes=${freeBytes}"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: error, statustext: Unable to determine"
            warning "${humanReadableCheckName}: Unable to determine"
            footerStatusColor="${statusColorError}"
            canEvaluateDiskSpace="false"

        fi

    fi

    if [[ "${canEvaluateDiskSpace}" == "true" ]]; then
        diskSpace="${freeSpace} free (${freePercentage}% available)"

        if (( $( echo "${freePercentage} < ${allowedMinimumFreeDiskPercentage}" | bc -l ) )); then

            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: See KB0080685 Disk Usage to help identify the 50 largest directories, status: fail, statustext: ${diskSpace}"
            footerStatusColor="${statusColorFail}"
            errorOut "${humanReadableCheckName}: ${diskSpace}"
            overallHealth+="${humanReadableCheckName}; "

        else

            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${diskSpace}"
            footerStatusColor="${statusColorSuccess}"
            info "${humanReadableCheckName}: ${diskSpace}"

        fi
    fi

    dialogUpdate "icon: SF=externaldrive.fill.badge.checkmark,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check User Directory Size and Item Count — Parameter 2: Target Directory; Parameter 3: Icon; Parameter 4: Display Name
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkUserDirectorySizeItems() {

    local targetDirectory="${loggedInUserHomeDirectory}/${2}"
    local humanReadableCheckName="${4}"
    local footerStatusColor="${statusColorSuccess}"
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
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${userDirectoryResult}"
        footerStatusColor="${statusColorSuccess}"
        info "${humanReadableCheckName}: ${userDirectoryResult}"
    else
        dirBlocks=$( du -s "${targetDirectory}" 2>/dev/null | awk '{print $1}' )
        dirBytes=$( echo "${dirBlocks} * 512" | bc 2>/dev/null || echo "0" )
        percentage=$( echo "scale=2; if (${totalDiskBytes} > 0) ${dirBytes} * 100 / ${totalDiskBytes} else 0" | bc -l 2>/dev/null || echo "0" )
        userDirectoryResult="${userDirectorySize} (${userDirectoryItems} items) — ${percentage}% of disk"
        if (( $( echo ${percentage}'>'${allowedMaximumDirectoryPercentage} | bc -l 2>/dev/null ) )); then
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: Please contact ${supportTeamName} if you need assistance, status: error, statustext: ${userDirectoryResult}"
            footerStatusColor="${statusColorError}"
            warning "${humanReadableCheckName}: ${userDirectoryResult}"
            # overallHealth+="${humanReadableCheckName}; " # Uncomment to treat as an error
        else
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${userDirectoryResult}"
            footerStatusColor="${statusColorSuccess}"
            info "${humanReadableCheckName}: ${userDirectoryResult}"
        fi
    fi

    dialogUpdate "icon: SF=${3},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check the status of the MDM Profile
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkMdmProfile() {
    local humanReadableCheckName="${mdmVendor} MDM Profile"
    local footerStatusColor="${statusColorSuccess}"
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
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Installed"
        footerStatusColor="${statusColorSuccess}"
        info "${humanReadableCheckName}: Installed"
    else
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, status: fail, statustext: NOT Installed"
        footerStatusColor="${statusColorFail}"
        errorOut "${humanReadableCheckName} (${1})"
        overallHealth+="${humanReadableCheckName}; "
        errorOut "Execute the following command to determine the profileIdentifier of the MDM Profile:"
        errorOut "sudo profiles show enrollment | grep 'profileIdentifier:'"
    fi

    dialogUpdate "icon: SF=gear.badge,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Apple Push Notification service (thanks, @isaacatmann!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkAPNs() {

    local humanReadableCheckName="Apple Push Notification service"
    local footerStatusColor="${statusColorSuccess}"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=wave.3.up.circle,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    apnsCheck=$( command log show --last 24h --predicate 'subsystem == "com.apple.ManagedClient" && (eventMessage CONTAINS[c] "Received HTTP response (200) [Acknowledged" || eventMessage CONTAINS[c] "Received HTTP response (200) [NotNow")' | tail -1 | cut -d '.' -f 1 )

    if [[ "${apnsCheck}" == *"Timestamp"* ]] || [[ -z "${apnsCheck}" ]]; then

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
        footerStatusColor="${statusColorFail}"
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
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${apnsStatus}"
        footerStatusColor="${statusColorSuccess}"
        info "${humanReadableCheckName}: ${apnsCheck}"

    fi

    dialogUpdate "icon: SF=wave.3.up.circle,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

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
# https://learn.jamf.com/r/en-US/jamf-domains-safelist-reference/Jamf_Domains_Safelist_Reference
# https://learn.jamf.com/r/en-US/jamf-ip-address-list/Jamf_Public_IP_Address_List
jamfHosts=(
    "jamf.com,443"
    "test.jamfcloud.com,443"
    "account.jamf.com,443"
    "idpcs.jamf.com,443"
    "account-cdn.jamf.com,443"
    "cdn.mfe.jamf.io,443"
    "api.apigw.jamf.com,443"
    "us.apigw.jamf.com,443"
    "eu.apigw.jamf.com,443"
    "apac.apigw.jamf.com,443"
    "appinstallers-packages.services.jamfcloud.com,443"
    "registration.cloudconnector.gov.services.jamfcloud.com,443"
    "registration.cloudconnector.services.jamfcloud.com,443"
    "ics.services.jamfcloud.com,443"
    "csa.services.jamfcloud.com,443"
    "jcds.apne1.inf.jamf.one,443"
    "jcds.apse2.inf.jamf.one,443"
    "jcds.euw2.inf.jamf.one,443"
    "jcds.euc1.inf.jamf.one,443"
    "jcds.use1.inf.jamf.one,443"
    "packages.soup.services.jamfcloud.com,443"
    "www.jamfroutines.com,443"
    "icon-staging-production-use1-ics-application.s3.amazonaws.com,443"
    "clientstream.launchdarkly.com,443"
    "mobile.launchdarkly.com,443"
    "app.launchdarkly.com,443"
    "nom.telemetrydeck.com,443"
)

# Generic network-host tester: uses `nc` for ports or `curl` for URLs
function checkNetworkHosts() {
    local index="$1"
    local name="$2"
    shift 2
    local hosts=("$@")
    local footerStatusColor="${statusColorSuccess}"

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
        dialogUpdate "listitem: index: ${index}, icon: SF=$(printf "%02d" $(($index+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Passed"
        footerStatusColor="${statusColorSuccess}"
        info "${name}: ${results%;; }"
    else
        dialogUpdate "listitem: index: ${index}, icon: SF=$(printf "%02d" $(($index+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, status: fail, statustext: Failed"
        footerStatusColor="${statusColorFail}"
        errorOut "${name}: ${results%;; }"
        overallHealth+="${name}; "
    fi

    dialogUpdate "icon: SF=network,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check the expiration date of the MDM Certificate (thanks, @isaacatmann!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkMdmCertificateExpiration() {

    local certificateName=""
    local footerStatusColor="${statusColorSuccess}"

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
            ;;
    esac

    local humanReadableCheckName="${mdmVendor} Certificate Authority"
    notice "Check the expiration date of the ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=mail.and.text.magnifyingglass,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining MDM Certificate expiration date …"

    sleep "${anticipationDuration}"

    if [[ -n "${certificateName}" ]]; then
        expiry=$(security find-certificate -c "${certificateName}" -p /Library/Keychains/System.keychain 2>/dev/null | \
                 openssl x509 -noout -enddate | cut -d= -f2)

        if [[ -z "$expiry" ]]; then
            expirationDateFormatted="NOT Installed"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorFail}, iconalpha: 1, status: fail, statustext: ${expirationDateFormatted}"
            footerStatusColor="${statusColorFail}"
            errorOut "${humanReadableCheckName} Expiration: ${expirationDateFormatted}"
            overallHealth+="${humanReadableCheckName}; "
        else
            now_seconds=$(date +%s)
            date_seconds=$(date -j -f "%b %d %T %Y %Z" "$expiry" +%s)
            expirationDateFormatted=$(date -j -f "%b %d %H:%M:%S %Y GMT" "$expiry" "+%d-%b-%Y")

            if (( date_seconds > now_seconds )); then
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${expirationDateFormatted}"
                footerStatusColor="${statusColorSuccess}"
                info "${humanReadableCheckName} Expiration: ${expirationDateFormatted}"
            else
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorFail}, iconalpha: 1, status: fail, statustext: ${expirationDateFormatted}"
                footerStatusColor="${statusColorFail}"
                errorOut "${humanReadableCheckName} Expiration: ${expirationDateFormatted}"
                overallHealth+="${humanReadableCheckName}; "
            fi
        fi
    fi

    dialogUpdate "icon: SF=mail.and.text.magnifyingglass,weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Last Jamf Pro Check-In (thanks, @jordywitteman!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkJamfProCheckIn() {

    local humanReadableCheckName="Last Jamf Pro check-in"
    local footerCheckIcon="SF=arrow.left.arrow.right.circle"
    local footerStatusColor="${statusColorSuccess}"
    notice "Checking ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=arrow.left.arrow.right.circle,${organizationColorScheme}"
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
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, status: fail, statustext: ${last_check_in_time_human_readable}"
        errorOut "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorFail}"
    elif [ ${time_since_check_in_epoch} -ge ${check_in_time_aging} ]; then
        # check_in_status_indicator="🟠"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: ${last_check_in_time_human_readable}"
        warning "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorError}"
    elif [ ${time_since_check_in_epoch} -lt ${check_in_time_aging} ]; then
        # check_in_status_indicator="🟢"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${last_check_in_time_human_readable}"
        info "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Last Jamf Pro Inventory Update (thanks, @jordywitteman!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkJamfProInventory() {

    local humanReadableCheckName="Last Jamf Pro inventory update"
    local footerCheckIcon="SF=checklist"
    local footerStatusColor="${statusColorSuccess}"
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
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, status: fail, statustext: ${last_inventory_time_human_readable}"
        errorOut "${humanReadableCheckName}: ${last_inventory_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorFail}"
    elif [ ${time_since_inventory_epoch} -ge ${inventory_time_aging} ]; then
        # inventory_status_indicator="🟠"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: ${last_inventory_time_human_readable}"
        warning "${humanReadableCheckName}: ${last_inventory_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorError}"
    elif [ ${time_since_inventory_epoch} -lt ${inventory_time_aging} ]; then
        # inventory_status_indicator="🟢"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${last_inventory_time_human_readable}"
        info "${humanReadableCheckName}: ${last_inventory_time_human_readable}"
    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Last Mosyle Check-In (thanks, @precursorca!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkMosyleCheckIn() {

    local humanReadableCheckName="Last Mosyle check-in"
    local footerCheckIcon="SF=arrow.left.arrow.right.circle"
    local footerStatusColor="${statusColorSuccess}"
    notice "Checking ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=arrow.left.arrow.right.circle,${organizationColorScheme}"
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
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, status: fail, statustext: ${last_check_in_time_human_readable}"
        errorOut "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorFail}"
    elif [ ${time_since_check_in_epoch} -ge ${check_in_time_aging} ]; then
        # check_in_status_indicator="🟠"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: ${last_check_in_time_human_readable}"
        warning "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorError}"
    elif [ ${time_since_check_in_epoch} -lt ${check_in_time_aging} ]; then
        # check_in_status_indicator="🟢"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${last_check_in_time_human_readable}"
        info "${humanReadableCheckName}: ${last_check_in_time_human_readable}"
    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check FileVault
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkFileVault() {

    local humanReadableCheckName="FileVault"
    local footerCheckIcon="SF=lock.laptopcomputer"
    local footerStatusColor="${statusColorSuccess}"
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
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled"
                info "${humanReadableCheckName}: Enabled"
                ;;

            *"Deferred enablement appears to be active for user"* )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enabled (next login)"
                warning "${humanReadableCheckName}: Enabled (next login)"
                ;;

            *  )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorFail}, iconalpha: 1, status: fail, statustext: Failed"
                errorOut "${humanReadableCheckName} (${1})"
                overallHealth+="${humanReadableCheckName}; "
                footerStatusColor="${statusColorFail}"
                ;;

        esac

    else

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorFail}, iconalpha: 1, status: fail, statustext: Failed"
        errorOut "${humanReadableCheckName} (${1})"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorFail}"

    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Internal Validation — Parameter 2: Target File; Parameter 3: Icon; Parameter 4: Display Name
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkInternal() {

    checkInternalTargetFile="${2}"
    checkInternalTargetFileIcon="${3}"
    checkInternalTargetFileDisplayName="${4}"
    local footerCheckIcon="${checkInternalTargetFileIcon}"
    local footerStatusColor="${statusColorSuccess}"

    notice "Internal Check: ${checkInternalTargetFile} …"

    dialogUpdate "icon: ${checkInternalTargetFileIcon}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining status of ${checkInternalTargetFileDisplayName} …"

    sleep "${anticipationDuration}"

    if [[ -e "${checkInternalTargetFile}" ]]; then

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Installed"
        info "${checkInternalTargetFileDisplayName} installed"
        footerCheckIcon="SF=checkmark.circle"
        
    else

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorFail}, iconalpha: 1, subtitle: Visit the ${organizationSelfServiceMarketingName} to install ${checkInternalTargetFileDisplayName}, status: fail, statustext: NOT Installed"
        errorOut "${checkInternalTargetFileDisplayName} NOT Installed"
        overallHealth+="${checkInternalTargetFileDisplayName}; "
        footerCheckIcon="SF=xmark.circle"
        footerStatusColor="${statusColorFail}"

    fi

    sleep "${anticipationDuration}"

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Touch ID Status (thanks, @alexfinn!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkTouchID() {

    local humanReadableCheckName="Touch ID"
    local footerCheckIcon="SF=touchid"
    local footerStatusColor="${statusColorSuccess}"
    local bioOutput=""
    local iokitDiagnosticsOutput=""
    local iokitBiometricSensorCount="0"
    local hw="Absent"
    notice "Check ${humanReadableCheckName} …"
    
    dialogUpdate "icon: SF=touchid,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} status …"

    sleep "${anticipationDuration}"

    # --- Detect Touch ID-capable hardware (internal or external) ---
    bioOutput=$( ioreg -l 2>/dev/null )
    iokitDiagnosticsOutput=$( /usr/sbin/ioreg -a -k IOKitDiagnostics 2>/dev/null )

    # Preferred check: Class instance count from IOKitDiagnostics.
    if [[ -n "${iokitDiagnosticsOutput}" ]]; then
        iokitBiometricSensorCount=$( /usr/libexec/PlistBuddy -c "Print :IOKitDiagnostics:Classes:AppleBiometricSensor" /dev/stdin <<< "${iokitDiagnosticsOutput}" 2>/dev/null | awk '/^[0-9]+$/ {print $1; exit}' )
        [[ -z "${iokitBiometricSensorCount}" ]] && iokitBiometricSensorCount="0"
    fi

    if [[ "${iokitBiometricSensorCount}" -gt 0 ]]; then
        hw="Present"
    # Fallback: Parse class count from standard ioreg output.
    elif [[ $bioOutput =~ '"AppleBiometricSensor"=([0-9]+)' && ${match[1]} -gt 0 ]]; then
        hw="Present"
    # Fallback: Generic Touch ID marker in ioreg output (covers external keyboards).
    elif [[ "${bioOutput:l}" == *"touch id"* ]]; then
        hw="Present"
    fi

    if [[ "${hw}" == "Absent" ]]; then

        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: ${hw}"
        info "Touch ID hardware ${hw:l}"
        footerStatusColor="${statusColorError}"

    else

        # Enrollment check
        local enrolled="false"
        local bioCount="0"
        local bioutilStatus=""

        if command -v bioutil >/dev/null 2>&1; then
            bioutilStatus=$( runAsUser bioutil -c 2>/dev/null )
            bioCount=$( echo "${bioutilStatus}" | awk '
                BEGIN { IGNORECASE=1; found=0 }
                {
                    if (match($0, /[0-9]+[[:space:]]+biometric template/)) {
                        value=substr($0, RSTART, RLENGTH)
                        sub(/[[:space:]]+biometric template.*/, "", value)
                        print value
                        found=1
                        exit
                    }
                    if (match($0, /[0-9]+[[:space:]]+finger(print)?s?/)) {
                        value=substr($0, RSTART, RLENGTH)
                        sub(/[[:space:]]+finger(print)?s?/, "", value)
                        print value
                        found=1
                        exit
                    }
                }
                END { if (found==0) print "0" }
            ' )
            [[ "${bioCount}" -gt 0 ]] && enrolled="true"
        fi

        if [[ "${enrolled}" == "true" ]]; then
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Enrolled"
            info "Touch ID: Enabled & Enrolled (${bioCount} template(s))"
        else
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: Not enrolled"
            warning "Touch ID: Hardware present, not enrolled"
            footerStatusColor="${statusColorError}"
        fi

    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Wi-Fi Strength (thanks, @kgolden-code!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkWiFiStrength() {

    local humanReadableCheckName="Wi-Fi Signal"
    local footerStatusColor="${statusColorSuccess}"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=wifi,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Measuring Wi-Fi signal strength …"

    sleep "${anticipationDuration}"

    # Get active Wi-Fi interface
    local wifiInterface
    wifiInterface=$( networksetup -listallhardwareports | awk '/Wi-Fi|AirPort/{getline; print $2}' | head -1 )

    local rssi=""
    if [[ -n "${wifiInterface}" ]]; then
        # Try modern wdutil first (Sonoma+)
        rssi=$( wdutil info 2>/dev/null | awk -F': ' '/RSSI/ {print $2; exit}' | awk '{print $1}' | tr -d ' ()\r\n' )
        
        # Fallback to classic airport
        if [[ -z "${rssi}" || "${rssi}" == "0" ]]; then
            local airportPath="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            if [[ -x "${airportPath}" ]]; then
                rssi=$( "${airportPath}" -I 2>/dev/null | grep "CtlRSSI" | awk '{print $2}' )
            fi
        fi
    fi

    if [[ -z "${rssi}" || "${rssi}" == "0" ]]; then
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${footerStatusColor}, iconalpha: 0.6, subtitle: Wi-Fi not active or Ethernet is primary, status: success, statustext: N/A (Ethernet)"
        info "${humanReadableCheckName}: Skipped — Ethernet primary or no Wi-Fi signal detected"
        dialogUpdate "icon: SF=wifi,weight=semibold,colour=${footerStatusColor}"
        sleep $((anticipationDuration / 2))
        return
    fi

    local quality="Unknown"

    if (( rssi >= -55 )); then
        quality="Excellent"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${footerStatusColor}, iconalpha: 0.8, subtitle: RSSI ${rssi} dBm, status: success, statustext: ${quality}"
    elif (( rssi >= -65 )); then
        quality="Good"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${footerStatusColor}, iconalpha: 0.8, subtitle: RSSI ${rssi} dBm, status: success, statustext: ${quality}"
    elif (( rssi >= -75 )); then
        quality="Fair"
        footerStatusColor="${statusColorError}"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorError}, iconalpha: 0.8, subtitle: RSSI ${rssi} dBm, status: error, statustext: ${quality}"
    else
        quality="Poor"
        footerStatusColor="${statusColorFail}"
        overallHealth+="${humanReadableCheckName}; "
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorFail}, iconalpha: 0.8, subtitle: RSSI ${rssi} dBm, status: fail, statustext: ${quality}"
    fi

    checkInspectTextByIndex[${1}]="${quality} (${rssi} dBm)"
    dialogUpdate "icon: SF=wifi,weight=semibold,colour=${footerStatusColor}"
    info "${humanReadableCheckName}: ${quality} (${rssi} dBm)"

    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check VPN Installation
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkVPN() {

    local footerCheckIcon="${vpnAppPath}"
    local footerStatusColor="${statusColorSuccess}"

    notice "Check ${vpnAppName} …"

    dialogUpdate "icon: ${vpnAppPath}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining status of ${vpnAppName} …"

    # sleep "${anticipationDuration}"

    case ${vpnStatus} in

        *"NOT installed"* )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
            errorOut "${vpnAppName} Failed"
            overallHealth+="${vpnAppName}; "
            footerCheckIcon="SF=xmark.circle"
            footerStatusColor="${statusColorFail}"
            ;;

        *"Idle"* )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: Idle"
            info "${vpnAppName} idle"
            footerCheckIcon="SF=exclamationmark.triangle.fill"
            footerStatusColor="${statusColorError}"
            ;;

        "Connected"* | "${ciscoVPNIP}" )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Connected"
            info "${vpnAppName} Connected"
            footerCheckIcon="SF=checkmark.circle"
            ;;

        "Internal" )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: On-campus / Internal network, status: success, statustext: Internal"
            info "${vpnAppName} Internal"
            footerCheckIcon="SF=checkmark.circle"
            ;;

        "Warning: Disconnected" | "Disconnected" )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: Disconnected"
            warning "${vpnAppName} Disconnected"
            footerCheckIcon="SF=exclamationmark.triangle.fill"
            footerStatusColor="${statusColorError}"
            ;;

        "None" )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: No VPN"
            info "No VPN"
            footerCheckIcon="SF=xmark.circle"
            footerStatusColor="${statusColorError}"
            ;;

        * )
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: Unknown"
            warning "${vpnAppName} Unknown"
            footerCheckIcon="SF=exclamationmark.triangle.fill"
            footerStatusColor="${statusColorError}"
            ;;

    esac

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check External Jamf Pro Validation (where Parameter 2 represents the Jamf Pro Policy Custom Trigger)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkExternalJamfPro() {

    trigger="${2}"
    appPath="${3}"
    appDisplayName=$(basename "${appPath}" .app)
    local footerCheckIcon="${appPath}"
    local footerStatusColor="${statusColorSuccess}"
    local externalCheckResult=""
    local warningStatus=""

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
    externalCheckResult="${externalValidation#*Script result: }"
    externalCheckResult="${externalCheckResult#<result>}"
    externalCheckResult="${externalCheckResult%</result>}"
    
    # Leverage the organization defaults domain
    if [[ -n $( defaults read "${organizationDefaultsDomain}" 2>/dev/null ) ]]; then

        checkStatus=$( defaults read "${organizationDefaultsDomain}" checkStatus )
        checkType=$( defaults read "${organizationDefaultsDomain}" checkType )
        checkExtended=$( defaults read "${organizationDefaultsDomain}" checkExtended )

        case ${checkType} in

            "fail" )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, status: fail, statustext: $checkStatus"
                errorOut "${appDisplayName} Failed"
                overallHealth+="${appDisplayName}; "
                footerCheckIcon="SF=xmark.circle"
                footerStatusColor="${statusColorFail}"
                ;;

            "success" )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: $checkStatus"
                info "${appDisplayName} $checkStatus"
                footerCheckIcon="SF=checkmark.circle"
                ;;

            "warning" )
                warningStatus="${checkStatus}"
                if [[ "${warningStatus:l}" == warning:* ]]; then
                    warningStatus="${warningStatus#*: }"
                elif [[ "${checkStatus:l}" == "warning" ]] && [[ -n "${checkExtended}" ]]; then
                    warningStatus="${checkExtended}"
                fi
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: $warningStatus"
                warning "${appDisplayName} Warning:$warningStatus"
                footerCheckIcon="SF=exclamationmark.triangle.fill"
                footerStatusColor="${statusColorError}"
                ;;

            "error" | * )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: $checkStatus:$checkExtended"
                errorOut "${appDisplayName} Error:$checkExtended"
                overallHealth+="${appDisplayName}; "
                footerCheckIcon="SF=exclamationmark.triangle.fill"
                footerStatusColor="${statusColorError}"
                ;;

        esac

    # Ignore the organization defaults domain
    else

        case ${externalCheckResult:l} in

            *"failed"* )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: Please contact ${supportTeamName}, status: fail, statustext: Failed"
                errorOut "${appDisplayName} Failed"
                overallHealth+="${appDisplayName}; "
                footerCheckIcon="SF=xmark.circle"
                footerStatusColor="${statusColorFail}"
                ;;

            *"running"* )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Running"
                info "${appDisplayName} running"
                footerCheckIcon="SF=checkmark.circle"
                ;;

            *"warning"* )
                warningStatus="${externalCheckResult}"
                if [[ "${warningStatus:l}" == warning:* ]]; then
                    warningStatus="${warningStatus#*: }"
                fi
                [[ -z "${warningStatus}" ]] && warningStatus="Warning"
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: $warningStatus"
                warning "${appDisplayName} Warning:$warningStatus"
                footerCheckIcon="SF=exclamationmark.triangle.fill"
                footerStatusColor="${statusColorError}"
                ;;

            *"error"* | * )
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: Error"
                errorOut "${appDisplayName} Error"
                overallHealth+="${appDisplayName}; "
                footerCheckIcon="SF=exclamationmark.triangle.fill"
                footerStatusColor="${statusColorError}"
                ;;

        esac

    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Network Quality
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkNetworkQuality() {

    local humanReadableCheckName="Network Quality"
    local footerCheckIcon="SF=gauge.with.dots.needle.67percent"
    local footerStatusColor="${statusColorSuccess}"
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
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, status: success, statustext: ${mbps} Mbps ${testStatus}"
    info "Download: ${mbps} Mbps, Responsiveness: ${dlResponsiveness}; "

    dialogUpdate "icon: ${icon}"
    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Homebrew Status
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkHomebrewStatus() {

    local humanReadableCheckName="Homebrew Status"
    local footerCheckIcon="SF=mug.fill"
    local footerStatusColor="${statusColorSuccess}"
    local brewBinary=""
    local installedHomebrewVersion=""
    local latestHomebrewVersion=""
    local latestHomebrewResponse=""
    local homebrewOutdatedJSON=""
    local outdatedFormulaeCount=""
    local outdatedCasksCount=""
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=mug.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Determining ${humanReadableCheckName} …"

    sleep "${anticipationDuration}"

    brewBinary=$( runAsUser env PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" zsh -lc 'command -v brew 2>/dev/null' 2>/dev/null | grep '^/' | tail -1 | xargs )
    [[ -z "${brewBinary}" && -x "/opt/homebrew/bin/brew" ]] && brewBinary="/opt/homebrew/bin/brew"
    [[ -z "${brewBinary}" && -x "/usr/local/bin/brew" ]] && brewBinary="/usr/local/bin/brew"

    if [[ -z "${brewBinary}" ]]; then
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: Optional tool not detected on this Mac, status: success, statustext: Not installed"
        info "${humanReadableCheckName}: Not installed"
    else
        installedHomebrewVersion=$( runHomebrewAsUser "${brewBinary}" --version 2>/dev/null | awk '/^Homebrew / { print $2; exit }' )
        latestHomebrewResponse=$( curl -fsL --connect-timeout 5 --max-time 10 "https://api.github.com/repos/Homebrew/brew/releases/latest" 2>/dev/null )

        if [[ -n "${latestHomebrewResponse}" ]]; then
            latestHomebrewVersion=$( get_json_value "${latestHomebrewResponse}" "tag_name" 2>/dev/null | tr -d '\r' | sed 's/^v//' )
            [[ "${latestHomebrewVersion}" == "undefined" ]] && latestHomebrewVersion=""
        fi

        homebrewOutdatedJSON=$( runHomebrewAsUser "${brewBinary}" outdated --json=v2 2>/dev/null )

        if [[ -n "${homebrewOutdatedJSON}" ]] && validateJson "${homebrewOutdatedJSON}" && jsonIsObject "${homebrewOutdatedJSON}"; then
            outdatedFormulaeCount=$( printf '%s' "${homebrewOutdatedJSON}" | jq -r '(.formulae // []) | length' 2>/dev/null )
            outdatedCasksCount=$( printf '%s' "${homebrewOutdatedJSON}" | jq -r '(.casks // []) | length' 2>/dev/null )
        else
            outdatedFormulaeCount=$( runHomebrewAsUser "${brewBinary}" outdated --formula --quiet 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ' )
            outdatedCasksCount=$( runHomebrewAsUser "${brewBinary}" outdated --cask --quiet 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ' )
        fi

        if [[ -z "${installedHomebrewVersion}" ]] || [[ -z "${latestHomebrewVersion}" ]] || [[ "${outdatedFormulaeCount}" != <-> ]] || [[ "${outdatedCasksCount}" != <-> ]]; then
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: Homebrew was found but could not be fully evaluated, status: error, statustext: Unable to determine"
            errorOut "${humanReadableCheckName}: Unable to determine; installed=${installedHomebrewVersion:-unknown}; latest=${latestHomebrewVersion:-unknown}; formulae=${outdatedFormulaeCount:-unknown}; casks=${outdatedCasksCount:-unknown}"
            overallHealth+="${humanReadableCheckName}; "
            footerStatusColor="${statusColorError}"
        else

            local totalOutdatedCount=$(( outdatedFormulaeCount + outdatedCasksCount ))

            if [[ "${installedHomebrewVersion}" == "${latestHomebrewVersion}" ]] && (( totalOutdatedCount == 0 )); then
                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${installedHomebrewVersion} current"
                info "${humanReadableCheckName}: Installed ${installedHomebrewVersion}; latest ${latestHomebrewVersion}; outdated formulae ${outdatedFormulaeCount}; outdated casks ${outdatedCasksCount}"
            else
                local statusSummary=""

                if [[ "${installedHomebrewVersion}" != "${latestHomebrewVersion}" ]] && (( totalOutdatedCount > 0 )); then
                    statusSummary="${installedHomebrewVersion} vs ${latestHomebrewVersion}; ${totalOutdatedCount} outdated"
                elif [[ "${installedHomebrewVersion}" != "${latestHomebrewVersion}" ]]; then
                    statusSummary="${installedHomebrewVersion} vs ${latestHomebrewVersion}"
                else
                    statusSummary="${totalOutdatedCount} outdated"
                fi

                dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: Open Terminal and update Homebrew packages if you manage them on this Mac, status: error, statustext: ${statusSummary}"
                errorOut "${humanReadableCheckName}: Installed ${installedHomebrewVersion}; latest ${latestHomebrewVersion}; outdated formulae ${outdatedFormulaeCount}; outdated casks ${outdatedCasksCount}"
                overallHealth+="${humanReadableCheckName}; "
                footerStatusColor="${statusColorError}"
            fi
        fi
    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Electron Apps for the macOS "Corner Mask" Slowdown Bug (Electron < 36.9.2 on macOS 26+)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkElectronCornerMask() {

    local humanReadableCheckName="Electron Corner Mask"
    local footerCheckIcon="SF=cpu.fill"
    local footerStatusColor="${statusColorSuccess}"
    notice "Check ${humanReadableCheckName} …"

    dialogUpdate "icon: SF=cpu.fill,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill ${organizationColorScheme//,/ }, iconalpha: 1, status: wait, statustext: Scanning for Electron apps …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Checking installed Electron apps …"

    sleep "${anticipationDuration}"

    local osMajorVersion="${osVersion%%.*}"
    if [[ "${osMajorVersion}" -lt 26 ]]; then
        info "${humanReadableCheckName}: macOS ${osVersion} — not affected."
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Not affected (macOS ${osVersion})"
    else
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
        local -A processedElectronApps=()

        setopt null_glob

        local appSearchRoots=(
            /Applications
            /Applications/Utilities
            /Users/"${loggedInUser}"/Applications
        )
        local frameworkPaths=(
            /Applications/*.app/Contents/Frameworks/Electron\ Framework.framework
            /Applications/Utilities/*.app/Contents/Frameworks/Electron\ Framework.framework
            /Users/"${loggedInUser}"/Applications/*.app/Contents/Frameworks/Electron\ Framework.framework
        )
        local knownSafeElectronAppNames=(
            "Visual Studio Code.app"
            "Slack.app"
        )
        local app=""
        local appName=""
        local appSearchRoot=""
        local appVersion=""
        local frameworkPath=""
        local versionFile=""
        local frameworkPlist=""
        local frameworkResourcesPath=""
        local frameworkFallbackResourcesPath=""
        local pkgJson=""
        local asarPkgJson=""
        local productJson=""
        local versionTxt=""
        local appInfoPlist=""
        local fixed=""
        local vulnerable=""

        for appName in "${knownSafeElectronAppNames[@]}"; do
            appVersion="${knownSafeElectronApps[$appName]}"
            for appSearchRoot in "${appSearchRoots[@]}"; do
                app="${appSearchRoot}/${appName}"
                if [[ -d "${app}" ]]; then
                    ((foundElectronApps++))
                    processedElectronApps["${app}"]=1
                    safeApps+=("${appName} (${appVersion}) [known fixed]")
                fi
            done
        done

        for frameworkPath in "${frameworkPaths[@]}"; do
            app="${frameworkPath:h:h:h}"
            [[ ! -d "${app}" ]] && continue
            if [[ -n "${processedElectronApps[$app]}" ]]; then
                continue
            fi
            processedElectronApps["${app}"]=1

            ((foundElectronApps++))
            appName="${app:t}"
            appVersion="Unknown"

            frameworkResourcesPath="${frameworkPath}/Versions/Current/Resources"
            frameworkFallbackResourcesPath="${frameworkPath}/Versions/A/Resources"
            versionFile="${frameworkResourcesPath}/version"
            frameworkPlist="${frameworkResourcesPath}/Info.plist"
            if [[ ! -f "${versionFile}" ]]; then
                versionFile="${frameworkFallbackResourcesPath}/version"
            fi
            if [[ ! -f "${frameworkPlist}" ]]; then
                frameworkPlist="${frameworkFallbackResourcesPath}/Info.plist"
            fi
            pkgJson="${app}/Contents/Resources/app/package.json"
            asarPkgJson="${app}/Contents/Resources/app.asar.unpacked/package.json"
            productJson="${app}/Contents/Resources/app/product.json"
            versionTxt="${app}/Contents/Resources/app/version.txt"
            appInfoPlist="${app}/Contents/Info.plist"

            if [[ -f "${versionFile}" ]]; then
                appVersion="${$(<"${versionFile}")//$'\n'/}"
                appVersion="${appVersion//$'\r'/}"
                appVersion="${appVersion//$'\t'/}"
            elif [[ -f "${frameworkPlist}" ]]; then
                appVersion=$(/usr/bin/plutil -extract CFBundleVersion raw -expect string "${frameworkPlist}" 2>/dev/null)
                if [[ -z "${appVersion}" ]]; then
                    appVersion=$(/usr/bin/plutil -extract CFBundleShortVersionString raw -expect string "${frameworkPlist}" 2>/dev/null)
                fi
            elif [[ -f "${pkgJson}" ]]; then
                appVersion=$(grep -Eo '"electronVersion"[^,]*' "${pkgJson}" | awk -F'"' '{print $4}')
            elif [[ -f "${asarPkgJson}" ]]; then
                appVersion=$(grep -Eo '"electronVersion"[^,]*' "${asarPkgJson}" | awk -F'"' '{print $4}')
            elif [[ -f "${productJson}" ]]; then
                appVersion=$(grep -Eo '"version"[^,]*' "${productJson}" | awk -F'"' '{print $4}')
                if [[ ! "${appVersion}" =~ ^[0-9]+\.[0-9]+ ]]; then
                    local commit=$(grep -Eo '"commit"[^,]*' "${productJson}" | awk -F'"' '{print $4}')
                    [[ -n "${commit}" ]] && appVersion="custom-${commit:0:7}"
                fi
            elif [[ -f "${versionTxt}" ]]; then
                appVersion="${$(<"${versionTxt}")//$'\n'/}"
                appVersion="${appVersion//$'\r'/}"
                appVersion="${appVersion//$'\t'/}"
            fi

            appVersion="${appVersion#"${appVersion%%[![:space:]]*}"}"
            appVersion="${appVersion%"${appVersion##*[![:space:]]}"}"

            if [[ -z "${appVersion}" || "${appVersion}" == "Unknown" ]]; then
                if [[ -f "${appInfoPlist}" ]]; then
                    appVersion=$(/usr/bin/plutil -extract CFBundleShortVersionString raw -expect string "${appInfoPlist}" 2>/dev/null)
                    appVersion="${appVersion#"${appVersion%%[![:space:]]*}"}"
                    appVersion="${appVersion%"${appVersion##*[![:space:]]}"}"
                fi

                if [[ -z "${appVersion}" ]]; then
                    warning "${humanReadableCheckName}: ${appName} version unknown"
                    vulnerableApps+=("${appName} (version unknown)")
                else
                    warning "${humanReadableCheckName}: ${appName} Electron version unknown (app ${appVersion})"
                    vulnerableApps+=("${appName} (${appVersion//, /; })")
                fi
                continue
            fi

            vulnerable=true
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
        done

        unsetopt null_glob

        if [[ ${foundElectronApps} -eq 0 ]]; then
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: No Electron apps found"
            info "${humanReadableCheckName}: No Electron-based apps detected."
        elif [[ ${#vulnerableApps[@]} -gt 0 ]]; then
            local vulnerableList=$(printf '%s; ' "${vulnerableApps[@]}")
            vulnerableList="${vulnerableList%; }"
            info "vulnerableList: ${vulnerableList}"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: ${vulnerableList}, status: error, statustext: Susceptible apps found"
            warning "${humanReadableCheckName}: Susceptible Electron apps detected — ${vulnerableList}"
            errorOut "${humanReadableCheckName}: ${vulnerableList}"
            overallHealth+="${humanReadableCheckName}; "
            footerStatusColor="${statusColorError}"
        else
            local safeList=$(printf '%s; ' "${safeApps[@]}")
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: All Electron apps patched"
            info "${humanReadableCheckName}: All Electron apps are running patched versions — ${safeList}"
        fi
    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Bluetooth Sharing
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkBluetoothSharing() {

    local humanReadableCheckName="Bluetooth Sharing"
    local footerCheckIcon="SF=dot.radiowaves.left.and.right"
    local footerStatusColor="${statusColorSuccess}"
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
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Disabled"
    else
        errorOut "${humanReadableCheckName}: Enabled (value: ${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: System Settings > General > Sharing > Accessories & Internet > Bluetooth Sharing > Disable, status: fail, statustext: Enabled"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorFail}"
    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check Password Hint
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkPasswordHint() {

    local humanReadableCheckName="Password Hint"
    local footerCheckIcon="SF=key.horizontal.fill"
    local footerStatusColor="${statusColorSuccess}"
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
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Compliant"
    else
        warning "${humanReadableCheckName}: Hint found"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, status: error, statustext: Found (Non-compliant)"
        footerStatusColor="${statusColorError}"
    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check AirPlay Receiver (thanks, @bigdoodr!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkAirPlayReceiver() {

    local humanReadableCheckName="AirPlay Receiver"
    local footerCheckIcon="SF=airplayvideo.circle.fill"
    local footerStatusColor="${statusColorSuccess}"
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
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: System Settings > General > AirDrop & Handoff > AirPlay Receiver > Disable, status: fail, statustext: Enabled"
            overallHealth+="${humanReadableCheckName}; "
            footerStatusColor="${statusColorFail}"
        else
            # 15.6.1 and earlier, and 26.x+: missing key treated as Disabled/compliant
            info "${humanReadableCheckName}: Disabled (key not found on macOS ${osMajorVersion}.${osMinorVersion})"
            dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Disabled"
        fi

    elif [[ "${result}" == "0" ]]; then
        # Value is 0, disabled (compliant)
        info "${humanReadableCheckName}: Disabled (${keyFound}=${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Disabled"

    elif [[ "${result}" == "1" ]]; then
        # Value is 1, enabled (non-compliant)
        errorOut "${humanReadableCheckName}: Enabled (${keyFound}=${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: System Settings > General > AirDrop & Handoff > AirPlay Receiver > Disable, status: fail, statustext: Enabled"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorFail}"

    elif [[ "${result}" == "2" ]]; then
        # Value is 2 (Contacts Only mode in some versions)
        info "${humanReadableCheckName}: Contacts Only (${keyFound}=${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Contacts Only"

    else
        # Unexpected value
        warning "${humanReadableCheckName}: Unexpected value (${keyFound}=${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorError}, iconalpha: 1, subtitle: System Settings > General > AirDrop & Handoff > AirPlay Receiver > Disable, status: error, statustext: Status Unknown"
        footerStatusColor="${statusColorError}"
    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Check AirDrop
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function checkAirDropSettings() {

    local humanReadableCheckName="AirDrop Settings"
    local footerCheckIcon="SF=airplayaudio.circle.fill"
    local footerStatusColor="${statusColorSuccess}"
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
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: Compliant"
    else
        errorOut "${humanReadableCheckName}: Discoverable by Everyone (value: ${result})"
        dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=bold colour=${statusColorFail}, iconalpha: 1, subtitle: System Settings > General > AirDrop & Handoff > AirDrop > No One / Contacts Only, status: fail, statustext: Everyone"
        overallHealth+="${humanReadableCheckName}; "
        footerStatusColor="${statusColorFail}"
    fi

    dialogUpdate "icon: ${footerCheckIcon},weight=semibold,colour=${footerStatusColor}"
    sleep $((anticipationDuration / 2))

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update Computer Inventory
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function updateComputerInventory() {

    if [[ "${operationMode}" == "Silent" ]] && [[ "${splunkOperationMode}" == "production" ]]; then
        notice "Skipping Jamf Pro inventory update: Operation Mode is ${operationMode} and Splunk Reporting is ${splunkOperationMode}"
        return 0
    else
        notice "Updating Computer Inventory …"
    fi

    dialogUpdate "icon: SF=pencil.and.list.clipboard,${organizationColorScheme}"
    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Updating …"
    dialogUpdate "progress: increment"
    dialogUpdate "progresstext: Updating Computer Inventory …"

    if [[ "${operationMode}" != "Test" ]]; then

        if [[ -n "${inventoryEndUsername}" ]]; then
            notice "Including '-endUsername' in 'jamf recon' (source: ${inventoryEndUsernameSource}; value: ${inventoryEndUsername})"
            if [[ "${suppressNonSplunkConsoleLogging}" == "true" ]]; then
                jamf recon -endUsername "${inventoryEndUsername}" >> "${scriptLog}" 2>&1
            else
                jamf recon -endUsername "${inventoryEndUsername}"
            fi
        else
            warning "NOT including '-endUsername' in 'jamf recon' since no SSO username is available for ${loggedInUser} (source: ${inventoryEndUsernameSource}; value: <empty>)"
            if [[ "${suppressNonSplunkConsoleLogging}" == "true" ]]; then
                jamf recon >> "${scriptLog}" 2>&1 # -verbose
            else
                jamf recon # -verbose
            fi
        fi

    else

        sleep "${anticipationDuration}"

    fi

    dialogUpdate "listitem: index: ${1}, icon: SF=$(printf "%02d" $(($1+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: Latest computer inventory submitted at $( date '+%A, %B %d at %I:%M %p %Z' ), status: success, statustext: Updated"

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
        {"title" : "AirDrop", "subtitle" : "Ensure AirDrop is not set to Everyone for security", "icon" : "SF=17.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5},
        {"title" : "Wi-Fi Strength", "subtitle" : "Checks current Wi-Fi signal strength and gives a simple quality rating.", "icon" : "SF=31.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}
    ]
    '
    # Validate developmentListitemJSON is valid JSON
    if ! validateJson "${developmentListitemJSON}"; then
        echo "Error: developmentListitemJSON is invalid JSON"
        echo "$developmentListitemJSON"
        exit 1
    else
        combinedJSON=$( mergeDialogAndListItems "${mainDialogJSON}" "${developmentListitemJSON}" )
    fi

else

    notice "Operation Mode is ${operationMode}; using MDM-specific dialogJSONFile."

    case ${mdmVendor} in

        "Addigy"            ) combinedJSON=$( mergeDialogAndListItems "${mainDialogJSON}" "${addigyMdmListitemJSON}" ) ;;
        "Filewave"          ) combinedJSON=$( mergeDialogAndListItems "${mainDialogJSON}" "${filewaveMdmListitemJSON}" ) ;;
        "Fleet"             ) combinedJSON=$( mergeDialogAndListItems "${mainDialogJSON}" "${fleetMdmListitemJSON}" ) ;;
        "Jamf Pro"          ) combinedJSON=$( mergeDialogAndListItems "${mainDialogJSON}" "${jamfProListitemJSON}" ) ;;
        "JumpCloud"         ) combinedJSON=$( mergeDialogAndListItems "${mainDialogJSON}" "${jumpcloudMdmListitemJSON}" ) ;;
        "Kandji"            ) combinedJSON=$( mergeDialogAndListItems "${mainDialogJSON}" "${kandjiMdmListitemJSON}" ) ;;
        "Microsoft Intune"  ) combinedJSON=$( mergeDialogAndListItems "${mainDialogJSON}" "${microsoftMdmListitemJSON}" ) ;;
        "Mosyle"            ) combinedJSON=$( mergeDialogAndListItems "${mainDialogJSON}" "${mosyleListitemJSON}" ) ;;
        *                   ) warning "Unknown MDM vendor: ${mdmVendor}" ; combinedJSON=$( mergeDialogAndListItems "${mainDialogJSON}" "${genericMdmListitemJSON}" ) ;;

    esac

fi

if ! validateJson "${combinedJSON}"; then
    fatal "combinedJSON is invalid; exiting."
fi

# Runtime check counters for dock badge updates
listitemLength=$(get_json_value "${combinedJSON}" "listitem.length")
if [[ "${listitemLength}" != <-> ]]; then
    listitemLength="0"
fi
remainingChecks="${listitemLength}"
completedCheckIndicesCsv=","
initializeCheckMetadataFromCombinedJSON

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

    dialogLaunchArgs=()
    dialogLaunchSucceeded="false"
    namedDialogPID=""

    if [[ "${enableDockIntegration:l}" == "true" ]]; then
        dialogDockIcon=$(resolveDockIcon "${dockIcon}")
        dialogLaunchBinary=$(prepareDockNamedDialogApp)
        dialogLaunchArgs=( "${dialogBinaryDebugArgs[@]}" --jsonfile "${dialogJSONFile}" --showdockicon --dockicon "${dialogDockIcon}" )
        if (( remainingChecks > 0 )); then
            dialogLaunchArgs+=( --dockiconbadge "${remainingChecks}" )
        fi
        info "Dock icon source: ${dialogDockIcon}"
    else
        dialogLaunchBinary="${dialogBinary}"
        dialogLaunchArgs=( "${dialogBinaryDebugArgs[@]}" --jsonfile "${dialogJSONFile}" )
        info "Dock integration disabled by configuration."
    fi

    info "Launching dialog binary: ${dialogLaunchBinary}"

    "${dialogLaunchBinary}" "${dialogLaunchArgs[@]}" &
    dialogPID=$!
    sleep 0.8

    if kill -0 "${dialogPID}" 2>/dev/null; then
        dialogLaunchSucceeded="true"
    else
        if [[ "${dialogLaunchBinary}" != "${dialogBinary}" ]]; then
            namedDialogPID=$(pgrep -f "${dialogDockNamedApp}/Contents/MacOS/" 2>/dev/null | head -n 1)
            if [[ -n "${namedDialogPID}" ]]; then
                dialogPID="${namedDialogPID}"
                dialogLaunchSucceeded="true"
            fi
        fi
    fi

    if [[ "${dialogLaunchSucceeded}" != "true" ]]; then
        if [[ "${dialogLaunchBinary}" != "${dialogBinary}" ]]; then
            notice "WARNING: Dock-enabled launch exited early; falling back to ${dialogBinary}."
        else
            notice "WARNING: Dialog launch exited early; retrying ${dialogBinary}."
        fi
        "${dialogBinary}" "${dialogLaunchArgs[@]}" &
        dialogPID=$!
    fi

    info "Dialog PID: ${dialogPID}"
    dialogUpdate "progresstext: Initializing …"

    # Band-Aid for macOS 15+ `withAnimation` SwiftUI bug
    dialogUpdate "list: hide"
    dialogUpdate "list: show"
    if (( remainingChecks > 0 )); then
        writeDockBadge "${remainingChecks}"
    fi

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
    # set -x
    checkAirDropSettings "0"
    checkWiFiStrength "1"
    # set +x

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
                checkUserDirectorySizeItems "13" "Downloads" "folder.fill.badge.plus" "Downloads"
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
                checkHomebrewStatus "28"
                checkElectronCornerMask "29"
                checkWiFiStrength "30"
                checkNetworkQuality "31"
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
                checkUserDirectorySizeItems "13" "Downloads" "folder.fill.badge.plus" "Downloads"
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
                checkHomebrewStatus "27"
                checkElectronCornerMask "28"
                checkWiFiStrength "29"
                checkNetworkQuality "30"
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
                checkUserDirectorySizeItems "13" "Downloads" "folder.fill.badge.plus" "Downloads"
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
                checkHomebrewStatus "28"
                checkElectronCornerMask "29"
                checkWiFiStrength "30"
                checkNetworkQuality "31"
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
                checkAirDropSettings "8"
                checkAirPlayReceiver "9"
                checkBluetoothSharing "10"
                checkVPN "11"
                checkUptime "12"
                checkFreeDiskSpace "13"
                checkUserDirectorySizeItems "14" "Desktop" "desktopcomputer.and.macbook" "Desktop"
                checkUserDirectorySizeItems "15" "Downloads" "folder.fill.badge.plus" "Downloads"
                checkUserDirectorySizeItems "16" ".Trash" "trash.fill" "Trash"
                checkMdmProfile "17"
                checkMdmCertificateExpiration "18"
                checkAPNs "19"
                checkJamfProCheckIn "20"
                checkJamfProInventory "21"
                checkNetworkHosts  "22" "Apple Push Notification Hosts"         "${pushHosts[@]}"
                checkNetworkHosts  "23" "Apple Device Management"               "${deviceMgmtHosts[@]}"
                checkNetworkHosts  "24" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
                checkNetworkHosts  "25" "Apple Certificate Validation"          "${certHosts[@]}"
                checkNetworkHosts  "26" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
                checkNetworkHosts  "27" "Jamf Hosts"                            "${jamfHosts[@]}"
                checkAppAutoPatch "28"
                checkHomebrewStatus "29"
                checkElectronCornerMask "30"
                checkInternal "31" "/Applications/Microsoft Teams.app" "/Applications/Microsoft Teams.app" "Microsoft Teams"
                checkExternalJamfPro "32" "symvBeyondTrustPMfM"        "/Applications/PrivilegeManagement.app"
                checkExternalJamfPro "33" "symvCiscoUmbrella"          "/Applications/Cisco/Cisco Secure Client.app"
                checkExternalJamfPro "34" "symvCrowdStrikeFalcon"      "/Applications/Falcon.app"
                checkExternalJamfPro "35" "symvGlobalProtect"          "/Applications/GlobalProtect.app"
                checkWiFiStrength "36"
                checkNetworkQuality "37"
                updateComputerInventory "38"
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
                checkUserDirectorySizeItems "13" "Downloads" "folder.fill.badge.plus" "Downloads"
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
                checkHomebrewStatus "28"
                checkElectronCornerMask "29"
                checkWiFiStrength "30"
                checkNetworkQuality "31"
                ;;

            "Kandji" )
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
                checkBluetoothSharing "14"
                checkMdmCertificateExpiration "15"
                checkAPNs "16"
                checkNetworkHosts "17" "Apple Push Notification Hosts"         "${pushHosts[@]}"
                checkNetworkHosts "18" "Apple Device Management"               "${deviceMgmtHosts[@]}"
                checkNetworkHosts "19" "Apple Software and Carrier Updates"    "${updateHosts[@]}"
                checkNetworkHosts "20" "Apple Certificate Validation"          "${certHosts[@]}"
                checkNetworkHosts "21" "Apple Identity and Content Services"   "${idAssocHosts[@]}"
                checkInternal "22" "/Applications/Microsoft Teams.app" "/Applications/Microsoft Teams.app" "Microsoft Teams"
				checkInternal "23" "/Applications/OneDrive.app" "/Applications/OneDrive.app" "Microsoft OneDrive"
				checkInternal "24" "/Applications/Microsoft Outlook.app" "/Applications/Microsoft Outlook.app" "Microsoft Outlook"
				checkInternal "25" "/Applications/Company Portal.app" "/Applications/Company Portal.app" "Company Portal"
				checkInternal "26" "/Applications/zoom.us.app" "/Applications/zoom.us.app" "Zoom"
				checkInternal "27" "/Applications/Cortex XDR.app" "/Applications/Cortex XDR.app" "Cortex"				
				checkInternal "28" "/Applications/Netskope Client.app" "/Applications/Netskope Client.app" "Netskope"				
                checkWiFiStrength "29"
                checkNetworkQuality "30"
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
                checkUserDirectorySizeItems "13" "Downloads" "folder.fill.badge.plus" "Downloads"
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
                checkHomebrewStatus "28"
                checkElectronCornerMask "29"
                checkWiFiStrength "30"
                checkNetworkQuality "31"
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
                checkUserDirectorySizeItems "13" "Downloads" "folder.fill.badge.plus" "Downloads"
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
                checkHomebrewStatus "29"
                checkElectronCornerMask "30"
                checkWiFiStrength "31"
                checkNetworkQuality "32"
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
                checkUserDirectorySizeItems "12" "Downloads" "folder.fill.badge.plus" "Downloads"
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
                checkHomebrewStatus "24"
                checkElectronCornerMask "25"
                checkWiFiStrength "26"
                checkNetworkQuality "27"
                ;;
        
        esac

        dialogUpdate "icon: ${icon}"
        dialogUpdate "progresstext: Final Analysis …"

        sleep "${anticipationDuration}"

    else

        # Operation Mode: Test
        dialogUpdate "title: ${humanReadableScriptName} (${scriptVersion})<br>Operation Mode: ${operationMode}"

        for (( i=0; i<listitemLength; i++ )); do
            notice "[Operation Mode: ${operationMode}] Check ${i} …"
            dialogUpdate "icon: SF=$(printf "%02d" $(($i+1))).square,${organizationColorScheme}"
            dialogUpdate "listitem: index: ${i}, icon: SF=$(printf "%02d" $(($i+1))).circle.fill $(echo "${organizationColorScheme}" | tr ',' ' '), iconalpha: 1, status: wait, statustext: Checking …"
            dialogUpdate "progress: increment"
            dialogUpdate "progresstext: [Operation Mode: ${operationMode}] • Item No. ${i} …"
            # sleep "${anticipationDuration}"
            dialogUpdate "listitem: index: ${i}, icon: SF=$(printf "%02d" $(($i+1))).circle.fill weight=semibold colour=${statusColorSuccess}, iconalpha: 0.9, subtitle: ${organizationBoilerplateComplianceMessage}, status: success, statustext: ${operationMode}"
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
