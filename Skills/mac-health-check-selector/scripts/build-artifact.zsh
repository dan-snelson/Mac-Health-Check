#!/bin/zsh --no-rcs
# shellcheck shell=bash

####################################################################################################
#
# Mac Health Check Selector: Build Artifact
#
# Builds and validates an MDM-specific, date-stamped copy of Mac-Health-Check.zsh in Artifacts/ for
# the mac-health-check-selector skill. The source script is read, never modified.
#
# Usage:
#   zsh build-artifact.zsh --list <slug> [--source <path>]
#   zsh build-artifact.zsh --slug <slug> --selection <file|-> [--prune-other-mdms] [--source <path>] [--out-dir <dir>]
#
# Slugs: jamf-pro, fleet, jumpcloud, microsoft-intune, mosyle, kandji, addigy, filewave, generic
#
# Selection: one check per line, in final order; blank lines and # comments are ignored. Pass
# `--selection -` to read it from stdin (a here-doc), so no temporary file is left behind.
#   <ID>|<raw title>                      C1|macOS Version
#                                         M1|'${mdmVendor}' MDM Profile
#   <ID>|custom|<row fragment>|<call>     A4|custom|{"title" : "Zoom", "subtitle" : "…", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}|checkInternal "/Applications/zoom.us.app" "/Applications/zoom.us.app" "Zoom"
#
# Raw titles are looked up in the source script: the chosen MDM's array first, then Jamf Pro, then
# the remaining MDMs. Each row is paired with the call at the same index in that MDM's branch. Each
# non-custom <ID> must match the check-ID map below (kept in sync with references/health-checks.md).
#
# --prune-other-mdms removes every other named MDM's list-item array, its branches in each vendor
# `case` block (including `serverURL` detection), and vendor-owned functions or data the selection no
# longer calls; the generic `* )` fallback always stays.
#
# Exit codes:
#   0  every validation check passed; artifact and complete sidecar .md written to --out-dir
#   1  a validation check failed; nothing written to --out-dir (failed build kept in the work directory)
#   2  usage or build error; nothing written
#
####################################################################################################
#
# HISTORY
#
# Version 5.0.0b6 30-Sep-2026, Dan K. Snelson (@dan-snelson)
# - Original version: tested renumbering, explicit PASS / FAIL validation, non-zero exit on failure
# - Added MDM display names, vendor-neutral Clock Skew subtitle outside Jamf Pro, borrowed-row notices,
#   `--selection -` (stdin), and a complete sidecar with Disabled reasons and tagged dependency notes
#
# Version 5.0.0b8 02-Oct-2026, Dan K. Snelson (@dan-snelson)
# - Added optional `--prune-other-mdms`, which removes other MDMs' arrays, `case` branches, detection,
#   and unreferenced vendor-owned symbols (keeping the generic fallback), with validation checks 4b and 4c
#
####################################################################################################



####################################################################################################
#
# Global Variables
#
####################################################################################################

setopt extendedglob pipefail

helperVersion="5.0.0b8"
healthCheckHeader="# Generate Health Checks based on Operation Mode and MDM Vendor"
placeholderNetwork="<YOUR_ORGANIZATION_NETWORK>"
inventoryTitle="Computer Inventory"
networkQualityTitle="Network Quality Test"

# Client-Side Cache sanitizer expressions; must match installClientSideScript in the source
operationModeSedExpression='s|operationMode="${4:-"Self Service"}"|operationMode="${4:-"Silent"}"|'
networkQualitySedExpression='/"title" : "Network Quality Test"/ s/},$/}/'
memoryPressureKeyLine='[[ "${title}" == "Memory Pressure" ]] && checkKeyByIndex[${i}]="memoryPressure"'

typeset -A slugVendor slugArray slugLabel
slugVendor=(
    jamf-pro            "Jamf Pro"
    fleet               "Fleet"
    jumpcloud           "JumpCloud"
    microsoft-intune    "Microsoft Intune"
    mosyle              "Mosyle"
    kandji              "Kandji"
    addigy              "Addigy"
    filewave            "Filewave"
    generic             "None"
)
slugArray=(
    jamf-pro            "jamfProListitemJSON"
    fleet               "fleetMdmListitemJSON"
    jumpcloud           "jumpcloudMdmListitemJSON"
    microsoft-intune    "microsoftMdmListitemJSON"
    mosyle              "mosyleListitemJSON"
    kandji              "kandjiMdmListitemJSON"
    addigy              "addigyMdmListitemJSON"
    filewave            "filewaveMdmListitemJSON"
    generic             "genericMdmListitemJSON"
)
slugLabel=(
    jamf-pro            '"Jamf Pro" )'
    fleet               '"Fleet" )'
    jumpcloud           '"JumpCloud" )'
    microsoft-intune    '"Microsoft Intune" )'
    mosyle              '"Mosyle" )'
    kandji              '"Kandji" )'
    addigy              '"Addigy" )'
    filewave            '"Filewave" )'
    generic             '* )'
)
slugOrder=( jamf-pro fleet jumpcloud microsoft-intune mosyle kandji addigy filewave generic )

typeset -A slugDisplay
slugDisplay=(
    jamf-pro            "Jamf Pro"
    fleet               "Fleet"
    jumpcloud           "JumpCloud"
    microsoft-intune    "Microsoft Intune"
    mosyle              "Mosyle"
    kandji              "Kandji / Iru"
    addigy              "Addigy"
    filewave            "Filewave"
    generic             "Other / MDM-agnostic"
)

# `serverURL` detection patterns (the `case "${serverURL}" in` labels), used by --prune-other-mdms
typeset -A slugDetect
slugDetect=(
    jamf-pro            "*jamf* | *jss*"
    fleet               "*fleet*"
    jumpcloud           "*jumpcloud*"
    microsoft-intune    "*microsoft*"
    mosyle              "*mosyle*"
    kandji              "*kandji*"
    addigy              "*addigy*"
    filewave            "*filewave*"
)

# Vendor-owned symbols: name|owning slug|kind (function or array); pruned only when no reference remains
vendorSymbols=(
    "checkJamfProCheckIn|jamf-pro|function"
    "checkJamfProInventory|jamf-pro|function"
    "checkExternalJamfPro|jamf-pro|function"
    "updateComputerInventory|jamf-pro|function"
    "jamfHosts|jamf-pro|array"
    "checkMosyleCheckIn|mosyle|function"
)

# Vendor-neutral subtitles for shipped rows that name Jamf Pro; applied when the chosen MDM is not Jamf Pro
typeset -A neutralSubtitle
neutralSubtitle=(
    "Clock Skew"        "Checks local clock offset against time.apple.com"
)

# Check IDs by raw source title, in master-table order (keep in sync with references/health-checks.md)
typeset -A titleId
typeset -a mapTitles
while IFS='|' read -r mapId mapTitle; do
    titleId[${mapTitle}]="${mapId}"
    mapTitles+=( "${mapTitle}" )
done <<'ENDOFIDMAP'
C1|macOS Version
C2|Available Updates
C3|System Integrity Protection
C4|Signed System Volume
C5|Firewall
C6|FileVault Encryption
C7|Gatekeeper / XProtect
C8|Touch ID
C9|Password Hint
C10|AirDrop
C11|AirPlay Receiver
C12|Bluetooth Sharing
C13|VPN Client
H1|Last Reboot
H2|Free Disk Space
H3|Desktop Size and Item Count
H4|Downloads Size and Item Count
H5|Trash Size and Item Count
H6|Memory Pressure
H7|Clock Skew
M1|'${mdmVendor}' MDM Profile
M2|Entra ID Registration
M3|'${mdmVendor}' MDM Certificate Expiration
M4|Apple Push Notification service
M5|Jamf Pro Check-In
M6|Jamf Pro Inventory
M7|Mosyle Check-In
M8|Apple Push Notification Hosts
M9|Apple Device Management
M10|Apple Software and Carrier Updates
M11|Apple Certificate Validation
M12|Apple Identity and Content Services
M13|Jamf Hosts
M14|Wi-Fi Strength
M15|Network Quality Test
A1|App Auto-Patch
A2|Homebrew Status
A3|Electron Corner Mask
A4|Microsoft Teams
A5|Fleet Desktop
A5|Microsoft Company Portal
A5|'${mdmVendor}' Self-Service
A5a|Microsoft One Drive
A5b|Microsoft Outlook
A5c|Company Portal
A5d|Zoom
A5e|Cortex
A5f|Netskope
A6|BeyondTrust Privilege Management
A7|Cisco Umbrella
A8|CrowdStrike Falcon
A9|Palo Alto GlobalProtect
F1|Computer Inventory
ENDOFIDMAP

# Restricted availability: owning slug, or "vendor" (needs a known MDM vendor)
typeset -A idOwner
idOwner=(
    M1 vendor   M3 vendor
    M5 jamf-pro M6 jamf-pro M13 jamf-pro
    A6 jamf-pro A7 jamf-pro A8 jamf-pro A9 jamf-pro F1 jamf-pro
    M7 mosyle
)

listSlug=""
slug=""
selectionFile=""
sourceScript=""
outDir=""
pruneOtherMdms="false"
failCount=0
typeset -a validationNumbers validationNames validationResults



####################################################################################################
#
# Functions
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Output
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function printUsage() {
    print -r -- "Usage:"
    print -r -- "  zsh build-artifact.zsh --list <slug> [--source <path>]"
    print -r -- "  zsh build-artifact.zsh --slug <slug> --selection <file|-> [--prune-other-mdms] [--source <path>] [--out-dir <dir>]"
    print -r -- "Slugs: ${slugOrder[*]}"
}

function buildError() {
    print -u2 -r -- "ERROR: ${1}"
    [[ -n "${workDirectory}" && -d "${workDirectory}" ]] && rm -rf "${workDirectory}"
    exit 2
}

function recordCheck() {
    # recordCheck <number> <name> <PASS|FAIL|SKIP|INFO> <detail>
    local checkNumber="${1}"
    local checkName="${2}"
    local checkStatus="${3}"
    local checkDetail="${4}"

    print -r -- "${checkStatus} ${checkNumber} ${checkName}${checkDetail:+ — ${checkDetail}}"
    [[ "${checkStatus}" == "FAIL" ]] && (( failCount++ ))
    validationNumbers+=( "${checkNumber}" )
    validationNames+=( "${checkName}" )
    validationResults+=( "${checkStatus}${checkDetail:+ (${checkDetail})}" )
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Region parsing
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function loadMdmRegion() {
    # loadMdmRegion <file> <slug>
    # Sets: regionAStart regionAEnd regionFirstRow regionLastRow regionBStart regionBEnd
    #       regionRows regionTitles regionCallIndexes regionCalls regionError
    local file="${1}"
    local regionSlug="${2}"
    local arrayName="${slugArray[${regionSlug}]}"
    local branchLabel="${slugLabel[${regionSlug}]}"
    local headerLine="" caseLine="" esacLine="" lineText="" lineNumber=0 callLine=""
    local -a arrayLines branchLines

    regionAStart="" regionAEnd="" regionFirstRow="" regionLastRow="" regionBStart="" regionBEnd="" regionError=""
    regionRows=() regionTitles=() regionCallIndexes=() regionCalls=()

    regionAStart=$( awk -v a="${arrayName}='" '$0 == a { print NR; exit }' "${file}" )
    [[ -n "${regionAStart}" ]] || { regionError="array start '${arrayName}=' not found"; return 1; }
    regionAEnd=$( awk -v s="${regionAStart}" -v q="'" 'NR > s && $0 == q { print NR; exit }' "${file}" )
    [[ -n "${regionAEnd}" ]] || { regionError="array end for ${arrayName} not found"; return 1; }

    headerLine=$( awk -v h="${healthCheckHeader}" 'index($0, h) == 1 { print NR; exit }' "${file}" )
    [[ -n "${headerLine}" ]] || { regionError="health-check header not found"; return 1; }
    caseLine=$( awk -v h="${headerLine}" 'NR > h && $0 == "        case ${mdmVendor} in" { print NR; exit }' "${file}" )
    [[ -n "${caseLine}" ]] || { regionError="health-check case block not found"; return 1; }
    esacLine=$( awk -v c="${caseLine}" 'NR > c && $0 == "        esac" { print NR; exit }' "${file}" )
    regionBStart=$( awk -v c="${caseLine}" -v l="            ${branchLabel}" 'NR > c && $0 == l { print NR; exit }' "${file}" )
    [[ -n "${regionBStart}" ]] || { regionError="branch label ${branchLabel} not found"; return 1; }
    regionBEnd=$( awk -v s="${regionBStart}" 'NR > s && $0 == "                ;;" { print NR; exit }' "${file}" )
    [[ -n "${regionBEnd}" ]] || { regionError="branch end for ${branchLabel} not found"; return 1; }
    if [[ -z "${esacLine}" ]] || (( regionBEnd > esacLine )) || (( regionAEnd >= regionBStart )); then
        regionError="anchors out of order (A ${regionAStart}-${regionAEnd}, B ${regionBStart}-${regionBEnd}, esac ${esacLine})"
        return 1
    fi

    arrayLines=( "${(@f)$( sed -n "${regionAStart},${regionAEnd}p" "${file}" )}" )
    lineNumber=$(( regionAStart - 1 ))
    for lineText in "${arrayLines[@]}"; do
        (( lineNumber++ ))
        if [[ "${lineText}" == [[:space:]]#'{"title"'* ]]; then
            if [[ -n "${regionLastRow}" ]] && (( lineNumber != regionLastRow + 1 )); then
                regionError="non-row line inside ${arrayName} before line ${lineNumber}"
                return 1
            fi
            [[ -z "${regionFirstRow}" ]] && regionFirstRow="${lineNumber}"
            regionLastRow="${lineNumber}"
            regionRows+=( "$( normalizeRow "${lineText}" )" )
            if [[ "${lineText}" =~ '"title" *: *"([^"]*)"' ]]; then
                regionTitles+=( "${match[1]}" )
            else
                regionError="row without title at line ${lineNumber}"
                return 1
            fi
        fi
    done
    (( ${#regionRows} > 0 )) || { regionError="no rows in ${arrayName}"; return 1; }

    if (( regionBEnd - regionBStart > 1 )); then
        branchLines=( "${(@f)$( sed -n "$(( regionBStart + 1 )),$(( regionBEnd - 1 ))p" "${file}" )}" )
    fi
    for callLine in "${branchLines[@]}"; do
        if [[ "${callLine}" =~ '^ +runConfiguredHealthCheck "([0-9]*)" (.+)$' ]]; then
            regionCallIndexes+=( "${match[1]}" )
            regionCalls+=( "${match[2]}" )
        else
            regionError="unexpected line in ${branchLabel} branch: ${callLine}"
            return 1
        fi
    done

    return 0
}

function normalizeRow() {
    # Strip trailing whitespace and the trailing comma; commas are re-added when rows are joined
    local rowText="${1}"
    rowText="${rowText%%[[:space:]]#}"
    rowText="${rowText%,}"
    print -r -- "${rowText}"
}

function renumberRow() {
    # renumberRow <row> <zero-based index>
    local rowText="${1}"
    local iconNumber=""
    printf -v iconNumber '%02d' $(( ${2} + 1 ))
    print -r -- "${rowText/SF=(<->|NN).circle/SF=${iconNumber}.circle}"
}

function resolveTitle() {
    # resolveTitle <raw title> [vendor]; expands '${mdmVendor}' (defaults to the chosen MDM's vendor)
    local rawTitle="${1}"
    local titleVendor="${2:-${mdmVendor}}"
    print -r -- "${rawTitle//\'\$\{mdmVendor\}\'/${titleVendor}}"
}

function evaluateArrayJson() {
    # evaluateArrayJson <file> <start> <end>
    sed -n "${2},${3}p" "${1}" > "${workDirectory}/array.zsh"
    organizationColorScheme="weight=semibold,colour=#000000" mdmVendor="${mdmVendor}" \
        zsh --no-rcs -c 'source "$1"; print -r -- "${(P)2}"' _ "${workDirectory}/array.zsh" "${arrayName}" 2>/dev/null
}

function loadSanitizeCheckKey() {
    local functionText=""
    functionText=$( awk '/^function sanitizeCheckKey\(\) \{$/ { f = 1 } f { print } f && /^}$/ { exit }' "${sourceScript}" )
    [[ -n "${functionText}" ]] || return 1
    eval "${functionText}"
    grep -qF -- "${memoryPressureKeyLine}" "${sourceScript}" && memoryPressureSpecialCase="true"
    return 0
}

function reportKeyForTitle() {
    local resolvedTitle="${1}"
    if [[ "${memoryPressureSpecialCase}" == "true" && "${resolvedTitle}" == "Memory Pressure" ]]; then
        print -r -- "memoryPressure"
    else
        sanitizeCheckKey "${resolvedTitle}"
    fi
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pruning (--prune-other-mdms)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function writeLabelFile() {
    # writeLabelFile <file> <pruned slug> …; tab-separated known / prune labels for findCaseBranchRanges
    local labelFile="${1}"
    shift
    local labelSlug=""
    {
        for labelSlug in ${slugOrder:#generic}; do
            print -r -- "known"$'\t'"vendor"$'\t'"\"${slugVendor[${labelSlug}]}\""
            print -r -- "known"$'\t'"detect"$'\t'"${slugDetect[${labelSlug}]}"
        done
        print -r -- "known"$'\t'"vendor"$'\t'"*"
        print -r -- "known"$'\t'"detect"$'\t'"*"
        for labelSlug in "$@"; do
            print -r -- "prune"$'\t'"vendor"$'\t'"\"${slugVendor[${labelSlug}]}\""
            print -r -- "prune"$'\t'"detect"$'\t'"${slugDetect[${labelSlug}]}"
        done
    } > "${labelFile}"
}

function findCaseBranchRanges() {
    # findCaseBranchRanges <file> <label file>
    # Prints one tab-separated line per pruned range: branch|block <case line> <start> <end> <label>
    # A block whose every branch is pruned is printed once as "block"; exits 3 on anchor drift
    awk '
        function trimRight(s) { sub(/[[:space:]]+$/, "", s); return s }
        function isBlank(n) { return (n >= 1 && n <= total && line[n] ~ /^[[:space:]]*$/) }
        function pad(n,   s) { s = ""; while (n-- > 0) s = s " "; return s }
        function isLabel(t) { return (substr(t, 1, indent + 4) == labelPrefix && substr(t, indent + 5, 1) != " " && t != "") }
        function fail(message) { print "ERROR\t" message; failed = 1; exit 3 }
        FNR == NR { split($0, p, "\t"); if (p[1] == "prune") prune[p[2] SUBSEP p[3]] = 1; else known[p[2] SUBSEP p[3]] = 1; next }
        { line[++total] = $0 }
        END {
            if (failed) exit 3
            for (n = 1; n <= total; n++) {
                kind = ""
                if (line[n] ~ /^ *case "?\$\{mdmVendor\}"? in$/) kind = "vendor"
                else if (line[n] == "case \"${serverURL}\" in") kind = "detect"
                if (kind == "") continue
                match(line[n], /^ */); indent = RLENGTH
                labelPrefix = pad(indent + 4); endText = pad(indent + 8) ";;"; esacText = pad(indent) "esac"
                branchCount = 0; prunedCount = 0; esacAt = 0; m = n + 1
                while (m <= total) {
                    text = trimRight(line[m])
                    if (text == esacText) { esacAt = m; break }
                    if (isLabel(text)) {
                        label = substr(text, indent + 5)
                        if (label !~ /\)/) fail("line " m ": branch label without )")
                        sub(/[[:space:]]*\).*$/, "", label)
                        if (!((kind SUBSEP label) in known)) fail("line " m ": unknown " kind " label " label)
                        finish = 0
                        if (text ~ /;;$/) {
                            finish = m
                        } else {
                            for (k = m + 1; k <= total; k++) {
                                t2 = trimRight(line[k])
                                if (t2 == endText) { finish = k; break }
                                if (t2 == esacText || isLabel(t2)) break
                            }
                        }
                        if (!finish) fail("line " m ": branch " label " has no ;;")
                        branchCount++
                        if ((kind SUBSEP label) in prune) { prunedCount++; ps[prunedCount] = m; pe[prunedCount] = finish; pl[prunedCount] = label }
                        m = finish + 1
                        continue
                    }
                    if (text != "" && substr(text, 1, indent + 5) != pad(indent + 5)) fail("line " m ": unexpected line between branches")
                    m++
                }
                if (!esacAt) fail("line " n ": case block has no esac")
                if (prunedCount > 0 && prunedCount == branchCount) {
                    s = n; e = esacAt
                    # A block that is its section'\''s only content takes the section header with it
                    h = s - 1; while (isBlank(h)) h--
                    f = e + 1; while (isBlank(f)) f++
                    if (h > 3 && h < s - 1 && line[h] ~ /^# # #/ && line[h - 1] ~ /^# / && line[h - 1] !~ /^# # #/ && line[h - 2] ~ /^# # #/ && isBlank(h - 3) && f <= total && line[f] ~ /^(# # #|####)/) {
                        s = h - 2; e = f - 1
                    } else if (isBlank(s - 1) && isBlank(e + 1)) e++
                    print "block\t" n "\t" s "\t" e "\t" kind
                } else {
                    for (i = 1; i <= prunedCount; i++) {
                        s = ps[i]; e = pe[i]
                        if (isBlank(s - 1) && isBlank(e + 1)) e++
                        print "branch\t" n "\t" s "\t" e "\t" pl[i]
                    }
                }
                n = esacAt
            }
        }' "${2}" "${1}"
}

function caseError() {
    # caseError <findCaseBranchRanges output>; prints its ERROR message
    local errorMessage=""
    errorMessage=$( print -r -- "${1}" | awk -F '\t' '$1 == "ERROR" { print $2; exit }' )
    print -r -- "${errorMessage:-vendor case blocks do not parse}"
}

function findArraySectionRange() {
    # findArraySectionRange <file> <array name>; prints "<start> <end>" (section header through validation fi)
    awk -v name="${2}" '
        { line[++total] = $0 }
        END {
            for (n = 1; n <= total; n++) if (line[n] == name "='\''") { a = n; break }
            if (!a) exit 3
            h = a - 1; while (h > 0 && line[h] ~ /^[[:space:]]*$/) h--
            if (h < 3 || line[h] !~ /^# # #/ || line[h - 1] !~ /^# .*List Items/ || line[h - 2] !~ /^# # #/) exit 3
            for (q = a + 1; q <= total && line[q] != "'\''"; q++) ;
            if (q > total) exit 3
            v = q + 1; while (v <= total && line[v] ~ /^[[:space:]]*$/) v++
            if (line[v] != "# Validate " name " is valid JSON") exit 3
            for (f = v + 1; f <= total && f <= v + 8 && line[f] != "fi"; f++) ;
            if (line[f] != "fi") exit 3
            e = f; while (e + 1 <= total && line[e + 1] ~ /^[[:space:]]*$/) e++
            print (h - 2) " " e
        }' "${1}"
}

function findSymbolRange() {
    # findSymbolRange <file> <name> <function|array>; prints "<start> <end>"
    # function: section header triple through the closing "}" plus trailing blank lines
    # array: preceding comment lines through the closing ")"
    awk -v name="${2}" -v kind="${3}" '
        { line[++total] = $0 }
        END {
            opener = (kind == "function") ? "function " name "() {" : name "=("
            for (n = 1; n <= total; n++) if (line[n] == opener) { d = n; break }
            if (!d) exit 3
            closer = (kind == "function") ? "}" : ")"
            for (q = d + 1; q <= total && line[q] != closer; q++) ;
            if (q > total) exit 3
            if (kind == "function") {
                h = d - 1; while (h > 0 && line[h] ~ /^[[:space:]]*$/) h--
                if (h < 3 || line[h] !~ /^# # #/ || line[h - 1] !~ /^# / || line[h - 1] ~ /^# # #/ || line[h - 2] !~ /^# # #/) exit 3
                s = h - 2; e = q
                while (e + 1 <= total && line[e + 1] ~ /^[[:space:]]*$/) e++
            } else {
                s = d; while (s - 1 > 0 && line[s - 1] ~ /^# / && line[s - 1] !~ /^# # #/) s--
                e = q
                if (s > 1 && line[s - 1] ~ /^[[:space:]]*$/ && e < total && line[e + 1] ~ /^[[:space:]]*$/) e++
            }
            print s " " e
        }' "${1}"
}

function countReferences() {
    # countReferences <file> <name> [<skip start> <skip end>]
    # Counts non-comment lines naming <name>, outside installClientSideScript (its sanitizer patterns are not calls)
    awk -v name="${2}" -v ds="${3:-0}" -v de="${4:-0}" '
        /^function installClientSideScript\(\) \{$/ { inside = 1 }
        inside { if ($0 == "}") inside = 0; next }
        NR >= ds && NR <= de { next }
        /^[[:space:]]*#/ { next }
        $0 ~ ("(^|[^A-Za-z0-9_])" name "([^A-Za-z0-9_]|$)") { count++ }
        END { print count + 0 }' "${1}"
}

function printLinesOutside() {
    # printLinesOutside <file> <range> …; prints the lines of <file> outside every "<start> <end>" range
    local file="${1}"
    shift
    print -r -l -- "$@" | awk '
        FNR == NR { k++; split($0, r, " "); s[k] = r[1]; e[k] = r[2]; next }
        { for (i = 1; i <= k; i++) if (FNR >= s[i] && FNR <= e[i]) next; print }' - "${file}"
}

function sortRanges() {
    # sortRanges <range> …; prints "<start> <end>" sorted by start
    print -r -l -- "$@" | sort -n -k1,1 -k2,2
}

function assembleArtifact() {
    # assembleArtifact <output> <plan file>; plan lines "<start> <end> [replacement file]" in source coordinates
    awk '
        FNR == NR { k++; s[k] = $1; e[k] = $2; f[k] = $3; next }
        {
            for (i = 1; i <= k; i++) {
                if (FNR >= s[i] && FNR <= e[i]) {
                    if (FNR == s[i] && f[i] != "") { while ((getline replacementLine < f[i]) > 0) print replacementLine; close(f[i]) }
                    next
                }
            }
            print
        }' "${2}" "${sourceScript}" > "${1}"
}

function writeAssemblyPlan() {
    # writeAssemblyPlan <plan file> <prune range> …; adds Regions A and B; exits 2 on overlap
    local planFile="${1}"
    shift
    local planLine="" previousEnd=0 planStart="" planEnd=""
    local -a planLines
    planLines=( "${(@f)$( sortRanges "${sourceAStart} ${sourceAEnd} ${workDirectory}/regionA.txt" "${sourceBStart} ${sourceBEnd} ${workDirectory}/regionB.txt" "$@" )}" )
    for planLine in "${planLines[@]}"; do
        planStart="${${(s: :)planLine}[1]}"
        planEnd="${${(s: :)planLine}[2]}"
        (( planStart > previousEnd && planEnd >= planStart )) || buildError "prune ranges overlap near source line ${planStart}"
        previousEnd="${planEnd}"
    done
    print -r -l -- "${planLines[@]}" > "${planFile}"
}



####################################################################################################
#
# Program
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Arguments
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

while (( $# > 0 )); do
    case "${1}" in
        --list )        listSlug="${2}"; shift 2 ;;
        --slug )        slug="${2}"; shift 2 ;;
        --selection )   selectionFile="${2}"; shift 2 ;;
        --source )      sourceScript="${2}"; shift 2 ;;
        --out-dir )     outDir="${2}"; shift 2 ;;
        --prune-other-mdms ) pruneOtherMdms="true"; shift ;;
        -h | --help )   printUsage; exit 0 ;;
        * )             printUsage; exit 2 ;;
    esac
done

if [[ -z "${sourceScript}" ]]; then
    if [[ -f "Mac-Health-Check.zsh" ]]; then
        sourceScript="Mac-Health-Check.zsh"
    else
        sourceScript="${0:A:h}/../../../Mac-Health-Check.zsh"
    fi
fi
[[ -r "${sourceScript}" ]] || buildError "source script not readable: ${sourceScript}"
sourceScript="${sourceScript:A}"
sourceDirectory="${sourceScript:h}"
command -v jq >/dev/null 2>&1 || buildError "jq is required"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# --list: print the shipped rows and calls for one MDM
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ -n "${listSlug}" ]]; then
    [[ -n "${slugArray[${listSlug}]}" ]] || { printUsage; exit 2; }
    loadMdmRegion "${sourceScript}" "${listSlug}" || buildError "${regionError}"
    (( ${#regionRows} == ${#regionCalls} )) || buildError "${listSlug}: ${#regionRows} rows but ${#regionCalls} calls"
    print -r -- "# ${slugDisplay[${listSlug}]} (${slugArray[${listSlug}]}; ${slugLabel[${listSlug}]}): ${#regionRows} checks; Region A ${regionAStart}-${regionAEnd}; Region B ${regionBStart}-${regionBEnd}"
    for (( i = 1; i <= ${#regionRows}; i++ )); do
        print -r -- "$(( i - 1 ))|${regionTitles[${i}]}|${regionCalls[${i}]}"
    done
    exit 0
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Build: inputs
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

[[ -n "${slug}" && -n "${slugArray[${slug}]}" ]] || { printUsage; exit 2; }
if [[ "${selectionFile}" == "-" ]]; then
    selectionInput="/dev/stdin"
else
    [[ -r "${selectionFile}" ]] || buildError "selection file not readable: ${selectionFile}"
    selectionInput="${selectionFile}"
fi
[[ -z "${outDir}" ]] && outDir="${sourceDirectory}/Artifacts"
outDir="${outDir:A}"

mdmVendor="${slugVendor[${slug}]}"
mdmDisplay="${slugDisplay[${slug}]}"
arrayName="${slugArray[${slug}]}"
branchLabel="${slugLabel[${slug}]}"
workDirectory=$( mktemp -d "${TMPDIR:-/tmp}/mhc-selector.XXXXXX" ) || buildError "unable to create work directory"
sourceHashBefore=$( shasum -a 256 "${sourceScript}" | awk '{ print $1 }' )

# Title → row / call map across every MDM region; chosen MDM first, then Jamf Pro, then the rest
typeset -A rowByTitle callByTitle sourceSlugByTitle slugsByTitle
lookupOrder=( "${slug}" ${slugOrder:#${slug}} )
for lookupSlug in "${lookupOrder[@]}"; do
    loadMdmRegion "${sourceScript}" "${lookupSlug}" || buildError "${lookupSlug}: ${regionError}"
    (( ${#regionRows} == ${#regionCalls} )) || buildError "${lookupSlug}: ${#regionRows} rows but ${#regionCalls} calls in source"
    for (( i = 1; i <= ${#regionRows}; i++ )); do
        slugsByTitle[${regionTitles[${i}]}]+=" ${lookupSlug}"
        (( ${+rowByTitle[${regionTitles[${i}]}]} )) && continue
        rowByTitle[${regionTitles[${i}]}]="${regionRows[${i}]}"
        callByTitle[${regionTitles[${i}]}]="${regionCalls[${i}]}"
        sourceSlugByTitle[${regionTitles[${i}]}]="${lookupSlug}"
    done
done
for sourceTitle in "${(@k)slugsByTitle}"; do
    (( ${+titleId[${sourceTitle}]} )) || buildError "no check ID for source title \"${sourceTitle}\"; add it to the ID map in build-artifact.zsh and to references/health-checks.md"
done

# Chosen MDM anchors and shipped titles (source)
loadMdmRegion "${sourceScript}" "${slug}" || buildError "${slug}: ${regionError}"
sourceAStart="${regionAStart}" sourceAEnd="${regionAEnd}" sourceFirstRow="${regionFirstRow}" sourceLastRow="${regionLastRow}"
sourceBStart="${regionBStart}" sourceBEnd="${regionBEnd}"
shippedTitles=( "${regionTitles[@]}" )

# Selection
typeset -a selectionIds selectionTitles selectionRows selectionCalls
typeset -A seenTitles
customCount=0
while IFS= read -r selectionLine || [[ -n "${selectionLine}" ]]; do
    selectionLine="${selectionLine%$'\r'}"
    selectionLine="${selectionLine##[[:space:]]#}"
    selectionLine="${selectionLine%%[[:space:]]#}"
    [[ -z "${selectionLine}" || "${selectionLine}" == \#* ]] && continue
    [[ "${selectionLine}" == *\|* ]] || buildError "selection line lacks '|': ${selectionLine}"
    selectionId="${selectionLine%%|*}"
    selectionRest="${selectionLine#*|}"
    if [[ "${selectionRest}" == custom\|* ]]; then
        selectionRest="${selectionRest#custom|}"
        [[ "${selectionRest}" == *\|* ]] || buildError "custom line needs <row>|<call>: ${selectionLine}"
        selectionRow="$( normalizeRow "    ${selectionRest%%|*}" )"
        selectionCall="${selectionRest#*|}"
        [[ "${selectionRow}" =~ '"title" *: *"([^"]*)"' ]] || buildError "custom row without title: ${selectionLine}"
        selectionTitle="${match[1]}"
        (( customCount++ ))
    else
        selectionTitle="${selectionRest}"
        (( ${+rowByTitle[${selectionTitle}]} )) || buildError "title not found in any source array: ${selectionTitle} (${selectionId})"
        [[ "${selectionId}" == "${titleId[${selectionTitle}]}" ]] || buildError "ID ${selectionId} does not match ${titleId[${selectionTitle}]} for \"${selectionTitle}\""
        selectionRow="${rowByTitle[${selectionTitle}]}"
        selectionCall="${callByTitle[${selectionTitle}]}"
    fi
    (( ${+seenTitles[${selectionTitle}]} )) && buildError "duplicate title in selection: ${selectionTitle}"
    seenTitles[${selectionTitle}]="${selectionId}"
    selectionIds+=( "${selectionId}" )
    selectionTitles+=( "${selectionTitle}" )
    selectionRows+=( "${selectionRow}" )
    selectionCalls+=( "${selectionCall}" )
done < "${selectionInput}"
(( ${#selectionTitles} > 0 )) || buildError "selection is empty"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Build: regions and artifact
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

unchangedCopy="false"
selectionUnchanged="false"
typeset -a neutralizedTitles
if (( customCount == 0 )) && [[ "${(pj:\n:)selectionTitles}" == "${(pj:\n:)shippedTitles}" ]]; then
    selectionUnchanged="true"
    [[ "${pruneOtherMdms}" == "false" ]] && unchangedCopy="true"
    sed -n "${sourceAStart},${sourceAEnd}p" "${sourceScript}" > "${workDirectory}/regionA.txt"
    sed -n "${sourceBStart},${sourceBEnd}p" "${sourceScript}" > "${workDirectory}/regionB.txt"
else
    {
        sed -n "${sourceAStart},$(( sourceFirstRow - 1 ))p" "${sourceScript}"
        for (( i = 1; i <= ${#selectionRows}; i++ )); do
            rowText="$( renumberRow "${selectionRows[${i}]}" $(( i - 1 )) )"
            if [[ "${selectionTitles[${i}]}" == "Palo Alto GlobalProtect" ]]; then
                rowText="${rowText/\"subtitle\" : \"[^\"]#\"/\"subtitle\" : \"Virtual Private Network (VPN) connection to ${placeholderNetwork}\"}"
            fi
            if [[ "${slug}" != "jamf-pro" ]] && (( ${+neutralSubtitle[${selectionTitles[${i}]}]} )); then
                rowText="${rowText/\"subtitle\" : \"[^\"]#\"/\"subtitle\" : \"${neutralSubtitle[${selectionTitles[${i}]}]}\"}"
                neutralizedTitles+=( "${selectionTitles[${i}]}" )
            fi
            (( i < ${#selectionRows} )) && rowText="${rowText},"
            print -r -- "${rowText}"
        done
        sed -n "$(( sourceLastRow + 1 )),${sourceAEnd}p" "${sourceScript}"
    } > "${workDirectory}/regionA.txt"
    {
        sed -n "${sourceBStart}p" "${sourceScript}"
        for (( i = 1; i <= ${#selectionCalls}; i++ )); do
            print -r -- "                runConfiguredHealthCheck \"$(( i - 1 ))\" ${selectionCalls[${i}]}"
        done
        sed -n "${sourceBEnd}p" "${sourceScript}"
    } > "${workDirectory}/regionB.txt"
fi

# Prune other MDMs: case branches and arrays first, then vendor-owned symbols nothing references any more
typeset -a pruneSlugs pruneRanges pruneCaseLines prunedSymbols keptSymbols prunedArrays
pruneBranchCount=0
pruneBlockCount=0
if [[ "${pruneOtherMdms}" == "true" ]]; then
    pruneSlugs=( ${${slugOrder:#${slug}}:#generic} )
    writeLabelFile "${workDirectory}/labels.txt" "${pruneSlugs[@]}"
    caseOutput=$( findCaseBranchRanges "${sourceScript}" "${workDirectory}/labels.txt" ) || buildError "prune: $( caseError "${caseOutput}" )"
    for caseRecord in "${(@f)caseOutput}"; do
        [[ -z "${caseRecord}" ]] && continue
        caseFields=( "${(@ps:\t:)caseRecord}" )
        pruneRanges+=( "${caseFields[3]} ${caseFields[4]}" )
        (( ${pruneCaseLines[(Ie)${caseFields[2]}]} )) || pruneCaseLines+=( "${caseFields[2]}" )
        if [[ "${caseFields[1]}" == "block" ]]; then (( pruneBlockCount++ )); else (( pruneBranchCount++ )); fi
    done
    for pruneSlug in "${pruneSlugs[@]}"; do
        arrayRange=$( findArraySectionRange "${sourceScript}" "${slugArray[${pruneSlug}]}" ) || buildError "prune: section for ${slugArray[${pruneSlug}]} not found"
        pruneRanges+=( "${arrayRange}" )
        prunedArrays+=( "${slugArray[${pruneSlug}]}" )
    done

    writeAssemblyPlan "${workDirectory}/plan.txt" "${pruneRanges[@]}"
    assembleArtifact "${workDirectory}/pass1.zsh" "${workDirectory}/plan.txt"
    for vendorSymbol in "${vendorSymbols[@]}"; do
        symbolFields=( "${(@s:|:)vendorSymbol}" )
        (( ${pruneSlugs[(Ie)${symbolFields[2]}]} )) || continue
        symbolRange=$( findSymbolRange "${workDirectory}/pass1.zsh" "${symbolFields[1]}" "${symbolFields[3]}" ) || buildError "prune: ${symbolFields[3]} ${symbolFields[1]} not found"
        if (( $( countReferences "${workDirectory}/pass1.zsh" "${symbolFields[1]}" ${=symbolRange} ) > 0 )); then
            keptSymbols+=( "${symbolFields[1]}" )
            continue
        fi
        symbolRange=$( findSymbolRange "${sourceScript}" "${symbolFields[1]}" "${symbolFields[3]}" ) || buildError "prune: ${symbolFields[3]} ${symbolFields[1]} not found"
        pruneRanges+=( "${symbolRange}" )
        prunedSymbols+=( "${symbolFields[1]}" )
    done
    pruneRanges=( "${(@f)$( sortRanges "${pruneRanges[@]}" )}" )
    writeAssemblyPlan "${workDirectory}/plan.txt" "${pruneRanges[@]}"
    rm -f "${workDirectory}/pass1.zsh"
fi

stamp=$( date +%Y-%m-%d-%H%M%S )
while [[ -e "${outDir}/Mac-Health-Check_${slug}_${stamp}.zsh" ]]; do
    sleep 1
    stamp=$( date +%Y-%m-%d-%H%M%S )
done
baseName="Mac-Health-Check_${slug}_${stamp}"
workArtifact="${workDirectory}/${baseName}.zsh"
finalArtifact="${outDir}/${baseName}.zsh"
finalSidecar="${outDir}/${baseName}.md"

if [[ "${pruneOtherMdms}" == "true" ]]; then
    assembleArtifact "${workArtifact}" "${workDirectory}/plan.txt"
else
    {
        sed -n "1,$(( sourceAStart - 1 ))p" "${sourceScript}"
        cat "${workDirectory}/regionA.txt"
        sed -n "$(( sourceAEnd + 1 )),$(( sourceBStart - 1 ))p" "${sourceScript}"
        cat "${workDirectory}/regionB.txt"
        sed -n "$(( sourceBEnd + 1 )),\$p" "${sourceScript}"
    } > "${workArtifact}"
fi
sourceLineCount=$( wc -l < "${sourceScript}" | tr -d ' ' )
artifactLineCount=$( wc -l < "${workArtifact}" | tr -d ' ' )

print -r -- "Mac Health Check Selector: build-artifact.zsh ${helperVersion}"
print -r -- "Source: ${sourceScript}"
print -r -- "MDM: ${mdmDisplay} (mdmVendor ${mdmVendor}; ${arrayName}; ${branchLabel}); source Region A ${sourceAStart}-${sourceAEnd}; Region B ${sourceBStart}-${sourceBEnd}"
print -r -- "Selection: ${#selectionTitles} checks (shipped: ${#shippedTitles}); unchanged copy: ${unchangedCopy}"
typeset -a prunedDisplays
for pruneSlug in "${pruneSlugs[@]}"; do
    prunedDisplays+=( "${slugDisplay[${pruneSlug}]}" )
done
if [[ "${pruneOtherMdms}" == "true" ]]; then
    print -r -- "Pruned other MDMs: ${(j:, :)prunedDisplays}; ${#pruneRanges} source ranges; ${sourceLineCount} → ${artifactLineCount} lines"
    print -r -- "Pruned symbols: ${${(j:, :)prunedSymbols}:-none}${keptSymbols:+; kept (still called): ${(j:, :)keptSymbols}}"
fi
typeset -a borrowedNotes
for (( i = 1; i <= ${#selectionTitles}; i++ )); do
    [[ -z "${sourceSlugByTitle[${selectionTitles[${i}]}]}" || "${selectionRows[${i}]}" != "${rowByTitle[${selectionTitles[${i}]}]}" ]] && continue
    [[ "${sourceSlugByTitle[${selectionTitles[${i}]}]}" == "${slug}" ]] && continue
    borrowedNote="${selectionTitles[${i}]} (from ${slugDisplay[${sourceSlugByTitle[${selectionTitles[${i}]}]}]}"
    (( ${neutralizedTitles[(Ie)${selectionTitles[${i}]}]} )) && borrowedNote="${borrowedNote}, subtitle made vendor-neutral"
    borrowedNote="${borrowedNote})"
    borrowedNotes+=( "${borrowedNote}" )
    print -r -- "INFO borrowed row: ${borrowedNote}"
done
print -r -- ""

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Validation
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# 1. Syntax
if zsh -n "${workArtifact}" 2>"${workDirectory}/zsh-n.txt"; then
    recordCheck 1 "zsh -n" PASS ""
else
    recordCheck 1 "zsh -n" FAIL "$( head -1 "${workDirectory}/zsh-n.txt" )"
fi

# 2. Array JSON
if loadMdmRegion "${workArtifact}" "${slug}"; then
    artifactAStart="${regionAStart}" artifactAEnd="${regionAEnd}" artifactBStart="${regionBStart}" artifactBEnd="${regionBEnd}"
    artifactCallIndexes=( "${regionCallIndexes[@]}" )
    artifactCalls=( "${regionCalls[@]}" )
    arrayJson=$( evaluateArrayJson "${workArtifact}" "${artifactAStart}" "${artifactAEnd}" )
    if print -r -- "${arrayJson}" | jq -e 'type == "array" and length > 0' >/dev/null 2>&1; then
        recordCheck 2 "Array jq (${arrayName})" PASS ""
    else
        recordCheck 2 "Array jq (${arrayName})" FAIL "array is not valid JSON"
        arrayJson="[]"
    fi
else
    recordCheck 2 "Array jq (${arrayName})" FAIL "artifact anchors: ${regionError}"
    arrayJson="[]"
    artifactCallIndexes=() artifactCalls=()
fi

# 3. Alignment
rowCount=$( print -r -- "${arrayJson}" | jq 'length' )
callCount=${#artifactCalls}
if (( rowCount == callCount && rowCount == ${#selectionTitles} )); then
    recordCheck 3a "Rows = calls" PASS "rows=${rowCount}, calls=${callCount}"
else
    recordCheck 3a "Rows = calls" FAIL "rows=${rowCount}, calls=${callCount}, selection=${#selectionTitles}"
fi

indexProblem=""
for (( i = 1; i <= callCount; i++ )); do
    if [[ "${artifactCallIndexes[${i}]}" != "$(( i - 1 ))" ]]; then
        indexProblem="call ${i} has index \"${artifactCallIndexes[${i}]}\", expected \"$(( i - 1 ))\""
        break
    fi
done
if [[ -z "${indexProblem}" ]] && (( callCount > 0 )); then
    recordCheck 3b "Indices contiguous" PASS "0–$(( callCount - 1 ))"
else
    recordCheck 3b "Indices contiguous" FAIL "${indexProblem:-no calls}"
fi

if print -r -- "${arrayJson}" | jq -e 'length > 0 and (to_entries | all(.[]; .key as $k | .value.icon | startswith("SF=" + (($k + 1) | tostring | if length < 2 then "0" + . else . end) + ".circle")))' >/dev/null 2>&1; then
    printf -v lastIcon '%02d' "${rowCount}"
    recordCheck 3c "Icons match indices" PASS "01–${lastIcon}"
else
    recordCheck 3c "Icons match indices" FAIL "SF=NN.circle does not equal index + 1"
fi

arrayTitles=( "${(@f)$( print -r -- "${arrayJson}" | jq -r '.[].title' )}" )
lastTitle="${arrayTitles[-1]}"
secondLastTitle=""
(( ${#arrayTitles} > 1 )) && secondLastTitle="${arrayTitles[-2]}"
inventoryCallPosition=0
for (( i = 1; i <= callCount; i++ )); do
    [[ "${artifactCalls[${i}]}" == updateComputerInventory* ]] && inventoryCallPosition="${i}"
done
inventoryRowPresent="false"
(( ${arrayTitles[(Ie)${inventoryTitle}]} )) && inventoryRowPresent="true"
if (( inventoryCallPosition == 0 )) && [[ "${inventoryRowPresent}" == "false" ]]; then
    recordCheck 3d "F1 last or absent" PASS "absent"
elif (( inventoryCallPosition == callCount )) && [[ "${lastTitle}" == "Computer Inventory" ]]; then
    recordCheck 3d "F1 last or absent" PASS "last"
else
    recordCheck 3d "F1 last or absent" FAIL "updateComputerInventory call ${inventoryCallPosition} of ${callCount}; last row \"${lastTitle}\""
fi

networkQualityPresent="false"
(( ${arrayTitles[(Ie)${networkQualityTitle}]} )) && networkQualityPresent="true"
if [[ "${networkQualityPresent}" == "true" ]]; then
    if [[ "${lastTitle}" == "Network Quality Test" ]]; then
        recordCheck 3e "M15 last or directly before F1" PASS "last row"
    elif [[ "${lastTitle}" == "Computer Inventory" && "${secondLastTitle}" == "Network Quality Test" ]]; then
        recordCheck 3e "M15 last or directly before F1" PASS "directly before F1"
    else
        recordCheck 3e "M15 last or directly before F1" FAIL "last rows \"${secondLastTitle}\", \"${lastTitle}\""
    fi
elif [[ "${inventoryRowPresent}" == "true" ]]; then
    recordCheck 3e "M15 last or directly before F1" FAIL "F1 present without M15; Client-Side Cache copy would keep a trailing comma"
else
    recordCheck 3e "M15 last or directly before F1" PASS "M15 and F1 absent"
fi

# 4. Diff scope
diff "${sourceScript}" "${workArtifact}" > "${workDirectory}/artifact.diff"
hunkHeaders=( ${(f)"$( grep -E '^[0-9]' "${workDirectory}/artifact.diff" )"} )
if [[ "${pruneOtherMdms}" == "true" ]]; then
    # Pruned hunks slide across identical neighbouring lines, so compare every line outside the edited ranges instead
    printLinesOutside "${sourceScript}" "${sourceAStart} ${sourceAEnd}" "${sourceBStart} ${sourceBEnd}" "${pruneRanges[@]}" > "${workDirectory}/outside.source"
    if [[ -n "${artifactAStart}" && -n "${artifactBStart}" ]]; then
        printLinesOutside "${workArtifact}" "${artifactAStart} ${artifactAEnd}" "${artifactBStart} ${artifactBEnd}" > "${workDirectory}/outside.artifact"
    else
        : > "${workDirectory}/outside.artifact"
    fi
    if cmp -s "${workDirectory}/outside.source" "${workDirectory}/outside.artifact"; then
        recordCheck 4 "Diff limited to two regions and pruned ranges" PASS "${#hunkHeaders} hunk(s); every line outside A, B, and ${#pruneRanges} pruned ranges unchanged"
    else
        recordCheck 4 "Diff limited to two regions and pruned ranges" FAIL "lines outside A ${sourceAStart}-${sourceAEnd} / B ${sourceBStart}-${sourceBEnd} / pruned ranges differ"
    fi
elif (( ${#hunkHeaders} == 0 )); then
    recordCheck 4 "Diff limited to two regions" PASS "0 hunks (unchanged copy)"
elif awk -v a1="${sourceAStart}" -v a2="${sourceAEnd}" -v b1="${sourceBStart}" -v b2="${sourceBEnd}" '
        /^[0-9]/ {
            split($0, p, /[acd]/); n = split(p[1], r, ","); lo = r[1]; hi = (n > 1) ? r[2] : r[1]
            if (!((lo >= a1 && hi <= a2) || (lo >= b1 && hi <= b2))) bad = 1
        }
        END { exit bad }' "${workDirectory}/artifact.diff"; then
    recordCheck 4 "Diff limited to two regions" PASS "${#hunkHeaders} hunk(s): ${hunkHeaders[*]}"
else
    recordCheck 4 "Diff limited to two regions" FAIL "hunk outside A ${sourceAStart}-${sourceAEnd} / B ${sourceBStart}-${sourceBEnd}: ${hunkHeaders[*]}"
fi

# 4b–4c. Pruned MDM code absent; generic fallback intact
if [[ "${pruneOtherMdms}" == "true" ]]; then
    pruneProblems=()
    for prunedArray in "${prunedArrays[@]}"; do
        grep -qF -- "${prunedArray}" "${workArtifact}" && pruneProblems+=( "${prunedArray}" )
    done
    if remainingBranches=$( findCaseBranchRanges "${workArtifact}" "${workDirectory}/labels.txt" ); then
        for caseRecord in "${(@f)remainingBranches}"; do
            [[ -n "${caseRecord}" ]] && pruneProblems+=( "${${(@ps:\t:)caseRecord}[5]} (line ${${(@ps:\t:)caseRecord}[3]})" )
        done
    else
        pruneProblems+=( "$( caseError "${remainingBranches}" )" )
    fi
    if [[ "${slug}" != "generic" ]] && ! grep -qxF -- "    ${slugDetect[${slug}]} )" "${workArtifact}"; then
        pruneProblems+=( "${mdmDisplay} detection missing" )
    fi
    if [[ "${slug}" != "generic" ]] && ! loadMdmRegion "${workArtifact}" "generic"; then
        pruneProblems+=( "generic fallback: ${regionError}" )
    fi
    if (( ${#pruneProblems} == 0 )); then
        recordCheck 4b "Pruned MDMs absent" PASS "${#prunedArrays} arrays, ${pruneBranchCount} branches, ${pruneBlockCount} blocks removed; generic fallback intact"
    else
        recordCheck 4b "Pruned MDMs absent" FAIL "${(j:; :)pruneProblems}"
    fi

    symbolProblems=()
    for prunedSymbol in "${prunedSymbols[@]}"; do
        (( $( countReferences "${workArtifact}" "${prunedSymbol}" ) > 0 )) && symbolProblems+=( "${prunedSymbol}" )
    done
    for keptSymbol in "${keptSymbols[@]}"; do
        print -r -- "INFO 4c ${keptSymbol} kept: the selection still calls it"
    done
    if (( ${#symbolProblems} == 0 )); then
        recordCheck 4c "Pruned symbols unreferenced" PASS "${${(j:, :)prunedSymbols}:-none removed}"
    else
        recordCheck 4c "Pruned symbols unreferenced" FAIL "still referenced: ${(j:, :)symbolProblems}"
    fi
fi

# 5. Client-Side Cache simulation (sanitizer extracted from installClientSideScript in the source)
sanitizerAwk="${workDirectory}/sanitizer.awk"
sanitizedScript="${workDirectory}/sanitized.zsh"
awk -v startLine="    awk '" -v endPrefix="    ' \"\${temporaryClientScript}\" > \"\${sanitizedClientScript}\"" '
    /^function installClientSideScript\(\) \{$/ { inFunction = 1; next }
    inFunction && /^}$/ { exit }
    inFunction && !capture && $0 == startLine { capture = 1; next }
    capture && index($0, endPrefix) == 1 { found = 1; exit }
    capture { print }
    END { exit (found ? 0 : 3) }' "${sourceScript}" > "${sanitizerAwk}"
sanitizerStatus=$?
if (( sanitizerStatus != 0 )) || [[ ! -s "${sanitizerAwk}" ]] \
    || ! grep -qF -- "sed -i '' '${operationModeSedExpression}'" "${sourceScript}" \
    || ! grep -qF -- "sed -i '' '${networkQualitySedExpression}'" "${sourceScript}"; then
    recordCheck 5 "Client-Side Cache simulation" FAIL "sanitizer drift: installClientSideScript no longer matches this helper"
else
    cp "${workArtifact}" "${workDirectory}/client.zsh"
    sed -i '' "${operationModeSedExpression}" "${workDirectory}/client.zsh"
    awk -f "${sanitizerAwk}" "${workDirectory}/client.zsh" > "${sanitizedScript}"
    sed -i '' "${networkQualitySedExpression}" "${sanitizedScript}"

    if zsh -n "${sanitizedScript}" 2>/dev/null; then
        recordCheck 5a "Sanitized zsh -n" PASS ""
    else
        recordCheck 5a "Sanitized zsh -n" FAIL "sanitized copy has a syntax error"
    fi
    if loadMdmRegion "${sanitizedScript}" "${slug}"; then
        sanitizedJson=$( evaluateArrayJson "${sanitizedScript}" "${regionAStart}" "${regionAEnd}" )
        if print -r -- "${sanitizedJson}" | jq -e 'type == "array" and length > 0' >/dev/null 2>&1; then
            recordCheck 5b "Sanitized array jq" PASS "$( print -r -- "${sanitizedJson}" | jq length ) rows"
        else
            recordCheck 5b "Sanitized array jq" FAIL "cached nightly Silent copy would exit on invalid JSON"
        fi
    else
        recordCheck 5b "Sanitized array jq" FAIL "sanitized anchors: ${regionError}"
    fi
    if grep -q "jamf recon" "${sanitizedScript}"; then
        recordCheck 5c "Sanitized copy has no jamf recon" FAIL "installClientSideScript would refuse to install"
    else
        recordCheck 5c "Sanitized copy has no jamf recon" PASS ""
    fi
fi

# 6. scriptVersion unchanged
sourceVersion=$( grep -m1 '^scriptVersion=' "${sourceScript}" )
artifactVersion=$( grep -m1 '^scriptVersion=' "${workArtifact}" )
if [[ -n "${sourceVersion}" && "${sourceVersion}" == "${artifactVersion}" ]]; then
    recordCheck 6 "scriptVersion unchanged" PASS "${sourceVersion#scriptVersion=}"
else
    recordCheck 6 "scriptVersion unchanged" FAIL "source ${sourceVersion:-missing}; artifact ${artifactVersion:-missing}"
fi

# 7. Source untouched
sourceHashAfter=$( shasum -a 256 "${sourceScript}" | awk '{ print $1 }' )
if [[ "${sourceHashBefore}" == "${sourceHashAfter}" ]]; then
    recordCheck 7 "Source unchanged" PASS "sha256 ${sourceHashAfter[1,12]}…"
else
    recordCheck 7 "Source unchanged" FAIL "sha256 changed during build"
fi
if git -C "${sourceDirectory}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if git -C "${sourceDirectory}" diff --quiet -- "${sourceScript}"; then
        print -r -- "INFO 7 git diff --quiet -- ${sourceScript:t}: clean"
    else
        print -r -- "INFO 7 git diff --quiet -- ${sourceScript:t}: pre-existing local changes (artifact built from working copy)"
    fi
fi

# 8. Artifacts git-ignored
if git -C "${sourceDirectory}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if git -C "${sourceDirectory}" check-ignore -q "${finalArtifact}" && git -C "${sourceDirectory}" check-ignore -q "${finalSidecar}"; then
        recordCheck 8 "Artifacts git-ignored" PASS ""
    else
        recordCheck 8 "Artifacts git-ignored" FAIL "${finalArtifact:t} or ${finalSidecar:t} is not ignored"
    fi
else
    recordCheck 8 "Artifacts git-ignored" SKIP "not a git work tree"
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Result
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

print -r -- ""
if (( failCount > 0 )); then
    print -r -- "RESULT: FAIL (${failCount} check(s)); nothing written to ${outDir}"
    print -r -- "Failed build kept for inspection: ${workArtifact}"
    exit 1
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Sidecar
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

loadSanitizeCheckKey || print -r -- "WARNING: sanitizeCheckKey not found in source; report keys omitted"
swiftDialogMinimum=$( awk -F'"' '/^swiftDialogMinimumRequiredVersion=/ { print $2; exit }' "${sourceScript}" )
vpnVendorSetting=$( awk -F'"' '/^vpnClientVendor=/ { print $2; exit }' "${sourceScript}" )
if [[ "${slug}" == "generic" ]]; then
    testTarget="a Mac whose \`serverURL\` matches no known MDM (an unenrolled Mac qualifies)"
    titleVendor="<MDM>"
else
    testTarget="a Mac enrolled in ${mdmDisplay}"
    titleVendor="${mdmVendor}"
fi

typeset -A selectedTitleSet selectedIdSet
externalSelected="false"
for (( i = 1; i <= ${#selectionTitles}; i++ )); do
    selectedTitleSet[${selectionTitles[${i}]}]="true"
    selectedIdSet[${selectionIds[${i}]}]="true"
    [[ "${selectionCalls[${i}]}" == checkExternalJamfPro* ]] && externalSelected="true"
done

# Report keys
typeset -a removedKeys addedKeys
for shippedTitle in "${shippedTitles[@]}"; do
    (( ${+selectedTitleSet[${shippedTitle}]} )) && continue
    resolvedTitle="$( resolveTitle "${shippedTitle}" )"
    removedKeys+=( "\`$( reportKeyForTitle "${resolvedTitle}" )\` (${resolvedTitle})" )
done
for (( i = 1; i <= ${#selectionTitles}; i++ )); do
    (( ${shippedTitles[(Ie)${selectionTitles[${i}]}]} )) && continue
    resolvedTitle="$( resolveTitle "${selectionTitles[${i}]}" )"
    addedKeys+=( "\`$( reportKeyForTitle "${resolvedTitle}" )\` (${resolvedTitle})" )
done

# Disabled checks, in master-table order, with reasons derived from shipped lists and availability
typeset -a disabledRows agentAppTitles
chosenShipsAgentApp="false"
for shippedTitle in "${shippedTitles[@]}"; do
    [[ "${titleId[${shippedTitle}]}" == A5* ]] && chosenShipsAgentApp="true"
done
for mapTitle in "${mapTitles[@]}"; do
    (( ${+selectedTitleSet[${mapTitle}]} )) && continue
    (( ${+slugsByTitle[${mapTitle}]} )) || continue
    mapCheckId="${titleId[${mapTitle}]}"
    titleOwners=( ${=slugsByTitle[${mapTitle}]} )
    restrictedOwner="${idOwner[${mapCheckId}]}"
    if (( ${shippedTitles[(Ie)${mapTitle}]} )); then
        disabledRows+=( "| ${mapCheckId} | $( resolveTitle "${mapTitle}" "${titleVendor}" ) | Admin choice |" )
    elif [[ "${mapCheckId}" == A5* ]]; then
        (( ${#agentAppTitles} == 0 )) && disabledRows+=( "__AGENT_APPS__" )
        agentAppTitles+=( "$( resolveTitle "${mapTitle}" "${slugVendor[${titleOwners[1]}]}" )" )
    elif [[ "${restrictedOwner}" == "vendor" && "${slug}" == "generic" ]]; then
        disabledRows+=( "| ${mapCheckId} | $( resolveTitle "${mapTitle}" "${titleVendor}" ) | Needs a known MDM vendor |" )
    elif [[ -n "${restrictedOwner}" && "${restrictedOwner}" != "vendor" && "${restrictedOwner}" != "${slug}" ]]; then
        disabledRows+=( "| ${mapCheckId} | $( resolveTitle "${mapTitle}" "${slugVendor[${restrictedOwner}]}" ) | ${slugDisplay[${restrictedOwner}]} only |" )
    else
        disabledRows+=( "| ${mapCheckId} | $( resolveTitle "${mapTitle}" "${titleVendor}" ) | Not default |" )
    fi
done
if (( ${#agentAppTitles} > 0 )); then
    if [[ "${chosenShipsAgentApp}" == "true" ]]; then
        agentAppReason="Other MDMs' agent apps; add an A4-style custom app if needed"
    else
        agentAppReason="No agent app ships for ${mdmDisplay}; add an A4-style custom app if needed"
    fi
    disabledRows[${disabledRows[(Ie)__AGENT_APPS__]}]="| A5 | ${(j:, :)agentAppTitles} | ${agentAppReason} |"
fi
if (( ! ${+selectedIdSet[A10]} )); then
    if [[ "${slug}" == "jamf-pro" ]]; then
        disabledRows+=( "| A10 | Other \`external-checks/\` script | Not default (custom) |" )
    else
        disabledRows+=( "| A10 | Other \`external-checks/\` script | Jamf Pro only |" )
    fi
fi

# Dependency notes, tagged by scope
typeset -a dependencyNotes
dependencyNotes+=( "[all] swiftDialog \`${swiftDialogMinimum}\` or newer (\`swiftDialogMinimumRequiredVersion\`); pre-flight installs or updates it." )
dependencyNotes+=( "[all] \`jq\` validates every list-item array; an invalid array exits the script before any check runs." )
dependencyNotes+=( "[all] Client-Side Cache / LaunchDaemon: the cached copy runs nightly in \`Silent\` and drops \`updateComputerInventory\`; H3–H5 fall back to the loginwindow \`lastUserName\` when no one is logged in." )
dependencyNotes+=( "[all] \`Silent\` + \`splunkOperationMode=production\` is reporting-first; use \`<YOUR_SPLUNK_HEC_URL>\` and \`<YOUR_SPLUNK_HEC_TOKEN>\`." )
dependencyNotes+=( "[all] Secrets: \`webhookURL\` and \`splunkHECToken\` go in root-only \`MacHealthCheck-Secrets.plist\`; Parameters 5 and 8 are rejected unless \`allowParameterSecrets=\"true\"\`." )
if [[ "${pruneOtherMdms}" == "false" ]]; then
    dependencyNotes+=( "[all] Runtime MDM detection: the edits run only on ${testTarget}; Macs enrolled elsewhere run their own unedited branch." )
elif [[ "${slug}" == "generic" ]]; then
    dependencyNotes+=( "[prune] Named-MDM code removed: every Mac runs the generic branch, whatever its MDM; rebuild without pruning for MDM-specific checks." )
else
    dependencyNotes+=( "[prune] Other MDM code removed: only ${mdmDisplay} and the generic fallback remain; Macs enrolled in any other MDM run the generic branch (no MDM Profile or MDM Certificate Expiration). Rebuild without pruning for mixed fleets." )
fi
if [[ "${unchangedCopy}" == "true" ]]; then
    dependencyNotes+=( "[all] Unchanged copy: the selection equals the shipped ${mdmDisplay} default." )
elif [[ "${selectionUnchanged}" == "true" ]]; then
    dependencyNotes+=( "[all] Check set unchanged: the selection equals the shipped ${mdmDisplay} default; only other MDM code was removed." )
else
    dependencyNotes+=( "[all] Check set changed: the first Self Service run after deployment is a full run (\`check_set_mismatch\`)." )
fi
(( ${#removedKeys} > 0 )) && dependencyNotes+=( "[all] Report keys removed: ${(j:, :)removedKeys}; Splunk dashboards and targeted-recheck continuity lose them." )
(( ${#addedKeys} > 0 )) && dependencyNotes+=( "[all] Report keys added: ${(j:, :)addedKeys}." )
(( ${#borrowedNotes} > 0 )) && dependencyNotes+=( "[all] Rows copied from other MDM arrays: ${(j:, :)borrowedNotes}; review their subtitles." )
(( ${+selectedIdSet[C8]} )) && dependencyNotes+=( "[C8] Touch ID reports an error on Macs without Touch ID hardware (VMs, desktops without a Touch ID keyboard); drop C8 for those fleets." )
(( ${+selectedIdSet[C13]} )) && dependencyNotes+=( "[C13] VPN Client follows \`vpnClientVendor\` (shipped \`${vpnVendorSetting}\`) and \`vpnClientDataType\`; it fails when that client is absent. Set both for your organization." )
(( ${+selectedIdSet[H6]} )) && dependencyNotes+=( "[H6] Memory Pressure needs samples from two distinct days before it can warn; early runs show \`Insufficient data\`." )
(( ${+selectedIdSet[M1]} )) && dependencyNotes+=( "[vendor] MDM Profile needs \`mdmVendorUuid\` or \`mdmProfileIdentifier\` for ${mdmDisplay}." )
[[ "${slug}" == "addigy" ]] && (( ${+selectedIdSet[M1]} )) && dependencyNotes+=( "[Addigy] \`mdmVendorUuid\` ships blank; MDM Profile fails until you fill it in." )
[[ "${slug}" == "kandji" ]] && dependencyNotes+=( "[Kandji] Detection needs \`serverURL\` to contain \`kandji\`; an Iru-branded URL without it runs the generic branch." )
if [[ "${slug}" == "generic" ]]; then
    dependencyNotes+=( "[generic] No MDM Profile or MDM Certificate Expiration: no vendor profile or certificate name is known." )
    (( ${+selectedIdSet[M4]} )) && dependencyNotes+=( "[generic] Apple Push Notification service (M4) fails on Macs with no MDM enrollment; expected on an unenrolled test Mac." )
fi
[[ "${slug}" == "jamf-pro" ]] && dependencyNotes+=( "[Jamf] The script exits early when \`/private/var/log/jamf.log\` is missing." )
[[ "${externalSelected}" == "true" ]] && dependencyNotes+=( "[Jamf] External checks need their \`external-checks/\` scripts saved in Jamf Pro and policies with matching custom triggers; output must include \`Running\`, \`Warning\`, \`Failed\`, or \`Error\`." )
(( ${+selectedIdSet[F1]} )) && dependencyNotes+=( "[Jamf] F1 runs \`jamf recon\` (90-second timeout); skipped in \`Silent\` + \`splunkOperationMode=production\` and removed from the Client-Side Cache copy." )
if (( ${+selectedIdSet[A9]} )) && [[ "${selectionUnchanged}" == "false" ]]; then
    dependencyNotes+=( "[A9] Palo Alto GlobalProtect subtitle now reads \`<YOUR_ORGANIZATION_NETWORK>\`; replace it before deploying." )
fi
for (( i = 1; i <= ${#selectionIds}; i++ )); do
    [[ "${selectionIds[${i}]}" == "A4" ]] && dependencyNotes+=( "[A4] ${selectionTitles[${i}]}: \`${selectionCalls[${i}]}\`; edit the path and name if your required app differs." )
done

artifactDisplayPath="${finalArtifact#${sourceDirectory}/}"
{
    print -r -- "# Mac Health Check artifact — ${mdmDisplay} — ${stamp}"
    print -r -- ""
    print -r -- "- Artifact: \`${artifactDisplayPath}\`"
    print -r -- "- Source: \`${sourceScript:t}\` (\`scriptVersion\` ${${sourceVersion#scriptVersion=}//\"/}, unchanged)"
    print -r -- "- MDM: ${mdmDisplay} (\`mdmVendor\` = \`${mdmVendor}\`, slug \`${slug}\`)"
    print -r -- "- Built by: \`scripts/build-artifact.zsh\` ${helperVersion}"
    if [[ "${pruneOtherMdms}" == "true" ]]; then
        print -r -- "- Other MDM code: removed (${(j:, :)prunedDisplays}); generic fallback kept"
    else
        print -r -- "- Other MDM code: kept (not pruned)"
    fi
    print -r -- ""
    print -r -- "## Enabled (${#selectionTitles})"
    print -r -- "| Index | ID | Title | Report key |"
    print -r -- "|---|---|---|---|"
    for (( i = 1; i <= ${#selectionTitles}; i++ )); do
        resolvedTitle="$( resolveTitle "${selectionTitles[${i}]}" )"
        print -r -- "| $(( i - 1 )) | ${selectionIds[${i}]} | ${resolvedTitle} | \`$( reportKeyForTitle "${resolvedTitle}" )\` |"
    done
    print -r -- ""
    print -r -- "## Disabled (${#disabledRows})"
    print -r -- "| ID | Title | Reason |"
    print -r -- "|---|---|---|"
    print -r -l -- "${disabledRows[@]}"
    print -r -- ""
    print -r -- "## Report keys removed vs shipped ${mdmDisplay} default"
    if (( ${#removedKeys} > 0 )); then print -r -l -- "${removedKeys[@]/#/- }"; else print -r -- "- None"; fi
    print -r -- ""
    print -r -- "## Report keys added vs shipped ${mdmDisplay} default"
    if (( ${#addedKeys} > 0 )); then print -r -l -- "${addedKeys[@]/#/- }"; else print -r -- "- None"; fi
    print -r -- ""
    if [[ "${pruneOtherMdms}" == "true" ]]; then
        print -r -- "## Pruned MDM code"
        print -r -- "- MDMs removed: ${(j:, :)prunedDisplays}; generic fallback (\`* )\`, \`genericMdmListitemJSON\`) kept"
        print -r -- "- List-item arrays removed: \`${(pj:\`, \`:)prunedArrays}\`"
        print -r -- "- Vendor \`case\` blocks: ${pruneBranchCount} branches removed, ${pruneBlockCount} emptied blocks removed (source lines ${(j:, :)pruneCaseLines})"
        print -r -- "- Vendor-only symbols removed: ${${prunedSymbols:+\`${(pj:\`, \`:)prunedSymbols}\`}:-None}"
        print -r -- "- Vendor-only symbols kept (still called by this selection): ${${keptSymbols:+\`${(pj:\`, \`:)keptSymbols}\`}:-None}"
        print -r -- "- Source lines: ${sourceLineCount} → ${artifactLineCount} (${#pruneRanges} ranges: ${(j:, :)${(@)pruneRanges// /-}})"
        print -r -- ""
    fi
    print -r -- "## Dependency notes"
    print -r -l -- "${dependencyNotes[@]/#/- }"
    print -r -- ""
    print -r -- "## Validation"
    print -r -- "| # | Check | Result |"
    print -r -- "|---|---|---|"
    for (( i = 1; i <= ${#validationNumbers}; i++ )); do
        print -r -- "| ${validationNumbers[${i}]} | ${validationNames[${i}]} | ${validationResults[${i}]} |"
    done
    print -r -- "| 9 | Five-mode test run on ${testTarget} | Pending (admin) |"
    print -r -- ""
    print -r -- "## Diff summary"
    if [[ "${unchangedCopy}" == "true" ]]; then
        print -r -- "- Unchanged copy of the source: selection equals the shipped ${mdmDisplay} default"
    elif [[ "${pruneOtherMdms}" == "true" ]]; then
        if [[ "${selectionUnchanged}" == "true" ]]; then
            print -r -- "- Regions A \`${arrayName}\` and B \`${branchLabel}\`: unchanged (selection equals the shipped ${mdmDisplay} default)"
        else
            print -r -- "- Region A \`${arrayName}\`: source lines ${sourceAStart}-${sourceAEnd}, ${#shippedTitles} rows → ${rowCount} rows"
            print -r -- "- Region B \`${branchLabel}\`: source lines ${sourceBStart}-${sourceBEnd}, ${#shippedTitles} calls → ${callCount} calls"
        fi
        print -r -- "- Pruned ranges: ${#pruneRanges} (see **Pruned MDM code**); ${#hunkHeaders} diff hunks"
    else
        print -r -- "- Region A \`${arrayName}\`: source lines ${sourceAStart}-${sourceAEnd}, ${#shippedTitles} rows → ${rowCount} rows"
        print -r -- "- Region B \`${branchLabel}\`: source lines ${sourceBStart}-${sourceBEnd}, ${#shippedTitles} calls → ${callCount} calls"
        print -r -- "- Hunk headers: \`${(pj:\`, \`:)hunkHeaders}\`"
    fi
    print -r -- ""
    print -r -- "## Next steps"
    print -r -- "1. Review this sidecar and the diff; add organization-specific notes below."
    print -r -- "2. Run the five-mode test on ${testTarget}; re-run the production policy afterwards to restore the Client-Side Cache copy and LaunchDaemon."
    print -r -- "3. Deploy the artifact as the MDM script; keep \`scriptVersion\` unchanged."
    nextStep=4
    if [[ "${selectionUnchanged}" == "false" ]]; then
        print -r -- "${nextStep}. Expect the first Self Service run to be a full run (\`check_set_mismatch\`)."
        (( nextStep++ ))
    fi
    if [[ "${pruneOtherMdms}" == "true" && "${slug}" != "generic" ]]; then
        print -r -- "${nextStep}. Optionally run once on a Mac not enrolled in ${mdmDisplay} (an unenrolled Mac qualifies) to confirm the generic fallback."
    fi
} > "${workDirectory}/${baseName}.md" || buildError "unable to write sidecar"

mkdir -p "${outDir}" || buildError "unable to create ${outDir}"
mv "${workArtifact}" "${finalArtifact}" || buildError "unable to write ${finalArtifact}"
mv "${workDirectory}/${baseName}.md" "${finalSidecar}" || { rm -f "${finalArtifact}"; buildError "unable to write ${finalSidecar}"; }

print -r -- "RESULT: PASS; artifact ${finalArtifact}"
print -r -- "Sidecar: ${finalSidecar}"
print -r -- "Enabled (${#selectionIds}): ${selectionIds[*]}"
print -r -- "Disabled: ${#disabledRows} row(s); report keys removed ${#removedKeys}, added ${#addedKeys}"

rm -rf "${workDirectory}"
exit 0
