#!/bin/zsh

# Author: Bart Reardon
# Date: 2023-11-23
# https://github.com/bartreardon/macscripts/blob/master/create_self_extracting_script.sh

# Updated by: Dan K. Snelson
# For Mac Health Check
# Date: 28-Sep-2026
# - Generated wrapper now decodes into a root-only `mktemp -d` directory (instead of a fixed, pre-plantable
#   `/var/tmp/MHC.zsh`), forwards all arguments (i.e., Jamf Pro Parameters 1-11) and removes the copy on exit

# Script for creating self extracting base64 encoded files.

# usage: file_to_self_extracting_script <file_path>

SCRIPT_NAME=$(basename "$0")
FILE_TO_ENCODE="$(cd "$(dirname "$0")"/.. && pwd)/Mac-Health-Check.zsh"

datestamp=$( date '+%Y-%m-%d-%H%M%S' )

file_to_self_extracting_script() {
    base64_string=$(base64 -i "$1")
    filename=$(basename "$1")

    cat <<EOF > "${filename}_self-extracting-${datestamp}.sh"
#!/bin/sh
base64_string='$base64_string'
umask 077
workDir=\$( /usr/bin/mktemp -d /var/tmp/MHC-selfExtracting.XXXXXX ) || exit 1
trap 'rm -rf "\$workDir"' EXIT
printf '%s' "\$base64_string" | /usr/bin/base64 -d > "\$workDir/${filename}" || exit 1
/bin/zsh --no-rcs "\$workDir/${filename}" "\$@"
EOF
    echo "Self-extracting script '${filename}_self-extracting-${datestamp}.sh' created."
}

printUsage() {
    echo "OVERVIEW: ${SCRIPT_NAME} is a utility that creates self extracting base64 encoded scripts."
    echo ""
    echo "USAGE: ${SCRIPT_NAME} [--file <filename>]"
    echo ""
    echo "OPTIONS:"
    echo "    -f, --file <filename>     Encode the selected file (defaults to ../Mac-Health-Check.zsh)"
    echo "    -h, --help                Print this message"
    echo ""
    echo "The generated script decodes into a root-only, per-run mktemp directory, forwards all arguments and removes the copy on exit."
    echo ""
}

# if no arguments passed, print help and exit
# if [[ "$#" -eq 0 ]]; then
#     printUsage
#     exit 0
# fi

# Loop through named arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --file|-f) FILE_TO_ENCODE="$2"; shift ;;
        --help|-h|help) printUsage; exit 0 ;;
        *) echo "Unknown argument: $1"; printUsage; exit 1 ;;
    esac
    shift
done

if [[ -z "$FILE_TO_ENCODE" ]]; then
    echo "Error: No file specified."
    printUsage
    exit 1
fi

file_to_self_extracting_script "${FILE_TO_ENCODE}"
