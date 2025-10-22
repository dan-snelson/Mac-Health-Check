#!/bin/zsh

# Author: Bart Reardon
# Date: 2023-11-23
# https://github.com/bartreardon/macscripts/blob/master/create_self_extracting_script.sh

# Updated by: Dan K. Snelson
# For Mac Health Check
# Date: 19-Oct-2025

# Script for creating self extracting base64 encoded files.

# usage: file_to_self_extracting_script <file_path> [target_path]

SCRIPT_NAME=$(basename "$0")
FILE_TO_ENCODE="$(cd "$(dirname "$0")"/.. && pwd)/Mac-Health-Check.zsh"
TARGET_PATH="/var/tmp/MHC.zsh"

datestamp=$( date '+%Y-%m-%d-%H%M%S' )

file_to_self_extracting_script() {
    base64_string=$(base64 -i "$1")
    filename=$(basename "$1")
    target_path=${2}
    # if [[ -n "$target_path" ]]; then
    #     # check to see if the path ends with a slash
    #     if [[ ! "$target_path" =~ /$ ]]; then
    #         target_path="${target_path}/"
    #     fi
    # fi

    cat <<EOF > "${filename}_self-extracting-${datestamp}.sh"
#!/bin/sh
base64_string='$base64_string'
echo "\$base64_string" | base64 -d > "${target_path}"
echo "File '${target_path}' has been created."
chmod u+x "${target_path}"
zsh "${target_path}"
EOF
    echo "Self-extracting script '${filename}_self-extracting-${datestamp}.sh' created."
}

printUsage() {
    echo "OVERVIEW: ${SCRIPT_NAME} is a utility that creates self extracting base64 encoded scripts."
    echo ""
    echo "USAGE: ${SCRIPT_NAME} --file <filename> [--target <directory>]"
    echo ""
    echo "OPTIONS:"
    echo "    -f, --file <filename>     Encode the selected file"
    echo "    -t, --target <directory>  Target directory to extract the file to. Defaults to the current directory."
    echo "    -h, --help                Print this message"
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
        --target|-t) TARGET_PATH="$2"; shift ;;
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

file_to_self_extracting_script "${FILE_TO_ENCODE}" "${TARGET_PATH}"
