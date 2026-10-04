#!/bin/zsh --no-rcs
# Post-install script: Automatically run [Mac Health Check](https://snelson.us/mhc) after installation.
# (Runs from the root-owned package payload path; never from user-writable `/usr/local/bin`)

echo "Running [Mac Health Check](https://snelson.us/mhc) …"
/bin/zsh --no-rcs "${3}/Library/Management/org.churchofjesuschrist/Mac-Health-Check.zsh" "" "" "" "Self Service"

exit 0
