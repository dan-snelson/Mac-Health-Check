#!/bin/zsh
# Post-install script: Automatically run [Mac Health Check](https://snelson.us/mhc) after installation.

echo "Running [Mac Health Check](https://snelson.us/mhc) …"
/usr/local/bin/Mac-Health-Check

exit 0