---
name: Bug Report
about: Submit a bug report for Mac Health Check (after using the snippet below and having reviewed open swiftDialog issues)
title: 'Bug: '
labels: bug
assignees: 'dan-snelson'

---

> Before submitting a bug report, please use the following snippet to download a fresh, time-stamped version of `Mac-Health-Check.zsh` and ensure you can replicate the unexpected behavior:
> 
> `timestamp=$( date '+%Y-%m-%d-%H%M%S' ) ; curl -o ~/Downloads/Mac-Health-Check-$timestamp.zsh https://raw.githubusercontent.com/dan-snelson/Mac-Health-Check/main/Mac-Health-Check.zsh ; sudo zsh ~/Downloads/Mac-Health-Check-$timestamp.zsh`
> 
> Also, please review the [open swiftDialog issues](https://github.com/swiftDialog/swiftDialog/issues) to help determine the source of the issue.
> 
> You're also invited to discuss via the [Mac Admins Slack](https://www.macadmins.org/) (free, registration required) [#mac-health-check Channel](https://slack.com/app_redirect?channel=C0977DRT7UY).

---

**Describe the bug**
A clear, concise description of the bug.

**To Reproduce**
 - Please describe how the script was executed (i.e., via macOS Terminal, via in a Jamf Pro Self Service policy, etc.).
 - Please detail any modififications.
 
**Expected behavior**
A clear, concise description of what you expected to happen.

**Code/log output**
Please supply the full command used, and if applicable, add full output from Terminal. Either upload the log, or paste the output in a code block (triple backticks at the start and end of the code block, please!).

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Environment (please complete the following information):**
 - OS version (i.e., 15.6)
 - Script version (i.e., 2.0.0) - please upgrade to the latest version before submitting a bug report.

**Additional context**
Add any other context about the problem here.
