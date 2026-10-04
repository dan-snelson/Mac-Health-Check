# Artifacts

The [`mac-health-check-selector`](../Skills/mac-health-check-selector/SKILL.md) skill writes its output here: edited copies of `Mac-Health-Check.zsh`, one MDM at a time. The source script is never modified.

## Naming

- Artifact: `Mac-Health-Check_<mdm-slug>_<YYYY-MM-DD-HHMMSS>.zsh`, with the timestamp in local time.
- Sidecar: `.md` with the same basename. It records the selection, the dependency notes, the validation results, and a diff summary.

Slugs: `jamf-pro`, `fleet`, `jumpcloud`, `microsoft-intune`, `mosyle`, `kandji`, `addigy`, `filewave`, `generic`.

## What changes

Each artifact differs from `Mac-Health-Check.zsh` in exactly two regions:

- the chosen MDM's list-item array, and
- that MDM's branch in the health-check `case ${mdmVendor} in` block.

Exception: an artifact built with `--prune-other-mdms` also drops every other named MDM's list-item array, its branches in each vendor `case` block (including `serverURL` detection), and vendor-only functions the selection no longer calls. The generic fallback always stays.

Only artifacts that pass validation checks 1–8 are written here. The skill's helper, [`scripts/build-artifact.zsh`](../Skills/mac-health-check-selector/scripts/build-artifact.zsh), builds and validates in a temporary work directory first.

`developmentListitemJSON`, `operationMode`, and every other setting keep the source defaults; edit the artifact manually to change them. `scriptVersion` stays unchanged.

## Before deploying

1. Review the sidecar.
2. Test on one Mac **enrolled in the artifact's MDM** with `sudo zsh --no-rcs ./Artifacts/<file>.zsh "" "" "" "Self Service"`. The script chooses its MDM branch from the enrolled server URL, so a Mac enrolled elsewhere runs that MDM's unedited checks. Exception: an artifact built with `--prune-other-mdms` no longer has those branches, so a Mac enrolled in another MDM runs the generic fallback checks. For a `generic` (Other / MDM-agnostic) artifact, test on an unenrolled Mac or one whose MDM the script does not detect; Apple Push Notification service then warns or fails as expected.
3. Repeat the test with `Silent`, `Debug`, `Development`, and `Test` as Parameter 4. `Development` runs the shipped `developmentListitemJSON` subset, not the selection.
4. Mind the Client-Side Cache. The install runs only in `Self Service`, `Debug`, and `Silent` with `splunkOperationMode=production` (never `Test` or `Development`), and only from a root-owned script path. Run from a user-owned checkout such as `./Artifacts/`, the script logs `install skipped` and leaves the Mac's cached copy alone. Run from a root-owned path (as an MDM script is), it replaces the Mac's Client-Side Cache copy and LaunchDaemon with the artifact; re-run the production policy afterwards to restore them.

## Version control

Everything in this folder except this README is git-ignored, because artifacts may carry organization-specific edits. Do not commit artifacts.
