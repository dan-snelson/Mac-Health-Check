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

Only artifacts that pass validation checks 1–8 are written here. The skill's helper, [`scripts/build-artifact.zsh`](../Skills/mac-health-check-selector/scripts/build-artifact.zsh), builds and validates in a temporary work directory first.

`developmentListitemJSON`, `operationMode`, and every other setting keep the source defaults; edit the artifact manually to change them. `scriptVersion` stays unchanged.

## Before deploying

1. Review the sidecar.
2. Test on one Mac **enrolled in the artifact's MDM** with `sudo zsh ./Artifacts/<file>.zsh "" "" "" "Self Service"`. The script chooses its MDM branch from the enrolled server URL, so a Mac enrolled elsewhere runs that MDM's unedited checks.
3. Repeat the test with `Silent`, `Debug`, `Development`, and `Test` as Parameter 4. `Development` runs the shipped `developmentListitemJSON` subset, not the selection.
4. Re-run the production policy afterwards. Non-`Silent` test runs replace the Mac's Client-Side Cache copy and LaunchDaemon with the artifact.

## Version control

Everything in this folder except this README is git-ignored, because artifacts may carry organization-specific edits. Do not commit artifacts.
