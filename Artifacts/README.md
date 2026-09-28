# Artifacts

The [`mac-health-check-selector`](../Skills/mac-health-check-selector/SKILL.md) skill writes its output here: edited copies of `Mac-Health-Check.zsh`, one MDM at a time. The source script is never modified.

## Naming

- Artifact: `Mac-Health-Check_<mdm-slug>_<YYYY-MM-DD-HHMMSS>.zsh`, with the timestamp in local time. The Development preset adds `_development`.
- Sidecar: `.md` with the same basename. It records the selection, the dependency notes, the validation results, and a diff summary.

Slugs: `jamf-pro`, `fleet`, `jumpcloud`, `microsoft-intune`, `mosyle`, `kandji`, `addigy`, `filewave`, `generic`.

## What changes

Each artifact differs from `Mac-Health-Check.zsh` in exactly two regions:

- the chosen MDM's list-item array, and
- that MDM's branch in the health-check `case ${mdmVendor} in` block.

For Development artifacts, the two regions are instead `developmentListitemJSON` and the direct Development check calls. `scriptVersion` stays unchanged.

## Before deploying

1. Review the sidecar.
2. Test on one Mac with `sudo zsh ./Artifacts/<file>.zsh "" "" "" "Development"`.
3. Repeat the test with `Self Service`, `Silent`, `Debug`, and `Test` as Parameter 4.

## Version control

Everything in this folder except this README is git-ignored, because artifacts may carry organization-specific edits. Do not commit artifacts.
