# Mac Health Check — Artifact Procedure

Companion reference for the `mac-health-check-selector` skill. It describes how to write an MDM-specific, date-stamped copy of `Mac-Health-Check.zsh` into `Artifacts/` and how to validate it. Derived from `Mac-Health-Check.zsh` `5.0.0b1`. When this file and the script disagree, the script wins.

The procedure is deterministic: find anchor lines, replace line ranges, validate. Prefer the tested helper `scripts/build-artifact.zsh`, which implements every step below. The manual snippets are the fallback for environments that cannot run it.

## Contract

- Never modify `Mac-Health-Check.zsh` in place. Read it; write only to `Artifacts/`. Check 7 proves the source is byte-identical before and after (SHA-256).
- The artifact is an unmodified copy of the source with exactly two regions replaced (see **Regions**). If the admin's selection equals the MDM's shipped default, copy the source unchanged and say so in the sidecar.
- Leave `scriptVersion` unchanged (check 6). A version change triggers targeted-recheck `version_mismatch`.
- Build every artifact from the untouched source, even when a session produces several.
- Use placeholders only (`<YOUR_WEBHOOK_URL>`, `<YOUR_ORGANIZATION_NETWORK>`, …). Never write real organization data.
- Only passing artifacts live in `Artifacts/`. Build in a work directory, validate there, and move the file into `Artifacts/` only when checks 1–8 pass. Leave a failed build in the work directory, fix the selection, and rebuild with a new timestamp.

## Naming

```text
Artifacts/Mac-Health-Check_<mdm-slug>_<YYYY-MM-DD-HHMMSS>.zsh
Artifacts/Mac-Health-Check_<mdm-slug>_<YYYY-MM-DD-HHMMSS>.md          # sidecar
```

- Timestamp: local time, `date +%Y-%m-%d-%H%M%S`, taken when the artifact is written. Before the admin confirms, show only the `<YYYY-MM-DD-HHMMSS>` placeholder.
- Slugs: `jamf-pro`, `fleet`, `jumpcloud`, `microsoft-intune`, `mosyle`, `kandji`, `addigy`, `filewave`, `generic`.
- `Artifacts/` sits next to the source script. Create it if missing. It is git-ignored except `Artifacts/README.md` (check 8).

## Helper (preferred)

Run from the repository root:

```zsh
# Shipped rows for one MDM: index|raw title|call (use to confirm the reference's default order)
zsh Skills/mac-health-check-selector/scripts/build-artifact.zsh --list microsoft-intune

# Build + validate + write the sidecar; the selection arrives on stdin, so no temporary file is left behind
zsh Skills/mac-health-check-selector/scripts/build-artifact.zsh --slug microsoft-intune --selection - <<'ENDOFSELECTION'
C1|macOS Version
C2|Available Updates
…
M15|Network Quality Test
ENDOFSELECTION
```

Quote the here-doc delimiter (`<<'ENDOFSELECTION'`) so `'${mdmVendor}'` in raw titles stays literal. `--selection <file>` also works; delete such a file after the build.

Selection format (one line per check, final order; blank lines and `#` comments are ignored):

```text
C1|macOS Version
M1|'${mdmVendor}' MDM Profile
A4|custom|{"title" : "Zoom", "subtitle" : "Web Conferencing Tool.", "icon" : "SF=NN.circle,'"${organizationColorScheme}"'", "status" : "pending", "statustext" : "Pending …", "iconalpha" : 0.5}|checkInternal "/Applications/zoom.us.app" "/Applications/zoom.us.app" "Zoom"
```

Titles are looked up in the source: the chosen MDM's array first, then Jamf Pro, then the remaining MDMs. Each row is paired with the call at the same index in that MDM's branch, and every row taken from another MDM's array prints `INFO borrowed row:`. The helper stops with exit `2` in these cases:

- a source region has more rows than calls, or the reverse;
- a selection ID does not match the helper's check-ID map;
- a source title is missing from that map, which means the map and `health-checks.md` need an update.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Checks 1–8 passed. The artifact and its complete sidecar are in `Artifacts/`. |
| `1` | At least one check failed. Nothing is written to `Artifacts/`, and the failed build stays in the printed work directory. |
| `2` | Usage, selection, or anchor error. Nothing is written. |

## Regions

Anchor on exact whole lines, never on label text alone. `"Jamf Pro" )` and the other vendor labels also appear in unrelated `case` blocks (configuration, help message, reports, webhooks, certificate names). Do not rely on line numbers; they drift with every release. The helper prints the live ranges.

**Region A — list-item array**

- Start: the line exactly `<arrayName>='` (column 1). Each array name occurs once.
- End: the first following line that is exactly `'`.
- Rows are the lines starting (after indentation) with `{"title"`. `[` and `]` sit on their own lines in every shipped array.
- Array names are inconsistent; take them from the **Artifact anchors per MDM** table in `health-checks.md`.
- Some shipped rows carry trailing whitespace after `},` (Kandji Cortex and Netskope). Strip trailing whitespace before handling commas.

**Region B — health-check case branch**

1. Find the header line starting with `# Generate Health Checks based on Operation Mode and MDM Vendor`.
2. After it, find the first line exactly `        case ${mdmVendor} in` (8 spaces).
3. After that, find the first line exactly `            "<Label>" )` (12 spaces), or `            * )` for generic.
4. End: the first following line exactly `                ;;` (16 spaces). It must come before the block's `        esac`.

Region A always precedes Region B in the file.

Leave `developmentListitemJSON` and the direct Development calls untouched; they keep the source defaults.

## Building replacement text

- **Rows:** copy each row verbatim from the chosen MDM's current array in the source. If that array lacks the check, copy it from another MDM's array. Only then fall back to the `health-checks.md` templates. Change only `NN`.
- **Org-specific text:** replace it with placeholders. The shipped A9 Palo Alto GlobalProtect subtitle becomes `Virtual Private Network (VPN) connection to <YOUR_ORGANIZATION_NETWORK>`.
- **Vendor-specific text:** outside Jamf Pro, the H7 Clock Skew subtitle becomes `Checks local clock offset against time.apple.com` (the shipped Jamf Pro row says "before Jamf Pro inventory submission"). Review other borrowed rows for vendor wording.
- **Icons:** `SF=NN.circle`, where `NN` = index + 1, zero-padded (`01` … `42`).
- **Shell splices:** keep `'"${organizationColorScheme}"'` and `'${mdmVendor}'` exactly.
- **Commas:** put a comma after every row except the last, with no trailing whitespace after the final `}`.
- **Calls:** write one `runConfiguredHealthCheck "<index>" <function> [args]` per row, in row order, with indices starting at `0`. Take function names and arguments from the master table in `health-checks.md`; never guess them.
- **Order constraints:**
  - `updateComputerInventory` (F1) is always last.
  - M15 Network Quality Test is the last row, or directly before F1. This is required by the Client-Side Cache (see check 5).
  - If F1 is selected without M15, warn the admin and ask: keep M15 directly before F1, or drop F1.
- **Indentation:**

| Line | Spaces |
|---|---|
| Array row | 4 |
| Branch label | 12 |
| Branch call and `;;` | 16 |

## Manual build (fallback)

Run the three blocks below in one zsh session from the repository root. First, write the chosen rows (verbatim source lines, any icon number) to `${work}/rows.txt`. Then write each row's `<function> [args]` to `${work}/calls.txt`, in the same order, with no index and no leading spaces.

```zsh
source="Mac-Health-Check.zsh"
slug="microsoft-intune"; arrayName="microsoftMdmListitemJSON"; branchLabel='"Microsoft Intune" )'; mdmVendor="Microsoft Intune"   # generic: branchLabel='* )'; mdmVendor="None"
work=$( mktemp -d )
mkdir -p Artifacts
sourceHash=$( shasum -a 256 "${source}" | awk '{ print $1 }' )

function findAnchors() {
    # findAnchors <file>; sets aStart aEnd firstRow lastRow bStart bEnd
    aStart=$( awk -v a="${arrayName}='" '$0 == a { print NR; exit }' "${1}" )
    aEnd=$( awk -v s="${aStart}" -v q="'" 'NR > s && $0 == q { print NR; exit }' "${1}" )
    firstRow=$( awk -v s="${aStart}" -v e="${aEnd}" 'NR > s && NR < e && /^[[:space:]]*\{"title"/ { print NR; exit }' "${1}" )
    lastRow=$( awk -v s="${aStart}" -v e="${aEnd}" 'NR > s && NR < e && /^[[:space:]]*\{"title"/ { n = NR } END { print n }' "${1}" )
    local hdr=$( awk 'index($0, "# Generate Health Checks based on Operation Mode and MDM Vendor") == 1 { print NR; exit }' "${1}" )
    local caseLine=$( awk -v h="${hdr}" 'NR > h && $0 == "        case ${mdmVendor} in" { print NR; exit }' "${1}" )
    bStart=$( awk -v c="${caseLine}" -v l="            ${branchLabel}" 'NR > c && $0 == l { print NR; exit }' "${1}" )
    bEnd=$( awk -v s="${bStart}" 'NR > s && $0 == "                ;;" { print NR; exit }' "${1}" )
}
findAnchors "${source}"
srcAStart=${aStart} srcAEnd=${aEnd} srcBStart=${bStart} srcBEnd=${bEnd}
print "A: ${aStart}-${aEnd} (rows ${firstRow}-${lastRow})  B: ${bStart}-${bEnd}"   # every value must be non-empty and aEnd < bStart
```

```zsh
stamp=$( date +%Y-%m-%d-%H%M%S )
artifact="${work}/Mac-Health-Check_${slug}_${stamp}.zsh"

# Region A: keep the lines around the rows; renumber rows from index 0 (BEGIN { n = 0 } avoids an empty first index)
{
    sed -n "${aStart},$(( firstRow - 1 ))p" "${source}"
    awk 'BEGIN { n = 0 }
         { sub(/[[:space:]]+$/, ""); sub(/,$/, ""); rows[n++] = $0 }
         END { for (i = 0; i < n; i++) { r = rows[i]; sub(/SF=[0-9N]+\.circle/, sprintf("SF=%02d.circle", i + 1), r); print r ((i < n - 1) ? "," : "") } }' "${work}/rows.txt"
    sed -n "$(( lastRow + 1 )),${aEnd}p" "${source}"
} > "${work}/regionA.txt"

# Region B: label, renumbered calls, ;;
{
    sed -n "${bStart}p" "${source}"
    awk 'BEGIN { n = 0 } NF { printf "                runConfiguredHealthCheck \"%d\" %s\n", n++, $0 }' "${work}/calls.txt"
    sed -n "${bEnd}p" "${source}"
} > "${work}/regionB.txt"

{
    sed -n "1,$(( aStart - 1 ))p" "${source}"
    cat "${work}/regionA.txt"
    sed -n "$(( aEnd + 1 )),$(( bStart - 1 ))p" "${source}"
    cat "${work}/regionB.txt"
    sed -n "$(( bEnd + 1 )),\$p" "${source}"
} > "${artifact}"
```

## Fallback when files cannot be written

If the AI cannot write files, print the intended artifact filename, the full artifact contents in one fenced `zsh` block, and the sidecar contents in a fenced `markdown` block. Then tell the admin to save both files under `Artifacts/` and run the helper, or the validation block below, on the saved file.

## Validation (run all; record each result in the sidecar)

Every check prints `PASS <n> …` or `FAIL <n> …`; `fail` ends non-zero if any check failed. Do not rely on `cmd && print PASS`, which prints nothing on failure, and do not rely on `set -e`, which does not stop on a failed `&&` chain.

| # | Check |
|---|---|
| 1 | `zsh -n` on the artifact |
| 2 | Edited array, with splices substituted, passes `jq` |
| 3a–3e | Rows = calls · indices `0..n-1` · icons `01..n` · F1 last or absent · M15 last, or directly before F1 |
| 4 | Every `diff` hunk falls inside source Region A or Region B |
| 5a–5c | Client-Side Cache replay: sanitized `zsh -n` · sanitized `jq` · no `jamf recon` text |
| 6 | `scriptVersion` equal in source and artifact |
| 7 | Source unchanged (SHA-256); `git diff --quiet -- Mac-Health-Check.zsh` as info |
| 8 | Artifact and sidecar paths git-ignored (`git check-ignore`) |
| 9 | Five-mode test run on a Mac enrolled in the chosen MDM (admin; pending) |

```zsh
fail=0
function passCheck() { print -r -- "PASS $*"; }
function failCheck() { print -r -- "FAIL $*"; fail=1; }
function arrayJsonFrom() {
    # arrayJsonFrom <file>: evaluate the anchored array with the shell splices substituted
    findAnchors "${1}"
    sed -n "${aStart},${aEnd}p" "${1}" > "${work}/array.zsh"
    organizationColorScheme="weight=semibold,colour=#000000" mdmVendor="${mdmVendor}" \
        zsh --no-rcs -c 'source "$1"; print -r -- "${(P)2}"' _ "${work}/array.zsh" "${arrayName}"
}
finalArtifact="Artifacts/${artifact:t}"; finalSidecar="${finalArtifact%.zsh}.md"

# 1. Syntax
if zsh -n "${artifact}"; then passCheck 1 "zsh -n"; else failCheck 1 "zsh -n"; fi

# 2. Array JSON
arrayJson=$( arrayJsonFrom "${artifact}" )
if print -r -- "${arrayJson}" | jq -e 'type == "array" and length > 0' >/dev/null 2>&1; then passCheck 2 "jq"; else failCheck 2 "jq"; arrayJson="[]"; fi

# 3. Alignment (re-anchor on the artifact; arrayJsonFrom ran in a subshell, so its anchors are gone)
findAnchors "${artifact}"
sed -n "$(( bStart + 1 )),$(( bEnd - 1 ))p" "${artifact}" > "${work}/artifactCalls.txt"
rows=$( print -r -- "${arrayJson}" | jq length ); calls=$( grep -c 'runConfiguredHealthCheck ' "${work}/artifactCalls.txt" )
if (( rows == calls && rows > 0 )); then passCheck 3a "rows=${rows} calls=${calls}"; else failCheck 3a "rows=${rows} calls=${calls}"; fi
if awk 'BEGIN { n = 0 } { gsub(/"/, "", $2); if ($2 != n "") bad = 1; n++ } END { exit bad }' "${work}/artifactCalls.txt"; then
    passCheck 3b "indices 0..$(( calls - 1 ))"; else failCheck 3b "indices not contiguous from 0"; fi
if print -r -- "${arrayJson}" | jq -e 'length > 0 and (to_entries | all(.[]; .key as $k | .value.icon | startswith("SF=" + (($k + 1) | tostring | if length < 2 then "0" + . else . end) + ".circle")))' >/dev/null; then
    passCheck 3c "icons 01..${rows}"; else failCheck 3c "icons do not match index + 1"; fi
lastTitle=$( print -r -- "${arrayJson}" | jq -r '.[-1].title' ); secondLastTitle=$( print -r -- "${arrayJson}" | jq -r '.[-2].title // ""' )
if { ! grep -q updateComputerInventory "${work}/artifactCalls.txt" || { tail -1 "${work}/artifactCalls.txt" | grep -q updateComputerInventory && [[ "${lastTitle}" == "Computer Inventory" ]]; }; }; then
    passCheck 3d "F1 last or absent"; else failCheck 3d "F1 not last"; fi
if ! print -r -- "${arrayJson}" | jq -e 'any(.[]; .title == "Network Quality Test")' >/dev/null; then
    if print -r -- "${arrayJson}" | jq -e 'any(.[]; .title == "Computer Inventory")' >/dev/null; then failCheck 3e "F1 without M15"; else passCheck 3e "M15 and F1 absent"; fi
elif [[ "${lastTitle}" == "Network Quality Test" ]] || [[ "${lastTitle}" == "Computer Inventory" && "${secondLastTitle}" == "Network Quality Test" ]]; then
    passCheck 3e "M15 last or directly before F1"
else
    failCheck 3e "M15 is not last or directly before F1 (last: ${secondLastTitle}, ${lastTitle})"
fi

# 4. Diff scope (source ranges)
diff "${source}" "${artifact}" > "${work}/artifact.diff"
if awk -v a1="${srcAStart}" -v a2="${srcAEnd}" -v b1="${srcBStart}" -v b2="${srcBEnd}" '
    /^[0-9]/ { split($0, p, /[acd]/); n = split(p[1], r, ","); lo = r[1]; hi = (n > 1) ? r[2] : r[1]
               if (!((lo >= a1 && hi <= a2) || (lo >= b1 && hi <= b2))) bad = 1 }
    END { exit bad }' "${work}/artifact.diff"; then passCheck 4 "diff scope"; else failCheck 4 "hunk outside the two regions"; fi
grep -E '^[0-9]' "${work}/artifact.diff"   # hunk headers for the sidecar diff summary

# 5. Client-Side Cache replay (copied from installClientSideScript in 5.0.0b1; the helper extracts it live)
cp "${artifact}" "${work}/client.zsh"
sed -i '' 's|operationMode="${4:-"Self Service"}"|operationMode="${4:-"Silent"}"|' "${work}/client.zsh"
awk '
    /^# Update Computer Inventory$/ { skipInventoryFunction=1; next }
    /^# Program$/ { if (skipInventoryFunction == 1) { skipInventoryFunction=0; print; next } }
    skipInventoryFunction == 1 { next }
    /"title" : "Computer Inventory"/ { next }
    /updateComputerInventory/ { next }
    /jamf[[:space:]]recon/ { next }
    { print }
' "${work}/client.zsh" > "${work}/sanitized.zsh"
sed -i '' '/"title" : "Network Quality Test"/ s/},$/}/' "${work}/sanitized.zsh"   # BSD sed, as in the script
if zsh -n "${work}/sanitized.zsh"; then passCheck 5a "sanitized zsh -n"; else failCheck 5a "sanitized zsh -n"; fi
if arrayJsonFrom "${work}/sanitized.zsh" | jq -e 'type == "array" and length > 0' >/dev/null 2>&1; then passCheck 5b "sanitized jq"; else failCheck 5b "sanitized jq"; fi
if grep -q "jamf recon" "${work}/sanitized.zsh"; then failCheck 5c "jamf recon text remains"; else passCheck 5c "no jamf recon"; fi

# 6. scriptVersion
if [[ "$( grep -m1 '^scriptVersion=' "${source}" )" == "$( grep -m1 '^scriptVersion=' "${artifact}" )" ]]; then passCheck 6 "scriptVersion unchanged"; else failCheck 6 "scriptVersion differs"; fi

# 7. Source untouched
if [[ "$( shasum -a 256 "${source}" | awk '{ print $1 }' )" == "${sourceHash}" ]]; then passCheck 7 "source unchanged"; else failCheck 7 "source changed"; fi
git diff --quiet -- "${source}" && print "INFO 7 git diff clean" || print "INFO 7 source has local changes vs HEAD"

# 8. Artifacts git-ignored
if git check-ignore -q "${finalArtifact}" && git check-ignore -q "${finalSidecar}"; then passCheck 8 "git-ignored"; else failCheck 8 "not git-ignored"; fi

# Result: move into Artifacts/ only when every check passed
if (( fail == 0 )); then mv "${artifact}" "${finalArtifact}" && print "RESULT: PASS ${finalArtifact}"; else print "RESULT: FAIL; failed build kept at ${artifact}"; fi
```

A failure in check 5 means the cached nightly `Silent` copy would exit on invalid JSON. Fix the row order (M15 last, or directly before F1), then rebuild. Remove `${work}` once the artifact passes.

## Test run (check 9; admin, on one Mac)

```zsh
sudo zsh ./Artifacts/<file>.zsh "" "" "" "Self Service"
```

- Use a Mac **enrolled in the chosen MDM**. For Other / MDM-agnostic, use a Mac whose `serverURL` matches no known MDM; an unenrolled Mac qualifies, logs `Unknown MDM vendor: None`, and fails M4 Apple Push Notification service as expected. The script sets `mdmVendor` from the enrolled `serverURL` at runtime. On a Mac enrolled elsewhere, the artifact runs that MDM's unedited branch; for example, an Intune artifact on a Jamf Pro Mac still runs Electron Corner Mask, Jamf Hosts, and `jamf recon`.
- Repeat with `Silent`, `Debug`, `Development`, and `Test` as Parameter 4. `Development` runs the shipped `developmentListitemJSON` subset, not the selection.
- Confirm that the dropped checks do not appear in the log and that the dialog row count matches the sidecar.
- Non-`Silent` runs call `installClientSideScript`. They replace the test Mac's `/Library/Management/<reverseDomainNameNotation>/MHC.zsh` and LaunchDaemon with a sanitized copy of the artifact. Re-run the production policy afterwards to restore them.
- The first `Self Service` run after a check-set change is a full run (`check_set_mismatch`); that is expected.

## Sidecar template

The helper writes this sidecar on exit `0`. Write it by hand only on the manual path. `<MDM>` is the display name (`Other / MDM-agnostic` for `generic`, `Kandji / Iru` for `kandji`), never `None`. Titles are resolved (`Microsoft Intune MDM Profile`, not `'${mdmVendor}' MDM Profile`).

Disabled reasons:

| Reason | When |
|---|---|
| `Admin choice` | In the shipped default, dropped by the admin |
| `<MDM> only` | Restricted to another MDM (Jamf Pro: M5, M6, M13, A6–A9, F1; Mosyle: M7) |
| `Needs a known MDM vendor` | M1 or M3 on Other |
| `Not default` | Available, not in the shipped default |

Other MDMs' A5 agent apps are grouped into one A5 row. A10 is listed as `Jamf Pro only`, or on Jamf Pro as `Not default (custom)`.

```markdown
# Mac Health Check artifact — <MDM> — <YYYY-MM-DD-HHMMSS>

- Artifact: `Artifacts/<basename>.zsh`
- Source: `Mac-Health-Check.zsh` (`scriptVersion` <x.y.z>, unchanged)
- MDM: <MDM> (`mdmVendor` = `<value>`, slug `<slug>`)
- Built by: `scripts/build-artifact.zsh` <version>

## Enabled (<n>)
| Index | ID | Title | Report key |
|---|---|---|---|

## Disabled (<m>)
| ID | Title | Reason |
|---|---|---|

## Report keys removed vs shipped <MDM> default
- `<key>` (<title>)

## Report keys added vs shipped <MDM> default
- None

## Dependency notes
- [all] … *(tags as in SKILL.md 4e: `[all]`, `[C8]`, `[C13]`, `[H6]`, `[vendor]`, `[Addigy]`, `[Kandji]`, `[generic]`, `[Jamf]`, `[A9]`, `[A4]`)*

## Validation
| # | Check | Result |
|---|---|---|
| 1 | zsh -n | PASS/FAIL |
| 2 | Array jq | PASS/FAIL |
| 3a–3e | Rows = calls, indices, icons, F1 last or absent, M15 last or before F1 | PASS/FAIL |
| 4 | Diff limited to two regions | PASS/FAIL |
| 5a–5c | Client-Side Cache simulation | PASS/FAIL |
| 6 | scriptVersion unchanged | PASS/FAIL |
| 7 | Source unchanged | PASS/FAIL |
| 8 | Artifacts git-ignored | PASS/FAIL/SKIP |
| 9 | Five-mode test run on a Mac enrolled in <MDM> *(Other: a Mac whose `serverURL` matches no known MDM)* | Pending (admin) |

## Diff summary
- Region A `<arrayName>`: source lines <a1>-<a2>, <old> rows → <new> rows
- Region B `<label>`: source lines <b1>-<b2>, <old> calls → <new> calls
- Hunk headers: `<diff output>`

## Next steps
1. Review this sidecar and the diff; add organization-specific notes below.
2. Run the five-mode test on one Mac enrolled in <MDM>; re-run the production policy afterwards to restore the Client-Side Cache copy and LaunchDaemon.
3. Deploy the artifact as the MDM script; keep `scriptVersion` unchanged.
4. Expect the first Self Service run to be a full run (`check_set_mismatch`).
```
