# Mac Health Check — Artifact Procedure

Companion reference for the `mac-health-check-selector` skill. It describes how to write an MDM-specific, date-stamped copy of `Mac-Health-Check.zsh` into `Artifacts/` and how to validate it. Derived from `Mac-Health-Check.zsh` `5.0.0b1`. When this file and the script disagree, the script wins.

The procedure is deterministic: find anchor lines, replace line ranges, validate. Any AI or human can follow it. The zsh snippets are optional helpers, not requirements.

## Contract

- Never modify `Mac-Health-Check.zsh` in place. Read it; write only to `Artifacts/`.
- The artifact is an unmodified copy of the source with exactly two regions replaced (see **Regions**). If the admin's selection equals the MDM's shipped default, copy the source unchanged and say so in the sidecar.
- Leave `scriptVersion` unchanged. A version change triggers targeted-recheck `version_mismatch`.
- Build every artifact from the untouched source, even when a session produces several.
- Use placeholders only (`<YOUR_WEBHOOK_URL>`, `<YOUR_ORGANIZATION_NETWORK>`, …). Never write real organization data.

## Naming

```text
Artifacts/Mac-Health-Check_<mdm-slug>_<YYYY-MM-DD-HHMMSS>.zsh
Artifacts/Mac-Health-Check_<mdm-slug>_<YYYY-MM-DD-HHMMSS>.md          # sidecar
Artifacts/Mac-Health-Check_<mdm-slug>_<YYYY-MM-DD-HHMMSS>_development.zsh   # Development preset
```

- Timestamp: local time, `date +%Y-%m-%d-%H%M%S`.
- Slugs: `jamf-pro`, `fleet`, `jumpcloud`, `microsoft-intune`, `mosyle`, `kandji`, `addigy`, `filewave`, `generic`.
- `Artifacts/` sits next to the source script. Create it if missing. It is git-ignored except `Artifacts/README.md`.

## Regions

Anchor on exact whole lines, never on label text alone. `"Jamf Pro" )` and the other vendor labels also appear in unrelated `case` blocks (configuration, help message, reports, webhooks, certificate names).

### MDM presets (`Self Service`, `Silent`, `Debug`, `Test`)

**Region A — list-item array**

- Start: the line exactly `<arrayName>='` (column 1). Each array name occurs once.
- End: the first following line that is exactly `'`.
- Array names are inconsistent; take them from the **Artifact anchors per MDM** table in `health-checks.md`.
- The Kandji array closes `]` on its last row instead of its own line; the end anchor still holds. Always write replacements with `[` and `]` on their own lines.

**Region B — health-check case branch**

1. Find the header line starting with `# Generate Health Checks based on Operation Mode and MDM Vendor`.
2. After it, find the first line exactly `        case ${mdmVendor} in` (8 spaces).
3. After that, find the first line exactly `            "<Label>" )` (12 spaces), or `            * )` for generic.
4. End: the first following line exactly `                ;;` (16 spaces). It must come before the block's `esac`.

Region A always precedes Region B in the file.

### Development preset

**Region A′ — `developmentListitemJSON`**

- After the header `# Generate dialogJSONFile based on Operation Mode and MDM Vendor`, start at the line exactly `    developmentListitemJSON='` (4 spaces).
- End: the first following line exactly `    '`.

**Region B′ — direct Development calls**

- After the **Generate Health Checks** header, locate `if [[ "${operationMode}" == "Development" ]]; then`.
- Replace only the lines strictly between `    # set -x` and `    # set +x`. Keep both comment lines.

Leave the MDM arrays and branches untouched for Development artifacts.

## Building replacement text

- **Rows:** copy each row verbatim from the chosen MDM's current array in the source. If that array lacks the check, copy it from another MDM's array. Only then fall back to the `health-checks.md` templates. Change only `NN`.
- **Org-specific text:** replace it with placeholders. The shipped A9 Palo Alto GlobalProtect subtitle becomes `Virtual Private Network (VPN) connection to <YOUR_ORGANIZATION_NETWORK>`.
- **Icons:** `SF=NN.circle`, where `NN` = index + 1, zero-padded (`01` … `42`).
- **Shell splices:** keep `'"${organizationColorScheme}"'` and `'${mdmVendor}'` exactly.
- **Commas:** put a comma after every row except the last, with no trailing whitespace after the final `}`.
- **Calls:** write one call per row, in row order. Take function names and arguments from the master table in `health-checks.md`; never guess them.
  - MDM branch call: `runConfiguredHealthCheck "<index>" <function> [args]`.
  - Development call: `<function> "<index>" [args]`. Each check function takes its index as the first argument.
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
| `developmentListitemJSON` row | 8 (`[` / `]` at 4) |
| Development call | 4 |

## Writing the artifact (optional helper)

```zsh
source="Mac-Health-Check.zsh"
slug="jamf-pro"; arrayName="jamfProListitemJSON"; branchLabel='"Jamf Pro" )'   # generic: branchLabel='* )'
stamp=$( date +%Y-%m-%d-%H%M%S )
artifact="Artifacts/Mac-Health-Check_${slug}_${stamp}.zsh"
work=$( mktemp -d )
mkdir -p Artifacts

aStart=$( awk -v a="${arrayName}='" '$0 == a { print NR; exit }' "${source}" )
aEnd=$( awk -v s="${aStart}" 'NR > s && $0 == "'"'"'" { print NR; exit }' "${source}" )
hdr=$( awk 'index($0, "# Generate Health Checks based on Operation Mode and MDM Vendor") == 1 { print NR; exit }' "${source}" )
caseLine=$( awk -v h="${hdr}" 'NR > h && $0 == "        case ${mdmVendor} in" { print NR; exit }' "${source}" )
bStart=$( awk -v c="${caseLine}" -v l="            ${branchLabel}" 'NR > c && $0 == l { print NR; exit }' "${source}" )
bEnd=$( awk -v s="${bStart}" 'NR > s && $0 == "                ;;" { print NR; exit }' "${source}" )
print "A: ${aStart}-${aEnd}  B: ${bStart}-${bEnd}"   # every value must be non-empty and aEnd < bStart

# Write the new Region A to ${work}/regionA.txt (array line through closing ') and the new Region B to ${work}/regionB.txt (label through ;;), then:
{
    sed -n "1,$(( aStart - 1 ))p" "${source}"
    cat "${work}/regionA.txt"
    sed -n "$(( aEnd + 1 )),$(( bStart - 1 ))p" "${source}"
    cat "${work}/regionB.txt"
    sed -n "$(( bEnd + 1 )),\$p" "${source}"
} > "${artifact}"
```

Development anchors (splice the same way; keep the `# set -x` / `# set +x` lines themselves):

```zsh
arrayName="developmentListitemJSON"
dHdr=$( awk 'index($0, "# Generate dialogJSONFile based on Operation Mode and MDM Vendor") == 1 { print NR; exit }' "${source}" )
aStart=$( awk -v h="${dHdr}" 'NR > h && $0 == "    developmentListitemJSON='"'"'" { print NR; exit }' "${source}" )
aEnd=$( awk -v s="${aStart}" 'NR > s && $0 == "    '"'"'" { print NR; exit }' "${source}" )
devIf=$( awk -v h="${hdr}" 'NR > h && $0 == "if [[ \"${operationMode}\" == \"Development\" ]]; then" { print NR; exit }' "${source}" )
setX=$( awk -v d="${devIf}" 'NR > d && $0 == "    # set -x" { print NR; exit }' "${source}" )
setPlusX=$( awk -v s="${setX}" 'NR > s && $0 == "    # set +x" { print NR; exit }' "${source}" )
# Region B′ = lines $(( setX + 1 )) through $(( setPlusX - 1 )); for check 4 use bStart=${setX} bEnd=${setPlusX}
```

## Fallback when files cannot be written

If the AI cannot write files, print the intended artifact filename, the full artifact contents in one fenced `zsh` block, and the sidecar contents in a fenced `markdown` block. Then tell the admin to save both files under `Artifacts/` and run the validation checks below.

## Validation (run all; record each result in the sidecar)

Recompute the anchors on the artifact (`aStartNew`, `aEndNew`, `bStartNew`, `bEndNew`) using the same commands with `"${artifact}"`.

1. **Syntax**

   ```zsh
   zsh -n "${artifact}" && print "PASS 1 zsh -n"
   ```

2. **Array JSON**: evaluate the edited array with the splices substituted, then parse it with `jq`.

   ```zsh
   sed -n "${aStartNew},${aEndNew}p" "${artifact}" > "${work}/array.zsh"
   arrayJson=$( organizationColorScheme="weight=semibold,colour=#000000" mdmVendor="Jamf Pro" \
       zsh -c 'source "$1"; print -r -- "${(P)2}"' _ "${work}/array.zsh" "${arrayName}" )
   print -r -- "${arrayJson}" | jq -e 'type == "array" and length > 0' >/dev/null && print "PASS 2 jq"
   ```

3. **Alignment**: row count equals call count, indices are contiguous, icons match, and F1 is last.

   ```zsh
   sed -n "${bStartNew},${bEndNew}p" "${artifact}" | grep 'runConfiguredHealthCheck ' > "${work}/calls.txt"
   rows=$( print -r -- "${arrayJson}" | jq length ); calls=$( wc -l < "${work}/calls.txt" | tr -d ' ' )
   [[ "${rows}" == "${calls}" ]] && print "PASS 3a rows=${rows} calls=${calls}"
   awk 'BEGIN { n = 0 } { gsub(/"/, "", $2); if ($2 != n "") bad = 1; n++ } END { exit bad }' "${work}/calls.txt" && print "PASS 3b indices 0..$(( calls - 1 ))"
   print -r -- "${arrayJson}" | jq -e 'to_entries | all(.[]; .key as $k | .value.icon | startswith("SF=" + (($k + 1) | tostring | if length < 2 then "0" + . else . end) + ".circle"))' >/dev/null && print "PASS 3c icons"
   ! grep -q updateComputerInventory "${work}/calls.txt" || tail -1 "${work}/calls.txt" | grep -q updateComputerInventory && print "PASS 3d F1 last or absent"
   ```

   For Development, build `calls.txt` from the non-comment lines between `# set -x` and `# set +x`, then run the same checks. The index is field `$2` there too, because the function name is `$1`:

   ```zsh
   awk -v s="${setX}" 'NR > s && $0 == "    # set +x" { exit } NR > s && !/^[[:space:]]*#/ && NF' "${artifact}" > "${work}/calls.txt"
   ```

   When evaluating `developmentListitemJSON` for check 2, extract lines `aStartNew` through `aEndNew` the same way. The 4-space indent does not affect `source`.

4. **Diff scope**: every hunk falls inside the source Region A or Region B range.

   ```zsh
   diff "${source}" "${artifact}" | awk -v a1="${aStart}" -v a2="${aEnd}" -v b1="${bStart}" -v b2="${bEnd}" '
       /^[0-9]/ { split($0, p, /[acd]/); n = split(p[1], r, ","); lo = r[1]; hi = (n > 1) ? r[2] : r[1]
                  if ((lo >= a1 && hi <= a2) || (lo >= b1 && hi <= b2)) print "ok  " $0; else { print "OUT " $0; bad = 1 } }
       END { exit bad }' && print "PASS 4 diff scope"
   diff "${source}" "${artifact}" | grep -E '^[0-9]'   # hunk headers for the sidecar diff summary
   ```

5. **Client-Side Cache simulation**: `installClientSideScript` in `Mac-Health-Check.zsh` sanitizes a copy of the running script. It drops the `"title" : "Computer Inventory"` row and every `updateComputerInventory` line, then strips a trailing comma only from the `Network Quality Test` row. Replay it (copied from `5.0.0b1`; keep it in sync with the script), then repeat check 2 on the result.

   ```zsh
   awk '
       /^# Update Computer Inventory$/ { skipInventoryFunction=1; next }
       /^# Program$/ { if (skipInventoryFunction == 1) { skipInventoryFunction=0; print; next } }
       skipInventoryFunction == 1 { next }
       /"title" : "Computer Inventory"/ { next }
       /updateComputerInventory/ { next }
       /jamf[[:space:]]recon/ { next }
       { print }
   ' "${artifact}" > "${work}/sanitized.zsh"
   sed -i '' '/"title" : "Network Quality Test"/ s/},$/}/' "${work}/sanitized.zsh"   # BSD sed, as in the script
   zsh -n "${work}/sanitized.zsh" && print "PASS 5a sanitized zsh -n"
   # Re-anchor ${arrayName} in ${work}/sanitized.zsh, then rerun check 2 → "PASS 5b sanitized jq"
   ```

   A failure here means the cached nightly `Silent` copy would exit on invalid JSON. Fix the row order (M15 last, or directly before F1). Do not ship the artifact until this passes.

6. **Test run (admin, on one Mac)**

   ```zsh
   sudo zsh ./Artifacts/<file>.zsh "" "" "" "Development"
   ```

   Repeat with `Self Service`, `Silent`, `Debug`, and `Test` as Parameter 4. The first `Self Service` run after a check-set change is a full run (`check_set_mismatch`); that is expected.

Remove `${work}` when done.

## Sidecar template

```markdown
# Mac Health Check artifact — <MDM> — <YYYY-MM-DD-HHMMSS>

- Artifact: `Artifacts/<basename>.zsh`
- Source: `Mac-Health-Check.zsh` (`scriptVersion` <x.y.z>, unchanged)
- MDM: <MDM> (`mdmVendor` = `<value>`, slug `<slug>`)
- operationMode (Parameter 4): <mode>
- Preset: <preset>

## Enabled (<n>)
| Index | ID | Title |
|---|---|---|

## Disabled
| ID | Title | Reason |
|---|---|---|

## Dependency notes
- …

## Validation
| # | Check | Result |
|---|---|---|
| 1 | `zsh -n` | PASS/FAIL |
| 2 | Array `jq` | PASS/FAIL |
| 3 | Rows = calls, indices, icons, F1 last | PASS/FAIL (rows=<n>, calls=<n>) |
| 4 | Diff limited to two regions | PASS/FAIL |
| 5 | Client-Side Cache simulation | PASS/FAIL |
| 6 | Five-mode test run | Pending (admin) |

## Diff summary
- Region A `<arrayName>`: source lines <a1>-<a2>, <old> rows → <new> rows
- Region B `<label>`: source lines <b1>-<b2>, <old> calls → <new> calls
- Hunk headers: `<diff output>`

## Next steps
1. Review this sidecar and the diff.
2. Run the five-mode test on one Mac.
3. Deploy the artifact as the MDM script; keep `scriptVersion` unchanged.
4. Expect the first Self Service run to be a full run (`check_set_mismatch`).
```
