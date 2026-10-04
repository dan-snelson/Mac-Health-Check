# Mac Health Check (5.0.0)

## Resources Build Utilities

This directory contains three helper files used to package or wrap `Mac-Health-Check.zsh`:

- `createSelfExtracting.zsh`: Creates a self-extracting shell script that embeds a Base64 copy of a source file.
- `Makefile`: Builds (and optionally signs) a macOS installer package (`.pkg`).
- `postInstall.zsh`: The package's `postinstall` script; runs the installed payload in `Self Service` mode.

It also holds reference material: [`Splunk-Dashboard-Reference.md`](Splunk-Dashboard-Reference.md) and its exported Splunk dashboard JSON, `mac-health-check-fleet-policies.yml` (sample Fleet policies), [`MacHealthCheck-Inspect-Mode/`](MacHealthCheck-Inspect-Mode/README.md) (Inspect Mode screenshots and demo assets), and `projectPlan.md` (historical `3.0.0` architecture notes).

### Prerequisites

- macOS with `zsh`, `make`, and `base64`
- Xcode Command Line Tools (for `pkgbuild`; required for `make pkg`)
- Developer ID Installer certificate in Keychain (only required for `make sign`)

---

### `createSelfExtracting.zsh` Usage

#### What it does

`createSelfExtracting.zsh` Base64-encodes a script, writes a new self-extracting `.sh` file, and configures that output to:

1. Create a root-only (`umask 077`) per-run directory with `mktemp -d /var/tmp/MHC-selfExtracting.XXXXXX`
2. Decode the embedded script into that directory
3. Execute it with `/bin/zsh --no-rcs`, forwarding all arguments (for example, Jamf Pro Parameters 1-11)
4. Remove the directory on exit

Beginning in `5.0.0`, the wrapper no longer writes to the fixed `/var/tmp/MHC.zsh` path (which a local user could pre-create and rewrite before root executed it) and the `--target` option has been removed. Regenerate any previously deployed self-extracting scripts.

Because the decoded copy is a root-owned file in a root-only directory under sticky `/var/tmp`, `Self Service`, `Debug` and `Silent` + `splunkOperationMode=production` runs from a self-extracting wrapper install the Client-Side Cache copy and LaunchDaemon, just like runs from your MDM's script cache. Reporting secrets still come only from `MacHealthCheck-Secrets.plist`.

#### Default behavior

- Default source file: `../Mac-Health-Check.zsh`
- Decoded path: unique, root-only `/var/tmp/MHC-selfExtracting.XXXXXX/<source_filename>`, removed on exit
- Output filename format: `<source_filename>_self-extracting-<YYYY-MM-DD-HHMMSS>.sh`

#### Commands

Run from this directory:

```zsh
cd /path/to/Mac-Health-Check/Resources
```

Use defaults:

```zsh
./createSelfExtracting.zsh
```

Specify a source file:

```zsh
./createSelfExtracting.zsh --file ../Mac-Health-Check.zsh
```

Show help:

```zsh
./createSelfExtracting.zsh --help
```

---

### `Makefile` Usage

#### What it does

The `Makefile` packages `../Mac-Health-Check.zsh` as:

- Install path: `/Library/Management/org.churchofjesuschrist/Mac-Health-Check.zsh` (root-owned; beginning in `5.0.0`, the payload no longer uses `/usr/local/bin`, which Homebrew can make user-writable)
- Package name format: `Mac-Health-Check-<scriptVersion>-<YYYY-MM-DD-HHMMSS>.pkg`
- Post-install behavior: runs `postInstall.zsh` (copied as `postinstall`), which executes the payload with `/bin/zsh --no-rcs` in `Self Service` mode

Because that installed payload is a trusted root-owned path, the post-install run:

- Shows the `Self Service` dialog (and detached Inspect summary) to the logged-in user while the package installs
- Installs the Client-Side Cache copy (`/Library/Management/org.churchofjesuschrist/MHC.zsh`) and its `org.churchofjesuschrist.MHC` LaunchDaemon
- Passes no Script Parameters, so `splunkOperationMode` is `test` (local report only) and webhook messages (Jamf Pro only) are sent only when `MacHealthCheck-Secrets.plist` already supplies a webhook URL

If you change `reverseDomainNameNotation` in `Mac-Health-Check.zsh`, also update `INSTALL_DIR` in `Makefile` and the payload path in `postInstall.zsh`.

#### Commands

Run from this directory:

```zsh
cd /path/to/Mac-Health-Check/Resources
```

Show available targets:

```zsh
make help
```

Build package (default target):

```zsh
make
# or
make pkg
```

Sign latest package (requires `CERT_NAME`):

```zsh
export CERT_NAME='Developer ID Installer: Your Name (TEAMID)'
make sign
```

Clean temporary build directories only:

```zsh
make temp-clean
```

Clean generated `.pkg` and temp files:

```zsh
make clean
```

Remove all build artifacts under `$TMPDIR/Mac-Health-Check`:

```zsh
make distclean
```

### Output Locations

- Generated `.pkg` files: this `Resources` directory (git-ignored as `Resources/*.pkg`)
- Temporary build paths: `$TMPDIR/Mac-Health-Check/` (per-user and private on macOS; falls back to `/var/tmp/Mac-Health-Check/` only when `TMPDIR` is unset). Beginning in `5.0.0`, `make` refuses a staging directory it does not own (mode `700`), so another local user cannot pre-create it and swap files before `pkgbuild`
- Self-extracting script output: current working directory where `createSelfExtracting.zsh` is run (git-ignored as `*_self-extracting-*.sh`)
