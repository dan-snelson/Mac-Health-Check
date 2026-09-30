# Mac Health Check (3.2.0)

## Resources Build Utilities

This directory contains two helper tools used to package or wrap `Mac-Health-Check.zsh`:

- `createSelfExtracting.zsh`: Creates a self-extracting shell script that embeds a Base64 copy of a source file.
- `Makefile`: Builds (and optionally signs) a macOS installer package (`.pkg`).

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

Beginning in `5.0.0b5`, the wrapper no longer writes to the fixed `/var/tmp/MHC.zsh` path (which a local user could pre-create and rewrite before root executed it) and the `--target` option has been removed. Regenerate any previously deployed self-extracting scripts.

#### Default behavior

- Default source file: `../Mac-Health-Check.zsh`
- Decoded path: unique, root-only `/var/tmp/MHC-selfExtracting.XXXXXX/<source_filename>`, removed on exit
- Output filename format: `<source_filename>_self-extracting-<YYYY-MM-DD-HHMMSS>.sh`

#### Commands

Run from this directory:

```zsh
cd /Users/dan/Documents/GitHub/dan-snelson/Mac-Health-Check/Resources
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

- Install path: `/Library/Management/org.churchofjesuschrist/Mac-Health-Check.zsh` (root-owned; beginning in `5.0.0b5`, the payload no longer uses `/usr/local/bin`, which Homebrew can make user-writable)
- Package name format: `Mac-Health-Check-<scriptVersion>-<YYYY-MM-DD-HHMMSS>.pkg`
- Post-install behavior: runs `postInstall.zsh` (copied as `postinstall`), which executes the payload with `/bin/zsh --no-rcs` in `Self Service` mode

#### Commands

Run from this directory:

```zsh
cd /Users/dan/Documents/GitHub/dan-snelson/Mac-Health-Check/Resources
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

Remove all build artifacts under `/var/tmp/Mac-Health-Check`:

```zsh
make distclean
```

### Output Locations

- Generated `.pkg` files: this `Resources` directory
- Temporary build paths: `/var/tmp/Mac-Health-Check/`
- Self-extracting script output: current working directory where `createSelfExtracting.zsh` is run
