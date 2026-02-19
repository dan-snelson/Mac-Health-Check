# Mac Health Check (3.0.0)

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

1. Decode to a target path
2. Make the decoded file executable
3. Execute it with `zsh`

#### Default behavior

- Default source file: `../Mac-Health-Check.zsh`
- Default decoded target path: `/var/tmp/MHC.zsh`
- Output filename format: `<source_filename>_self-extracting-<YYYY-MM-DD-HHMMSS>.sh`

#### Commands

Run from this directory:

```zsh
cd /Users/danksnelson/Documents/GitHub/dan-snelson/Mac-Health-Check/Resources
```

Use defaults:

```zsh
./createSelfExtracting.zsh
```

Specify a source file:

```zsh
./createSelfExtracting.zsh --file ../Mac-Health-Check.zsh
```

Specify source and extraction target path:

```zsh
./createSelfExtracting.zsh --file ../Mac-Health-Check.zsh --target /var/tmp/MHC.zsh
```

Show help:

```zsh
./createSelfExtracting.zsh --help
```

---

### `Makefile` Usage

#### What it does

The `Makefile` packages `../Mac-Health-Check.zsh` as:

- Install path: `/usr/local/bin/Mac-Health-Check`
- Package name format: `Mac-Health-Check-<scriptVersion>-<YYYY-MM-DD-HHMMSS>.pkg`
- Post-install behavior: runs `postInstall.zsh` (copied as `postinstall`)

#### Commands

Run from this directory:

```zsh
cd /Users/danksnelson/Documents/GitHub/dan-snelson/Mac-Health-Check/Resources
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
