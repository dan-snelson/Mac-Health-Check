# Makefile for building [Mac Health Check](https://snelson.us/mhc) .PKG installer
# Inspired by [erase-install Makefile](https://github.com/grahampugh/erase-install/blob/main/Makefile); thanks, @grahampugh!

# See: [MDM Configuration](https://github.com/dan-snelson/Mac-Health-Check/wiki/99.-MDM-Configuration#mdm-configuration)

NAME = Mac-Health-Check
IDENTIFIER = us.snelson.$(NAME)
DATESTAMP := $(shell date '+%Y-%m-%d-%H%M%S')
SCRIPT_VERSION := $(shell sed -n 's/.*scriptVersion="\([^"]*\)".*/\1/p' ../Mac-Health-Check.zsh)
PKG = $(NAME)-$(SCRIPT_VERSION)-$(DATESTAMP).pkg
SIGNED_PKG = $(PKG:%.pkg=%-signed.pkg)
TMPBASE = /var/tmp/$(NAME)
ROOT = $(TMPBASE)/root-$(DATESTAMP)# Temp package root
SCRIPTS = $(TMPBASE)/scripts-$(DATESTAMP)# Temp scripts dir for pkgbuild

# Sources relative to repo root (Makefile is in Resources/, so use ../)
SCRIPT = ../Mac-Health-Check.zsh

# Default target
all: pkg

# Create package root and copy files
$(ROOT):
	@echo "Preparing package root in $(ROOT)..."
	mkdir -p $(ROOT)/usr/local/bin
	chmod 755 $(ROOT)/usr/local/bin  # Ensure bin dir is executable
	# Copy main script (rename to drop .zsh for clean exec)
	cp $(SCRIPT) "$(ROOT)/usr/local/bin/$(NAME)"
	chmod 755 "$(ROOT)/usr/local/bin/$(NAME)"
	@echo "Main script copied to $(ROOT)."

# Prepare scripts dir (copy postInstall.zsh from current dir)
$(SCRIPTS): postInstall.zsh
	@echo "Preparing scripts in $(SCRIPTS)..."
	mkdir -p $(SCRIPTS)
	cp postInstall.zsh $(SCRIPTS)/postinstall
	chmod 755 $(SCRIPTS)/postinstall
	@echo "Post-install script copied to $(SCRIPTS)/."

# Build the .pkg using pkgbuild (flat pkg with root + scripts); output to current dir
pkg: $(ROOT) $(SCRIPTS)
	@echo "Building $(PKG)..."
	pkgbuild --root "$(ROOT)" --identifier "$(IDENTIFIER)" --version "$(SCRIPT_VERSION)" --ownership recommended --install-location / --scripts "$(SCRIPTS)" "$(PKG)"
	@echo "Package built: $(PKG) (in Resources/)"
	@echo "To install: sudo installer -pkg $(PKG) -target /"
	@echo "Post-install will auto-run /usr/local/bin/$(NAME) (default: interactive test mode)."
	# Optional: Auto-clean temp dirs after build (uncomment if desired)
	# $(MAKE) temp-clean

# Sign the latest .pkg (requires CERT_NAME env var)
sign:
	@if [ -z "$$CERT_NAME" ]; then \
		echo "Error: Set CERT_NAME env var (e.g., export CERT_NAME='Developer ID Installer: Your Name (TEAMID)')"; \
		exit 1; \
	fi; \
	if [ -f "$(PKG)" ]; then \
		productsign --sign "$$CERT_NAME" "$(PKG)" "$(SIGNED_PKG)"; \
		echo "Signed: $(SIGNED_PKG)"; \
		echo "Verify: pkgutil --check-signature $(SIGNED_PKG)"; \
	else \
		echo "No .pkg found—run 'make pkg' first."; \
		exit 1; \
	fi

# Clean temp build artifacts only (keeps .pkg)
temp-clean:
	@echo "Cleaning temp dirs in $(TMPBASE)..."
	rm -rf $(ROOT) $(SCRIPTS)

# Clean everything (temp + .pkg)
clean: temp-clean
	@echo "Cleaning .pkg from Resources/..."
	rm -f *.pkg *-signed.pkg

# Full clean: Everything under /var/tmp/$(NAME)/
distclean: clean
	@echo "Full cleanup: Removing all under $(TMPBASE)/..."
	rm -rf $(TMPBASE)

# Help target (self-documenting)
help:
	@echo "$(NAME) Makefile (run from Resources/)"
	@echo "Targets:"
	@echo "  all      : Build the .pkg (default)"
	@echo "  pkg      : Build $(NAME)-<SCRIPT_VERSION>-<TIMESTAMP>.pkg in Resources/"
	@echo "  sign     : Sign the .pkg (set CERT_NAME env var)"
	@echo "  temp-clean : Remove temp dirs only (keeps .pkg)"
	@echo "  clean    : Remove temp + .pkg"
	@echo "  distclean: Nuke all under /var/tmp/$(NAME)/"
	@echo "  help     : Show this help"
	@echo ""
	@echo "Requirements: Xcode Command Line Tools (for pkgbuild)."
	@echo "Notes: Builds in /var/tmp/$(NAME)/ for cleanliness; .pkg outputs to Resources/."
	@echo "       Extracts version from ../Mac-Health-Check.zsh (scriptVersion var)."
	@echo "       Main script installed as /usr/local/bin/$(NAME) (Zsh-compatible)."
	@echo "       .pkg filename uses script version + current timestamp."
	@echo "       Post-install auto-runs the script (edit postInstall.zsh for custom args)."
	@echo "Optional: For signing, 'productsign --sign \"Developer ID Installer\" $(PKG) $(SIGNED_PKG)'."
	@echo "         Add preinstall script to Resources/ as 'preInstall.zsh' and update $(SCRIPTS) target to copy it too."

.PHONY: all pkg sign temp-clean clean distclean help