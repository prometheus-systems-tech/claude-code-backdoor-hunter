# Copyright (c) 2026 Ross WD Cameron <rwd.cameron@prometheus-systems.co.za>
# Licensed under the GNU General Public License, version 2.
#
# Targets:
#   make hunter   build the C port into build/hunter
#   make native   build a package for the host OS (deb, rpm, FreeBSD pkg or macOS pkg)
#   make deb | rpm | freebsd | macos
#   make install  install into DESTDIR/PREFIX
#   make clean
#
# GNU make is required (FreeBSD: gmake native).

NAME       := claude-code-backdoor-hunter
VERSION    := 1.0.0
APP_ID     := org.backdoorhunter.Gui
MAINTAINER := Ross WD Cameron <rwd.cameron@prometheus-systems.co.za>
SUMMARY    := Read-only checker for the trojanized anthropic.claude-code extension
URL        := https://github.com/prometheus-systems-tech/claude-code-backdoor-hunter

UNAME := $(shell uname -s)

ifeq ($(UNAME),Linux)
  PREFIX ?= /usr
else
  PREFIX ?= /usr/local
endif

BUILD := build
STAGE := $(BUILD)/stage
DIST  := dist

OSID := $(shell . /etc/os-release 2>/dev/null && echo "$$ID $$ID_LIKE")

.PHONY: native install deb rpm freebsd macos windows clean hunter gui all

CC     ?= cc
CFLAGS ?= -O2
GTK_CFLAGS := $(shell pkg-config --cflags gtk4 2>/dev/null)
GTK_LIBS   := $(shell pkg-config --libs gtk4 2>/dev/null)

all: hunter gui

hunter: src/hunter.c
	mkdir -p $(BUILD)
	$(CC) -std=c99 -Wall -Wextra $(CFLAGS) -o $(BUILD)/hunter src/hunter.c

gui: src/gui.c
	@pkg-config --exists gtk4 || { echo "GTK 4 development files not found (apt install libgtk-4-dev / dnf install gtk4-devel)"; exit 1; }
	mkdir -p $(BUILD)
	$(CC) -std=gnu99 -Wall -Wextra -Wno-deprecated-declarations $(CFLAGS) $(GTK_CFLAGS) -o $(BUILD)/hunter-gui src/gui.c $(GTK_LIBS)

native:
ifeq ($(UNAME),Darwin)
	@$(MAKE) --no-print-directory macos
else ifeq ($(UNAME),FreeBSD)
	@$(MAKE) --no-print-directory freebsd
else ifeq ($(UNAME),Linux)
	@case " $(OSID) " in \
	  *" debian "*|*" ubuntu "*) $(MAKE) --no-print-directory deb ;; \
	  *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*) $(MAKE) --no-print-directory rpm ;; \
	  *) echo "Unsupported Linux distribution: $(OSID)"; exit 1 ;; \
	esac
else
	@echo "Unsupported OS: $(UNAME)"; exit 1
endif

# ---------------------------------------------------------------- install
install: hunter gui
	install -d $(DESTDIR)$(PREFIX)/libexec/$(NAME) $(DESTDIR)$(PREFIX)/bin \
	  $(DESTDIR)$(PREFIX)/share/applications \
	  $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps \
	  $(DESTDIR)$(PREFIX)/share/doc/$(NAME)
	install -m 755 $(BUILD)/hunter $(BUILD)/hunter-gui $(DESTDIR)$(PREFIX)/libexec/$(NAME)/
	ln -sf $(PREFIX)/libexec/$(NAME)/hunter $(DESTDIR)$(PREFIX)/bin/$(NAME)
	ln -sf $(PREFIX)/libexec/$(NAME)/hunter-gui $(DESTDIR)$(PREFIX)/bin/$(NAME)-gui
	install -m 644 packaging/$(APP_ID).desktop $(DESTDIR)$(PREFIX)/share/applications/
	install -m 644 packaging/$(APP_ID).svg $(DESTDIR)$(PREFIX)/share/icons/hicolor/scalable/apps/
	install -m 644 README.md LICENSE $(DESTDIR)$(PREFIX)/share/doc/$(NAME)/
	printf 'Copyright (c) 2026 %s\nLicensed under the GNU General Public License, version 2.\nSee LICENSE in this directory.\n' \
	  "$(MAINTAINER)" > $(DESTDIR)$(PREFIX)/share/doc/$(NAME)/copyright
	chmod 644 $(DESTDIR)$(PREFIX)/share/doc/$(NAME)/copyright

$(STAGE):
	rm -rf $(STAGE)
	$(MAKE) --no-print-directory install DESTDIR=$(CURDIR)/$(STAGE) PREFIX=$(PREFIX)

# ------------------------------------------------------------------ deb
deb:
	@command -v dpkg-deb >/dev/null || { echo "dpkg-deb not found (apt install dpkg-dev)"; exit 1; }
	rm -rf $(STAGE) && $(MAKE) --no-print-directory install DESTDIR=$(CURDIR)/$(STAGE) PREFIX=/usr
	install -d $(STAGE)/DEBIAN $(DIST)
	printf '%s\n' \
	  'Package: $(NAME)' \
	  'Version: $(VERSION)' \
	  'Section: utils' \
	  'Priority: optional' \
	  'Architecture: $(shell dpkg --print-architecture 2>/dev/null)' \
	  'Depends: libgtk-4-1, policykit-1' \
	  'Maintainer: $(MAINTAINER)' \
	  'Homepage: $(URL)' \
	  'Description: $(SUMMARY)' \
	  ' Checks for indicators of compromise from the SSH backdoor in the' \
	  ' trojanized anthropic.claude-code 2.1.313 extension. Includes a GTK 4' \
	  ' front end. Makes no changes to the system.' \
	  > $(STAGE)/DEBIAN/control
	dpkg-deb --root-owner-group --build $(STAGE) $(DIST)/$(NAME)_$(VERSION)_$(shell dpkg --print-architecture 2>/dev/null).deb
	@echo "Built $(DIST)/$(NAME)_$(VERSION)_$(shell dpkg --print-architecture 2>/dev/null).deb"

# ------------------------------------------------------------------ rpm
rpm:
	@command -v rpmbuild >/dev/null || { echo "rpmbuild not found (dnf install rpm-build)"; exit 1; }
	rm -rf $(STAGE) $(BUILD)/rpm && $(MAKE) --no-print-directory install DESTDIR=$(CURDIR)/$(STAGE) PREFIX=/usr
	install -d $(BUILD)/rpm $(DIST)
	printf '%s\n' \
	  'Name: $(NAME)' \
	  'Version: $(VERSION)' \
	  'Release: 1' \
	  'Summary: $(SUMMARY)' \
	  'License: GPL-2.0-only' \
	  'URL: $(URL)' \
	  'Requires: gtk4, polkit' \
	  '%description' \
	  'Checks for indicators of compromise from the SSH backdoor in the' \
	  'trojanized anthropic.claude-code 2.1.313 extension. Includes a GTK 4' \
	  'front end. Makes no changes to the system.' \
	  '%install' \
	  'cp -a $(CURDIR)/$(STAGE)/. %{buildroot}/' \
	  '%files' \
	  '/usr/bin/$(NAME)' \
	  '/usr/bin/$(NAME)-gui' \
	  '/usr/libexec/$(NAME)' \
	  '/usr/share/applications/$(APP_ID).desktop' \
	  '/usr/share/icons/hicolor/scalable/apps/$(APP_ID).svg' \
	  '/usr/share/doc/$(NAME)' \
	  > $(BUILD)/rpm/$(NAME).spec
	rpmbuild -bb --define "_topdir $(CURDIR)/$(BUILD)/rpm" \
	  --define "_rpmdir $(CURDIR)/$(DIST)" --define "_build_id_links none" \
	  --define "debug_package %{nil}" $(BUILD)/rpm/$(NAME).spec
	@echo "RPM written under $(DIST)/"

# -------------------------------------------------------------- FreeBSD
freebsd:
	@command -v pkg >/dev/null || { echo "pkg not found"; exit 1; }
	rm -rf $(STAGE) $(BUILD)/meta && $(MAKE) --no-print-directory install DESTDIR=$(CURDIR)/$(STAGE) PREFIX=/usr/local
	install -d $(BUILD)/meta $(DIST)
	printf '%s\n' \
	  'name: "$(NAME)"' \
	  'version: "$(VERSION)"' \
	  'origin: "security/$(NAME)"' \
	  'comment: "$(SUMMARY)"' \
	  'maintainer: "rwd.cameron@prometheus-systems.co.za"' \
	  'www: "$(URL)"' \
	  'prefix: "/usr/local"' \
	  'licenses: ["GPLv2"]' \
	  'licenselogic: "single"' \
	  'desc: "Checks for indicators of compromise from the SSH backdoor in the trojanized anthropic.claude-code extension. The GUI needs the gtk4 package."' \
	  > $(BUILD)/meta/+MANIFEST
	cd $(STAGE)/usr/local && find . \( -type f -o -type l \) | sed 's|^\./||' | sort > $(CURDIR)/$(BUILD)/plist
	pkg create -r $(CURDIR)/$(STAGE) -m $(BUILD)/meta -p $(BUILD)/plist -o $(DIST)
	@echo "Built package under $(DIST)/"

# ---------------------------------------------------------------- macOS
macos:
	@command -v pkgbuild >/dev/null || { echo "pkgbuild not found"; exit 1; }
	rm -rf $(STAGE) && $(MAKE) --no-print-directory install DESTDIR=$(CURDIR)/$(STAGE) PREFIX=/usr/local
	install -d $(DIST)
	pkgbuild --root $(STAGE) --identifier za.co.prometheus-systems.$(NAME) \
	  --version $(VERSION) --install-location / $(DIST)/$(NAME)-$(VERSION).pkg
	@echo "Built $(DIST)/$(NAME)-$(VERSION).pkg"

# ---------------------------------------------------------------- Windows 10+ installer
# Cross-compiles hunter.exe (zig cc or MinGW) and builds the NSIS setup.exe.
# Override WINCC / MAKENSIS for other toolchains, e.g. WINCC=x86_64-w64-mingw32-gcc MAKENSIS=makensis
WINCC ?= python3 -m ziglang cc -target x86_64-windows-gnu
NSISDIR ?= $(HOME)/tools/nsis-3.10
GTKWIN ?= $(HOME)/tools/gtk4-win/ucrt64
WINE ?= flatpak run --filesystem=$(CURDIR) --filesystem=$(HOME)/tools --command=wine org.winehq.Wine
MAKENSIS ?= $(WINE) $(NSISDIR)/makensis.exe

windows:
	install -d $(BUILD) $(DIST)
	@test -d $(GTKWIN) || python3 packaging/windows/fetch_gtk4.py $(dir $(GTKWIN))
	@mkdir -p $(GTKWIN)/lib-zig && for f in $(GTKWIN)/lib/*.dll.a; do b=$$(basename $$f .dll.a); ln -sf $$f $(GTKWIN)/lib-zig/$$b.a; done
	$(WINCC) -std=c99 -O2 -o $(BUILD)/hunter.exe src/hunter.c
	PKG_CONFIG_LIBDIR=$(GTKWIN)/lib/pkgconfig:$(GTKWIN)/share/pkgconfig sh -c \
	  '$(WINCC) -std=gnu11 -O2 -Wno-deprecated-declarations -mwindows -o $(BUILD)/hunter-gui.exe src/gui.c \
	   -L$(GTKWIN)/lib-zig $$(pkg-config --define-variable=prefix=$(GTKWIN) --cflags --libs gtk4)'
	python3 packaging/windows/stage.py $(GTKWIN) $(BUILD)/win-stage $(BUILD)/hunter.exe $(BUILD)/hunter-gui.exe $(WINE)
	cd packaging/windows && $(MAKENSIS) -DVERSION=$(VERSION) installer.nsi
	@echo "Built $(DIST)/$(NAME)-$(VERSION)-setup.exe"

clean:
	rm -rf $(BUILD) $(DIST)
