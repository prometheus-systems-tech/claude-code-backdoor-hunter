<p align="center"><img src="packaging/logo.png" alt="Claude Code Backdoor Hunter logo" width="160"></p>

# Claude Code Backdoor Hunter

*Read-only checker for the trojanized `anthropic.claude-code` 2.1.313 extension (Cursor marketplace)*

---

## Overview

`claude-code-backdoor-hunter` looks for indicators of compromise from the SSH backdoor in the trojanized `anthropic.claude-code` 2.1.313 extension, disclosed on 30 October 2026. It makes no changes to the system.

Supported platforms: Debian 12+, Ubuntu 24.04+, RHEL 9+ (including compatible rebuilds), FreeBSD 14+ (`pkg` and manual or Linux-compat installs) and macOS 12+ (Homebrew, `.app` bundles, `pkgutil`). Other Linux distributions run on a best-effort basis.

It is a single C99 source file ([src/hunter.c](src/hunter.c)) with no dependencies beyond a C compiler, so it builds on Linux, FreeBSD, macOS and Windows.

## Usage

```bash
make hunter
./build/hunter
```

Run with `sudo` for a complete check. Without it, root's `authorized_keys`, some logs and the system journal may be unreadable, and the script reports this.

If you run an SSH server on purpose, pass `--sshd-ok` to report a running `sshd` as `[ok]` instead of a `[?]` review item. In the GUI, tick "SSH server is expected to run".

## Checks

1. Installed extensions and Cursor installs (packages, Flatpak, Snap, AppImage, tarball, VSIX), editor logs
2. SSH `authorized_keys` files for all readable users
3. Persistence: cron, systemd, autostart, shell profiles, `rc.local`, `sshd_config`
4. Shell history
5. Running processes (reverse SSH tunnels)
6. Active network connections to the C2 IP
7. Local SSH service and recent logins (journal, `auth.log`, `secure`)
8. System logs for the C2 IP. Each hit is triaged: searches for the IP (`grep`, `journalctl`, this tool) and browser URL errors are ignored, sshd activity, firewall `SRC=`/`DST=` entries and tunnel command lines are flagged `[!]`, and anything else is listed for review `[?]`

The checks match published indicators (Cursor security notice, 30 October 2026): SHA-256 hashes of the trojanized `extension.js` and VSIX files (2.1.312 and 2.1.313 from Cursor's marketplace), the attacker public key and its label, the dropped files `~/.config/.smt`, `~/.config/.smtk`, `.stk_*` and `com.apple.sysmond.plist`, and the tunnel command line. Version 2.1.312 is only malicious when it came from Cursor's marketplace, so it is flagged for review unless its hash matches.

## GUI (optional)

`src/gui.c` is a GTK 4 front end written in C. It runs the `hunter` binary, streams the output with colour coding, shows progress and the final result, and can save a report. All detection logic stays in `hunter`.

```bash
make gui
./build/hunter-gui
```

The GUI looks for `hunter` next to itself, then in `../libexec/claude-code-backdoor-hunter/`. Set `HUNTER_BIN` to use a different checker binary.

GTK 4 selects the Wayland or X11 backend automatically. To force one, set `GDK_BACKEND=wayland` or `GDK_BACKEND=x11`.

The "Run with administrator rights" option uses `pkexec` and only elevates the checker, not the GUI, so it works the same under Wayland and X11. Your own home directory is still the one checked.

Build dependencies (GTK 4.8 or newer, a C compiler, `pkg-config`):

- Debian and Ubuntu: `sudo apt install build-essential libgtk-4-dev`
- RHEL 9+: `sudo dnf install gcc gtk4-devel`
- FreeBSD: `pkg install gtk4 pkgconf`
- macOS: `brew install gtk4 pkg-config`

## Building on other platforms

`make all` builds both `hunter` and `hunter-gui`.

On Windows with MinGW: `gcc -std=c99 -O2 -o hunter.exe src/hunter.c`. The Windows build checks extension folders, `authorized_keys` (including `administrators_authorized_keys`), startup folders, scheduled tasks, PowerShell history, processes and `netstat`. Windows event logs are not scanned yet.

🛈 Note: the Windows path is untested. It was written against the Win32 API but only built and run on Linux.

## Native packages

```bash
make native
```

Builds a package for the host OS into `dist/`:

- Debian and Ubuntu: `.deb` (needs `dpkg-deb`)
- RHEL 9+ and compatibles: `.rpm` (needs `rpm-build`)
- FreeBSD: `pkg` package (use `gmake native`)
- macOS: `.pkg` (needs `pkgbuild`)

The package installs `claude-code-backdoor-hunter` and `claude-code-backdoor-hunter-gui` (the C binaries) into the path, plus a desktop entry and icon. Use `make deb`, `make rpm`, `make freebsd` or `make macos` to target one explicitly, and `make clean` to remove build output.

## Exit codes

- `0` - no indicators found
- `1` - indicators of compromise found
- `2` - nothing definite, but items marked `[?]` need manual review

## If indicators are found

1. Isolate the machine from the network.
2. Remove the offending key and persistence entries.
3. Rotate all credentials and keys the machine had access to.

## Requirements

- A C99 compiler and `make` (GNU make; FreeBSD: `gmake`)
- Optional: `timeout` (macOS: `gtimeout` from Homebrew coreutils), `ss`, `netstat`, `sockstat` or `lsof`, `journalctl`, `log` (macOS), package manager CLIs (`dpkg`, `rpm`, `dnf`, `pkg`, `brew`, etc.)

---

*Document version: v1.0.0 — last reviewed 2026-10-31*
*© 2026 Ross WD Cameron <rwd.cameron@prometheus-systems.co.za>.*
*Licensed under the GNU General Public License, version 2. See [LICENSE](LICENSE).*
