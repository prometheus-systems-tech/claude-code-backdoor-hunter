# Claude Code Backdoor Hunter

*Read-only checker for the trojanized `anthropic.claude-code` 2.1.313 extension (Cursor marketplace)*

---

## Overview

`check_claude_code_backdoor.sh` looks for indicators of compromise from the SSH backdoor in the trojanized `anthropic.claude-code` 2.1.313 extension, disclosed on 30 October 2026. It makes no changes to the system.

Supported platforms: Debian 12+, Ubuntu 24.04+, RHEL 9+ (including compatible rebuilds), FreeBSD 14+ (`pkg` and manual or Linux-compat installs) and macOS 12+ (Homebrew, `.app` bundles, `pkgutil`). Other Linux distributions run on a best-effort basis.

The script is plain POSIX `sh`, so no extra shell needs installing on any platform.

## Usage

```bash
chmod +x check_claude_code_backdoor.sh
./check_claude_code_backdoor.sh
```

Run with `sudo` for a complete check. Without it, root's `authorized_keys`, some logs and the system journal may be unreadable, and the script reports this.

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

`check_claude_code_backdoor_gui.py` is a GTK 4 front end that runs the script, streams the output with colour coding, shows progress and the final result, and can save a report. All detection logic stays in the shell script.

```bash
./check_claude_code_backdoor_gui.py
```

GTK 4 selects the Wayland or X11 backend automatically. To force one, set `GDK_BACKEND=wayland` or `GDK_BACKEND=x11`.

The "Run with administrator rights" option uses `pkexec` and only elevates the shell script, not the GUI, so it works the same under Wayland and X11. Your own home directory is still the one checked.

Dependencies (GTK 4.8 or newer, Python 3):

- Debian and Ubuntu: `sudo apt install python3-gi gir1.2-gtk-4.0`
- RHEL 9+: `sudo dnf install python3-gobject gtk4`
- FreeBSD: `pkg install gtk4 py311-gobject3` (match the package prefix to your Python version)
- macOS: `brew install pygobject3 gtk4`

## Native packages

```bash
make native
```

Builds a package for the host OS into `dist/`:

- Debian and Ubuntu: `.deb` (needs `dpkg-deb`)
- RHEL 9+ and compatibles: `.rpm` (needs `rpm-build`)
- FreeBSD: `pkg` package (use `gmake native`)
- macOS: `.pkg` (needs `pkgbuild`)

The package installs `claude-code-backdoor-hunter` and `claude-code-backdoor-hunter-gui` into the path, plus a desktop entry and icon. Use `make deb`, `make rpm`, `make freebsd` or `make macos` to target one explicitly, and `make clean` to remove build output.

## Exit codes

- `0` - no indicators found
- `1` - indicators of compromise found
- `2` - nothing definite, but items marked `[?]` need manual review

## If indicators are found

1. Isolate the machine from the network.
2. Remove the offending key and persistence entries.
3. Rotate all credentials and keys the machine had access to.

## Requirements

- A POSIX `sh` (dash, FreeBSD `sh`, macOS `sh`, bash in sh mode), `find`, `grep`, `awk`, `sed`, `ps`
- Optional: `timeout` (macOS: `gtimeout` from Homebrew coreutils), `ss`, `netstat`, `sockstat` or `lsof`, `journalctl`, `log` (macOS), package manager CLIs (`dpkg`, `rpm`, `dnf`, `pkg`, `brew`, etc.)

---

*Document version: v1.0.0 — last reviewed 2026-10-31*
*© 2026 Ross WD Cameron <rwd.cameron@prometheus-systems.co.za>.*
*Licensed under the GNU General Public License, version 2. See [LICENSE](LICENSE).*
