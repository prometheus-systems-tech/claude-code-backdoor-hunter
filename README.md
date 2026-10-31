# Claude Code Backdoor Hunter

*Read-only checker for the trojanized `anthropic.claude-code` 2.1.313 extension (Cursor marketplace)*

---

## Overview

`check_claude_code_backdoor.sh` looks for indicators of compromise from the SSH backdoor in the trojanized `anthropic.claude-code` 2.1.313 extension, disclosed on 30 October 2026. It makes no changes to the system.

Supported platforms: Debian 12+, RHEL 9+ (including compatible rebuilds) and FreeBSD 14+ (`pkg` and manual or Linux-compat installs). Other Linux distributions run on a best-effort basis.

On FreeBSD, bash is not part of the base system:

```bash
pkg install bash
```

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
8. System logs for the C2 IP

## Exit codes

- `0` - no indicators found
- `1` - indicators of compromise found
- `2` - nothing definite, but items marked `[?]` need manual review

## If indicators are found

1. Isolate the machine from the network.
2. Remove the offending key and persistence entries.
3. Rotate all credentials and keys the machine had access to.

## Requirements

- bash 4+ (FreeBSD: `pkg install bash`), `find`, `grep`, `awk`, `ps`, `timeout`
- Optional: `ss`, `netstat` or `sockstat`, `journalctl`, package manager CLIs (`dpkg`, `rpm`, `dnf`, `pkg`, etc.)

---

*Document version: v1.0.0 — last reviewed 2026-10-31*
*Licensed under the GNU General Public License, version 2. See [LICENSE](LICENSE).*
