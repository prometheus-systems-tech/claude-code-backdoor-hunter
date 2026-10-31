#!/bin/sh
# Read-only check for the trojanized anthropic.claude-code 2.1.313 (Cursor marketplace)
# SSH backdoor, disclosed 30 Oct 2026. Makes no changes to the system.
#
# POSIX sh script (no bashisms). Supported: Debian 12+, RHEL 9+ family, FreeBSD 14+, macOS 12+.
# Exit codes: 0 = no indicators, 1 = indicators found, 2 = nothing definite, items need review.

C2_IP="134.209.82.225"
KEY_LABEL="svc-telemetry"
BAD_VER="2.1.313"
SINCE="2026-10-29"      # install window began 29 Oct 2026
found=0
review=0

warn() { echo "[!] $*"; found=1; }
note() { echo "[?] $*"; review=1; }
ok()   { echo "[ok] $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# timeout(1) is not POSIX; run without it when missing.
if have timeout; then
  tmo() { _t=$1; shift; timeout "$_t" "$@"; }
elif have gtimeout; then
  tmo() { _t=$1; shift; gtimeout "$_t" "$@"; }
else
  tmo() { shift; "$@"; }
fi

TOTAL=8
progress() {
  _step=$1
  _width=30
  _filled=$(( _step * _width / TOTAL ))
  _bar=""
  _i=0
  while [ "$_i" -lt "$_width" ]; do
    if [ "$_i" -lt "$_filled" ]; then _bar="${_bar}#"; else _bar="${_bar}-"; fi
    _i=$(( _i + 1 ))
  done
  printf '[%s] %d/%d (%d%%)\n' "$_bar" "$_step" "$TOTAL" "$(( _step * 100 / TOTAL ))"
}

# OS detection (supported: Debian 12+, the RHEL 9+ family, FreeBSD 14+ and macOS 12+; others run best-effort)
DISTRO_FAMILY="other"
IS_BSD=0
IS_MAC=0
if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
  DISTRO_FAMILY="macos"
  IS_MAC=1
  _macv="$(sw_vers -productVersion 2>/dev/null)"
  _major="${_macv%%.*}"
  if [ "${_major:-0}" -lt 12 ] 2>/dev/null; then
    echo "[?] macOS $_macv is older than the supported macOS 12+."
  fi
  echo "Detected: macOS $_macv (family: $DISTRO_FAMILY)"
elif [ "$(uname -s 2>/dev/null)" = "FreeBSD" ]; then
  DISTRO_FAMILY="freebsd"
  IS_BSD=1
  _fbsd="$(freebsd-version -u 2>/dev/null || uname -r)"
  _major="${_fbsd%%.*}"
  if [ "${_major:-0}" -lt 14 ] 2>/dev/null; then
    echo "[?] FreeBSD $_fbsd is older than the supported FreeBSD 14+."
  fi
  echo "Detected: FreeBSD $_fbsd (family: $DISTRO_FAMILY)"
elif [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  _ids=" ${ID:-} ${ID_LIKE:-} "
  _major="${VERSION_ID%%.*}"
  case "$_ids" in
    *" debian "*|*" ubuntu "*)
      DISTRO_FAMILY="debian"
      if [ "${ID:-}" = "debian" ] && [ "${_major:-0}" -lt 12 ] 2>/dev/null; then
        echo "[?] Debian $VERSION_ID is older than the supported Debian 12+."
      fi ;;
    *" rhel "*|*" fedora "*|*" centos "*)
      DISTRO_FAMILY="rhel"
      if [ "${ID:-}" != "fedora" ] && [ "${_major:-0}" -lt 9 ] 2>/dev/null; then
        echo "[?] ${PRETTY_NAME:-RHEL-family} is older than the supported RHEL 9+."
      fi ;;
  esac
  echo "Detected: ${PRETTY_NAME:-unknown} (family: $DISTRO_FAMILY)"
fi

# BSD grep has no --max-filesize; only pass it when GNU grep supports it.
GREP_MAX1=""
GREP_MAX5=""
echo x | grep -q --max-filesize=1M y 2>/dev/null
if [ $? -eq 1 ]; then GREP_MAX1="--max-filesize=1M"; GREP_MAX5="--max-filesize=5M"; fi

# Auth log files (Debian: auth.log, RHEL: secure, FreeBSD: auth.log). Debian 12 may have no file at all, only the journal.
AUTH_LOGS=""
for al in /var/log/auth.log /var/log/secure; do
  [ -r "$al" ] && AUTH_LOGS="$AUTH_LOGS $al"
done

# ---------------------------------------------------------------- 1
progress 0
echo "== 1. Installs and extensions (packages, Flatpak, Snap, AppImage, tarball, VSIX) =="
set --
for r in \
  "$HOME/.cursor" "$HOME/.cursor-server" "$HOME/.config/Cursor" \
  "$HOME/.vscode" "$HOME/.vscode-insiders" "$HOME/.vscode-oss" "$HOME/.vscodium" \
  "$HOME/.vscode-server" "$HOME/.var/app" "$HOME/snap" \
  "$HOME/.cursor-linux" /compat/linux/root/.cursor \
  "$HOME/Library/Application Support/Cursor" "$HOME/Library/Application Support/Code" \
  "$HOME/Library/Application Support/Code - Insiders" "$HOME/Library/Application Support/VSCodium"
do
  [ -d "$r" ] && set -- "$@" "$r"
done

ext_dirs=""
if [ $# -gt 0 ]; then
  ext_dirs=$(tmo 30 find "$@" -maxdepth 6 -type d -iname 'anthropic.claude-code-*' 2>/dev/null)
fi
if [ -z "$ext_dirs" ]; then
  ok "No anthropic.claude-code extension folders found."
else
  while IFS= read -r d; do
    [ -z "$d" ] && continue
    case "$d" in
      *"$BAD_VER"*) warn "Malicious version installed: $d" ;;
      *)            note "Extension present (not $BAD_VER), confirm it was never $BAD_VER: $d" ;;
    esac
    if tmo 20 grep -rIqs "$C2_IP" "$d" 2>/dev/null; then
      warn "C2 IP found inside extension files: $d"
    fi
  done <<EOF_EXT
$ext_dirs
EOF_EXT
fi

# extensions.json records installed versions even after folders are removed
for ej in "$HOME"/.cursor/extensions/extensions.json "$HOME"/.vscode*/extensions/extensions.json; do
  [ -f "$ej" ] || continue
  if grep -Eq "anthropic\.claude-code.{0,250}$BAD_VER" "$ej" 2>/dev/null; then
    warn "extensions.json lists claude-code $BAD_VER: $ej"
  fi
done

# editor logs can show past installs/updates even if the extension is gone
set --
for l in "$HOME/.config/Cursor/logs" "$HOME/.config/Code/logs" "$HOME/.cursor/logs" \
         "$HOME/Library/Application Support/Cursor/logs" "$HOME/Library/Application Support/Code/logs" \
         "$HOME/Library/Logs"; do
  [ -d "$l" ] && set -- "$@" "$l"
done
if [ $# -gt 0 ]; then
  # shellcheck disable=SC2086
  hits=$(tmo 30 grep $GREP_MAX5 -rIlE \
    "claude-code[^[:space:]]*$BAD_VER|$BAD_VER[^[:space:]]*claude-code" "$@" 2>/dev/null | head -n 5)
  if [ -n "$hits" ]; then
    warn "Editor logs mention claude-code $BAD_VER:"
    echo "$hits" | sed 's/^/    /'
  fi
fi

echo
echo "-- Package managers (the malicious item is the extension $BAD_VER, not the app itself) --"
pm_check() {
  if [ -n "$2" ]; then
    note "$1 install found, confirm the extension version separately:"
    echo "$2" | sed 's/^/    /'
  fi
}
have dpkg    && pm_check "dpkg/apt"    "$(dpkg -l 2>/dev/null | grep -iE '^ii +(cursor|claude-code|anysphere)')"
have pkg     && pm_check "FreeBSD pkg" "$(pkg info 2>/dev/null | grep -iE '^(cursor|claude-code|anysphere|vscode|code-oss|vscodium)')"
have rpm     && pm_check "rpm/dnf"     "$(rpm -qa 2>/dev/null | grep -iE '^(cursor|claude-code|anysphere)')"
have dnf     && pm_check "dnf history" "$(tmo 20 dnf -q history list 2>/dev/null | grep -iE 'cursor|claude-code|anysphere')"
have pacman  && pm_check "pacman/AUR"  "$(pacman -Q 2>/dev/null | grep -iE '^(cursor|claude-code)')"
have snap    && pm_check "snap"        "$(snap list 2>/dev/null | grep -iE '^(cursor|claude)')"
have flatpak && pm_check "flatpak"     "$(flatpak list --app --columns=application,version,installation 2>/dev/null | grep -iE 'cursor|claude|anysphere')"
have brew    && pm_check "Homebrew"    "$(brew list --versions 2>/dev/null | grep -iE '^(cursor|claude)')"
have brew    && pm_check "Homebrew cask" "$(brew list --cask --versions 2>/dev/null | grep -iE '^(cursor|claude|visual-studio-code|vscodium)')"
have pkgutil && pm_check "macOS pkgutil" "$(pkgutil --pkgs 2>/dev/null | grep -iE 'cursor|claude-code|anysphere|todesktop')"
have nix-env && pm_check "nix"         "$(nix-env -q 2>/dev/null | grep -iE 'cursor|claude')"
have npm     && pm_check "npm global"  "$(npm ls -g --depth=0 2>/dev/null | grep -i 'claude-code')"
have pnpm    && pm_check "pnpm global" "$(pnpm ls -g --depth=0 2>/dev/null | grep -i 'claude-code')"

echo "-- AppImage, tarball and manual installs --"
manual=$(tmo 40 find "$HOME/Applications" "$HOME/Downloads" "$HOME/Desktop" "$HOME/Documents" \
  "$HOME/bin" "$HOME/opt" "$HOME/.local/bin" "$HOME/.local/opt" "$HOME/.local/share/appimagekit" \
  /Applications /Users/Shared /opt /usr/local /compat/linux/opt /tmp /var/tmp /mnt /media -maxdepth 4 \
  \( -iname '*cursor*.appimage' -o -iname 'cursor*.tar*' -o -iname 'cursor*.tgz' -o -iname 'cursor*.zip' \
     -o \( -iname 'cursor*' \( -type d -o -type f -perm -u+x \) \) \) 2>/dev/null | head -n 20)
if [ -n "$manual" ]; then
  note "Possible AppImage/tarball/manual Cursor installs:"
  echo "$manual" | sed 's/^/    /'
  # portable installs keep extensions inside the install directory
  while IFS= read -r p; do
    [ -d "$p" ] || continue
    inner=$(tmo 15 find "$p" -maxdepth 6 -type d -iname 'anthropic.claude-code-*' 2>/dev/null)
    [ -z "$inner" ] && continue
    while IFS= read -r e; do
      [ -z "$e" ] && continue
      case "$e" in
        *"$BAD_VER"*) warn "Malicious version in portable install: $e" ;;
        *)            note "Extension inside portable install: $e" ;;
      esac
    done <<EOF_INNER
$inner
EOF_INNER
  done <<EOF_MANUAL
$manual
EOF_MANUAL
else
  ok "No AppImage or tarball Cursor installs found in common locations."
fi

if have cursor; then
  _cur=$(command -v cursor)
  note "cursor on PATH: $(readlink -f "$_cur" 2>/dev/null || echo "$_cur")"
fi
for df in /usr/share/applications/*cursor*.desktop /usr/local/share/applications/*cursor*.desktop \
          "$HOME"/.local/share/applications/*cursor*.desktop \
          /var/lib/flatpak/exports/share/applications/*ursor*.desktop \
          "$HOME"/.local/share/flatpak/exports/share/applications/*ursor*.desktop; do
  [ -e "$df" ] || continue
  note "Desktop entry $df -> $(grep '^Exec=' "$df" 2>/dev/null | head -n 1)"
done

vsix=$(tmo 30 find "$HOME/Downloads" "$HOME/Desktop" "$HOME/Documents" "$HOME/.cache" /tmp \
  -maxdepth 4 -iname '*claude-code*.vsix' 2>/dev/null | head -n 10)
if [ -n "$vsix" ]; then
  while IFS= read -r v; do
    [ -z "$v" ] && continue
    case "$v" in
      *"$BAD_VER"*) warn "Malicious VSIX file: $v" ;;
      *)            note "VSIX file (check its version): $v" ;;
    esac
  done <<EOF_VSIX
$vsix
EOF_VSIX
fi

# ---------------------------------------------------------------- 2
echo
progress 1
echo "== 2. SSH authorized_keys (all readable users) =="
set -- "$HOME/.ssh/authorized_keys" "$HOME/.ssh/authorized_keys2"
for h in /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2 /root/.ssh/authorized_keys \
         /Users/*/.ssh/authorized_keys /Users/*/.ssh/authorized_keys2 /var/root/.ssh/authorized_keys \
         /etc/ssh/authorized_keys.d/*; do
  [ -r "$h" ] || continue
  [ "$h" = "$HOME/.ssh/authorized_keys" ] && continue
  [ "$h" = "$HOME/.ssh/authorized_keys2" ] && continue
  set -- "$@" "$h"
done
checked=0
for kf in "$@"; do
  [ -f "$kf" ] || continue
  checked=1
  if grep -n "$KEY_LABEL" "$kf"; then
    warn "Key labelled '$KEY_LABEL' in $kf"
  fi
  if [ -n "$(find "$kf" -newermt "$SINCE" 2>/dev/null)" ]; then
    note "$kf modified since $SINCE. Review its keys:"
  fi
  awk '{print "    - " $NF}' "$kf"
done
[ $checked -eq 0 ] && ok "No authorized_keys files found."
for d in /root/.ssh /etc/ssh/sshd_config.d; do
  if [ -d "$d" ] && [ ! -r "$d" ]; then
    note "Cannot read $d (run with sudo for a full check)."
  fi
done

# ---------------------------------------------------------------- 3
echo
progress 2
echo "== 3. Persistence: cron, systemd, autostart, shell profiles =="
if crontab -l 2>/dev/null | grep -E "$C2_IP|$KEY_LABEL"; then
  warn "User crontab references the C2 IP or key label."
else
  ok "User crontab clean."
fi
set --
for p in \
  "$HOME/.config/systemd" "$HOME/.config/autostart" "$HOME/.local/bin" \
  "$HOME/.bashrc" "$HOME/.profile" "$HOME/.bash_profile" "$HOME/.zshrc" "$HOME/.zprofile" \
  "$HOME/.bash_logout" "$HOME/.config/fish" "$HOME/.bashrc.d" \
  /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/crontab \
  /etc/systemd/system /etc/systemd/user \
  /var/spool/cron /var/spool/cron/crontabs \
  /var/cron/tabs /usr/local/etc/cron.d /etc/rc.conf /etc/rc.conf.d /etc/rc.local.d \
  /usr/local/etc/rc.d /etc/periodic /usr/local/etc/periodic /etc/csh.cshrc /etc/csh.login \
  "$HOME/.cshrc" "$HOME/.login" "$HOME/.shrc" "$HOME/.tcshrc" \
  /etc/profile.d /etc/profile /etc/bashrc /etc/bash.bashrc /etc/rc.local /etc/rc.d/rc.local \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d \
  "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons /usr/lib/cron/tabs \
  /etc/zshenv /etc/zprofile /etc/zshrc /etc/paths.d "$HOME/.zshenv"
do
  [ -e "$p" ] && [ -r "$p" ] && set -- "$@" "$p"
done
hits=""
if [ $# -gt 0 ]; then
  # shellcheck disable=SC2086
  hits=$(tmo 60 grep $GREP_MAX1 -rIlE "$C2_IP|$KEY_LABEL" "$@" 2>/dev/null)
fi
if [ -n "$hits" ]; then
  warn "Persistence files reference the C2 IP or key label:"
  echo "$hits" | sed 's/^/    /'
else
  ok "No persistence files reference the C2 IP or key label."
fi
recent=$(tmo 30 find "$HOME/.config/systemd" "$HOME/.config/autostart" "$HOME/.local/bin" \
  "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons \
  /etc/cron.d /etc/systemd/system -type f -newermt "$SINCE" 2>/dev/null | head -n 20)
if [ -n "$recent" ]; then
  note "Persistence files created or changed since $SINCE (verify you made them):"
  echo "$recent" | sed 's/^/    /'
fi

# ---------------------------------------------------------------- 4
echo
progress 3
echo "== 4. Shell history =="
hist_hits=0
for hf in "$HOME"/.bash_history "$HOME"/.zsh_history "$HOME"/.local/share/fish/fish_history \
          "$HOME"/.history "$HOME"/.sh_history; do
  if [ -f "$hf" ] && grep -qE "$C2_IP|$KEY_LABEL" "$hf" 2>/dev/null; then
    warn "C2 IP or key label in $hf"
    hist_hits=1
  fi
done
[ $hist_hits -eq 0 ] && ok "No references in shell history."

# ---------------------------------------------------------------- 5
echo
progress 4
echo "== 5. Running processes (reverse tunnels) =="
allprocs=$(ps -axww -o pid,user,args 2>/dev/null || ps -ef 2>/dev/null)
procs=$(echo "$allprocs" | grep -E "$C2_IP|ssh[^|]* -[A-Za-z]*R ?[0-9]+:" | grep -v grep)
if [ -n "$procs" ]; then
  warn "Suspicious process(es):"
  echo "$procs" | sed 's/^/    /'
else
  ok "No suspicious ssh tunnel processes."
fi

# ---------------------------------------------------------------- 6
echo
progress 5
echo "== 6. Network connections =="
if [ "$IS_BSD" -eq 1 ] || [ "$IS_MAC" -eq 1 ]; then
  conns="$(sockstat -c 2>/dev/null; netstat -an -p tcp 2>/dev/null; lsof -nP -i 2>/dev/null)"
  if echo "$conns" | grep -q "$C2_IP"; then
    warn "Active connection to $C2_IP"
    echo "$conns" | grep "$C2_IP" | sed 's/^/    /'
  else
    ok "No active connection to $C2_IP."
  fi
elif have ss; then
  if ss -tn 2>/dev/null | grep -q "$C2_IP"; then
    warn "Active connection to $C2_IP"
    ss -tnp 2>/dev/null | grep "$C2_IP" | sed 's/^/    /'
  else
    ok "No active connection to $C2_IP."
  fi
elif have netstat; then
  if netstat -tn 2>/dev/null | grep -q "$C2_IP"; then
    warn "Active connection to $C2_IP"
    netstat -tnp 2>/dev/null | grep "$C2_IP" | sed 's/^/    /'
  else
    ok "No active connection to $C2_IP."
  fi
else
  note "Neither 'ss' (iproute2/iproute) nor 'netstat' available, connection check skipped."
fi

# ---------------------------------------------------------------- 7
echo
progress 6
echo "== 7. Local SSH service and recent logins =="
if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null \
   || { [ "$IS_BSD" -eq 1 ] && service sshd onestatus >/dev/null 2>&1; } \
   || { [ "$IS_MAC" -eq 1 ] && launchctl print-disabled system 2>/dev/null \
        | grep -Eq '"com.openssh.sshd" => (enabled|false)'; }; then
  note "sshd is running. Confirm this is intentional."
else
  ok "sshd not running."
fi
if have journalctl; then
  acc=$(journalctl _COMM=sshd --since "$SINCE" --no-pager 2>/dev/null | grep -E "Accepted (publickey|password)" | tail -n 5)
  if [ -n "$acc" ]; then
    note "SSH logins since $SINCE (verify they were you):"
    echo "$acc" | sed 's/^/    /'
  fi
fi
if [ "$IS_MAC" -eq 1 ] && have log; then
  # unified log; may be partial without sudo. The header line echoes the predicate, so filter it out.
  acc=$(tmo 120 log show --start "$SINCE" --style compact \
    --predicate 'process == "sshd" AND eventMessage CONTAINS "Accepted"' 2>/dev/null \
    | grep -E "Accepted (publickey|password)" | tail -n 5)
  if [ -n "$acc" ]; then
    note "SSH logins since $SINCE (verify they were you):"
    echo "$acc" | sed 's/^/    /'
  fi
fi
if [ -n "$AUTH_LOGS" ]; then
  # shellcheck disable=SC2086
  acc=$(grep -hE "Accepted (publickey|password)" $AUTH_LOGS 2>/dev/null | tail -n 5)
  if [ -n "$acc" ]; then
    note "Recent SSH logins in$AUTH_LOGS (verify they were you):"
    echo "$acc" | sed 's/^/    /'
  fi
fi

# ---------------------------------------------------------------- 8
echo
progress 7
echo "== 8. System logs for the C2 IP =="
if have journalctl; then
  if journalctl --since "$SINCE" --no-pager 2>/dev/null | grep -q "$C2_IP"; then
    warn "System journal mentions $C2_IP since $SINCE."
  else
    ok "No journal mentions of $C2_IP (journal may need sudo to be complete)."
  fi
elif [ "$IS_MAC" -eq 1 ] && have log; then
  # unified log; this can take a while. The header line echoes the predicate, so filter it out.
  if tmo 180 log show --start "$SINCE" --style compact \
       --predicate "eventMessage CONTAINS \"$C2_IP\"" 2>/dev/null \
       | grep -v 'Filtering the log data' | grep -q "$C2_IP"; then
    warn "Unified log mentions $C2_IP since $SINCE."
  else
    ok "No unified log mentions of $C2_IP (log may need sudo to be complete)."
  fi
else
  echo "    (journalctl not available, relying on classic log files)"
fi
# Classic log files (RHEL: secure, messages; Debian: auth.log, syslog; FreeBSD: auth.log, messages), if readable
logfiles=""
for lf in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/kern.log /var/log/system.log; do
  [ -r "$lf" ] && logfiles="$logfiles $lf"
done
if [ -n "$logfiles" ]; then
  # shellcheck disable=SC2086
  if grep -qs "$C2_IP" $logfiles; then
    warn "Log files mention $C2_IP:$logfiles"
  else
    ok "No mentions of $C2_IP in$logfiles."
  fi
elif [ "$IS_MAC" -ne 1 ]; then
  note "No readable classic log files (run with sudo for a complete check)."
fi

echo
progress 8
echo
if [ "$found" -eq 1 ]; then
  echo "RESULT: indicators of compromise found. Isolate the machine, remove the key/persistence, rotate credentials."
  exit 1
elif [ "$review" -eq 1 ]; then
  echo "RESULT: no definite indicators, but [?] items need manual review."
  exit 2
else
  echo "RESULT: no indicators found."
  exit 0
fi
