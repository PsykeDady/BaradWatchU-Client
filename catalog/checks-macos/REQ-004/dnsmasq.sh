#!/bin/bash
# dnsmasq method of REQ-004 on macOS (same contract as the Linux dnsmasq.sh).
# dnsmasq comes from Homebrew (/opt/homebrew, /usr/local) or MacPorts (/opt/local) and is
# started at boot by a LaunchDaemon (e.g. `sudo brew services start dnsmasq`).
# Output: CODE|detail with CODE in ACTIVE, NOT_ENABLED, NO_RULES, INACTIVE, ABSENT, UNKNOWN.
set -u
min_rules=${1:-1000}
binary='' prefix=''
for candidate in /opt/homebrew /usr/local /opt/local; do
  if [ -x "$candidate/sbin/dnsmasq" ]; then
    binary="$candidate/sbin/dnsmasq" prefix=$candidate
    break
  fi
done
if [ -z "$binary" ]; then
  printf 'ABSENT|dnsmasq non installato (Homebrew o MacPorts)'
  exit 0
fi
if ! /usr/bin/pgrep -x dnsmasq >/dev/null 2>&1; then
  printf 'INACTIVE|dnsmasq installato (%s) ma non in esecuzione' "$binary"
  exit 0
fi
# Started at boot: a LaunchDaemon that runs this dnsmasq with RunAtLoad or KeepAlive.
enabled=no
for plist in /Library/LaunchDaemons/*.plist; do
  [ -f "$plist" ] || continue
  program=$(/usr/bin/plutil -extract Program raw -o - "$plist" 2>/dev/null) ||
    program=$(/usr/bin/plutil -extract ProgramArguments.0 raw -o - "$plist" 2>/dev/null) || continue
  case $program in
    "$binary"|"$prefix"/opt/dnsmasq/sbin/dnsmasq|*/Cellar/dnsmasq/*/sbin/dnsmasq) ;;
    *) continue ;;
  esac
  at_load=$(/usr/bin/plutil -extract RunAtLoad raw -o - "$plist" 2>/dev/null) || at_load=false
  keep=$(/usr/bin/plutil -type KeepAlive "$plist" 2>/dev/null) || keep=''
  if [ "$at_load" = true ] || [ -n "$keep" ]; then enabled="sì (${plist##*/})"; fi
done
# Block rules: "server=/domain/" (no upstream) or "address=/domain/0.0.0.0|::|#|" in the main
# configuration, conf-file/conf-dir files and every servers-file they reference.
files=() rules=0 unreadable=0
add_file() { [ -e "$1" ] && files+=("$1"); }
add_file "$prefix/etc/dnsmasq.conf"
for conf in "$prefix"/etc/dnsmasq.d/*.conf; do add_file "$conf"; done
if ((${#files[@]})); then
  extra=$(/usr/bin/awk -F= '
    $1 == "conf-file" || $1 == "servers-file" { print $2 }
    $1 == "conf-dir" { split($2, part, ","); print part[1] "/*.conf" }
  ' "${files[@]}" 2>/dev/null)
  while IFS= read -r pattern; do
    [ -n "$pattern" ] || continue
    # shellcheck disable=SC2086 # the conf-dir pattern is meant to expand
    for conf in $pattern; do add_file "$conf"; done
  done <<EOF
$extra
EOF
fi
for file in ${files[@]+"${files[@]}"}; do
  if [ ! -r "$file" ]; then unreadable=$((unreadable + 1)); continue; fi
  count=$(/usr/bin/awk '/^server=\/[^\/]+\/$/ || /^address=\/[^\/]+\/(0\.0\.0\.0|::|#)?$/ {n++} END {print n+0}' "$file" 2>/dev/null) || count=0
  rules=$((rules + count))
done
resolver=$(/usr/sbin/scutil --dns 2>/dev/null | /usr/bin/awk '/^resolver #1/ {r=1} r && /nameserver\[0\]/ {print $3; exit}')
case $resolver in
  127.*|::1) resolver_note="DNS di sistema puntato a $resolver (loopback)" ;;
  '') resolver_note='DNS di sistema non leggibile (scutil --dns)' ;;
  *) resolver_note="osservazione: il DNS di sistema non punta a loopback ($resolver), il filtro locale può essere aggirato" ;;
esac
detail="dnsmasq in esecuzione ($binary), avvio automatico=$enabled, $rules regole di blocco (minimo $min_rules), $resolver_note"
if [ "$enabled" = no ]; then
  printf 'NOT_ENABLED|%s' "$detail"
elif ((rules < min_rules)); then
  if ((unreadable > 0)); then printf 'UNKNOWN|%s; %s file di regole non leggibili' "$detail" "$unreadable"
  else printf 'NO_RULES|%s' "$detail"; fi
else
  printf 'ACTIVE|%s' "$detail"
fi
