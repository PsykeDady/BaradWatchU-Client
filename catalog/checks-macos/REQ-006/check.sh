#!/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-006 — data encryption on macOS (REQUIREMENTS SEC-006): FileVault on the startup volume.
# Source: /usr/bin/fdesetup status (no privileges). On Apple silicon and T2 Macs the internal
# storage is always hardware-encrypted, but without FileVault the key is not protected by the
# user's password, so only FileVault counts.
#   PASS: FileVault is On. FAIL: FileVault is Off or being decrypted.
#   WARN: encryption in progress, deferred enablement pending, or unknown output.
set -u
id=REQ-006
json_string() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\t'/\\t}; s=${s//$'\r'/\\r}; s=${s//$'\n'/\\n}
  s=$(printf '%s' "$s" | LC_ALL=C /usr/bin/tr -d '\000-\010\013\014\016-\037\177')
  printf '"%s"' "$s"
}
emit() { # STATUS SUMMARY [DETAIL...]
  local status=$1 summary=$2 detail first=1
  shift 2
  printf '{"id":"%s","status":"%s","summary":%s,"details":[' "$id" "$status" "$(json_string "$summary")"
  for detail in "$@"; do
    ((first)) || printf ','
    first=0
    json_string "$detail"
  done
  printf ']}'
  exit 0
}

if [ ! -x /usr/bin/fdesetup ]; then
  emit WARN 'Lo stato di FileVault non è leggibile' '/usr/bin/fdesetup assente'
fi
output=$(/usr/bin/fdesetup status 2>&1) || true
first=$(printf '%s\n' "$output" | /usr/bin/head -n 1)
details=("fdesetup status: $(printf '%s' "$output" | /usr/bin/paste -s -d '|' - | /usr/bin/sed 's/|/; /g')")
if [ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ] || /usr/sbin/system_profiler SPiBridgeDataType 2>/dev/null | /usr/bin/grep -q 'Model Identifier'; then
  details+=('Archiviazione interna cifrata in hardware (Apple silicon/T2): FileVault lega la chiave alla password dell’utente')
fi
case $output in
  *'Encryption in progress'*) emit WARN 'La cifratura FileVault è in corso' "${details[@]}" ;;
  *'Decryption in progress'*) emit FAIL 'FileVault è in fase di disattivazione (decifratura in corso)' "${details[@]}" ;;
  *'Deferred enablement appears to be active'*) emit WARN 'FileVault è disattivato con attivazione differita in attesa del prossimo accesso' "${details[@]}" ;;
esac
case $first in
  'FileVault is On.'*) emit PASS 'FileVault è attivo sul volume di avvio' "${details[@]}" ;;
  'FileVault is Off.'*) emit FAIL 'FileVault è disattivato' "${details[@]}" 'Attivalo da Impostazioni di Sistema > Privacy e sicurezza > FileVault' ;;
esac
emit WARN 'Lo stato di FileVault non è interpretabile' "${details[@]}"
