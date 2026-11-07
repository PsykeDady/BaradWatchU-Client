#!/usr/bin/bash
set -u -o pipefail
if [[ ! -x /usr/bin/cato-sdp ]]; then
  printf 'ABSENT|client non installato'
  exit 0
fi
raw=$(/usr/bin/cato-sdp status 2>/dev/null); rc=$?
if ((rc != 0)); then
  printf 'UNKNOWN|client installato; comando status fallito (exit %s)' "$rc"
  exit 0
fi
if printf '%s\n' "$raw" | /usr/bin/grep -Eiq '^[[:space:]]*Cato client is connected[[:space:]]*$'; then
  printf 'CONNECTED|client installato; Cato client is connected'
elif printf '%s\n' "$raw" | /usr/bin/grep -Eiq '^[[:space:]]*Cato client is disconnected[[:space:]]*$'; then
  printf 'DISCONNECTED|client installato; Cato client is disconnected'
elif printf '%s\n' "$raw" | /usr/bin/grep -Eq '(^|[^A-Z_])STATE_(CONNECTED|AUTHENTICATED|CONNECTED_AUTH)($|[^A-Z_])'; then
  printf 'CONNECTED|client installato; stato connesso riportato'
elif printf '%s\n' "$raw" | /usr/bin/grep -Eq '(^|[^A-Z_])STATE_(DISCONNECTED|IDLE|STOPPED|ERROR|FAILED)($|[^A-Z_])'; then
  printf 'DISCONNECTED|client installato; stato disconnesso o errore'
else
  printf 'UNKNOWN|client installato; stato non determinabile'
fi
