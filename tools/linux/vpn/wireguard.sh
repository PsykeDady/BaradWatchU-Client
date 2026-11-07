#!/usr/bin/bash
set -u -o pipefail
if [[ ! -x /usr/bin/wg ]]; then
  printf 'ABSENT|strumenti WireGuard non installati'
  exit 0
fi
interfaces=$(/usr/bin/wg show interfaces 2>/dev/null); rc=$?
if ((rc != 0)); then
  printf 'UNKNOWN|strumenti installati; stato delle interfacce non determinabile (exit %s)' "$rc"
elif [[ -n $interfaces ]]; then
  count=$(printf '%s\n' "$interfaces" | /usr/bin/wc -w)
  printf 'CONNECTED|strumenti installati; interfacce WireGuard attive: %s' "$count"
else
  printf 'DISCONNECTED|strumenti installati; nessuna interfaccia attiva'
fi
