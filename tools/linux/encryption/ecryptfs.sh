#!/usr/bin/bash
set -u -o pipefail
if [[ ! -x /usr/bin/findmnt ]]; then
  printf 'UNKNOWN|findmnt non disponibile'
  exit 0
fi
mounts=$(/usr/bin/findmnt -rn -t ecryptfs -o TARGET 2>/dev/null) || {
  printf 'UNKNOWN|findmnt non è riuscito a enumerare i mount'
  exit 0
}
count=$(printf '%s\n' "$mounts" | /usr/bin/awk 'NF {n++} END {print n+0}') || count=0
if [[ $count =~ ^[0-9]+$ ]] && ((count > 0)); then
  printf 'PRESENT|%s mount eCryptfs attivi rilevati; percorsi omessi' "$count"
else
  printf 'ABSENT|nessun mount eCryptfs attivo rilevato'
fi
