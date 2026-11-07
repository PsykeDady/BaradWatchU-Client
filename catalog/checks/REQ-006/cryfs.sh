#!/usr/bin/bash
# CryFS method of REQ-006 (skill audit-postazione R4: container for sensitive data).
set -u -o pipefail
if [[ ! -x /usr/bin/findmnt ]]; then
  printf 'UNKNOWN|findmnt non disponibile'
  exit 0
fi
mounts=$(/usr/bin/findmnt -rn -t fuse.cryfs -o TARGET 2>/dev/null) || mounts=''
count=$(printf '%s\n' "$mounts" | /usr/bin/awk 'NF {n++} END {print n+0}') || count=0
if [[ $count =~ ^[0-9]+$ ]] && ((count > 0)); then
  printf 'PRESENT|%s container CryFS montati; percorsi omessi' "$count"
elif [[ -x /usr/bin/cryfs ]]; then
  printf 'ABSENT|cryfs installato ma nessun container montato'
else
  printf 'ABSENT|nessun container CryFS montato'
fi
