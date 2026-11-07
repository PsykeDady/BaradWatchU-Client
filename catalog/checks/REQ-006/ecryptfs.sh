#!/usr/bin/bash
# eCryptfs method of REQ-006 (skill audit-postazione R4: encrypted home).
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
home_covered=no
if [[ -n ${HOME:-} ]]; then
  while IFS= read -r target; do
    [[ -n $target ]] || continue
    target=$(printf '%b' "$target")  # findmnt -r escapes spaces as \x20
    [[ $HOME == "$target" || $HOME == "$target"/* ]] && home_covered=yes
  done <<<"$mounts"
fi
if [[ $count =~ ^[0-9]+$ ]] && ((count > 0)); then
  printf 'PRESENT|%s mount eCryptfs attivi; home utente cifrata=%s; percorsi omessi' "$count" "$home_covered"
else
  printf 'ABSENT|nessun mount eCryptfs attivo rilevato'
fi
