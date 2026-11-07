#!/usr/bin/bash
set -u -o pipefail
if [[ ! -x /usr/bin/lsblk ]]; then
  printf 'UNKNOWN|lsblk non disponibile'
  exit 0
fi
types=$(/usr/bin/lsblk -r -n -o TYPE 2>/dev/null) || {
  printf 'UNKNOWN|lsblk non è riuscito a enumerare i dispositivi'
  exit 0
}
count=$(printf '%s\n' "$types" | /usr/bin/awk '$1=="crypt" {n++} END {print n+0}') || count=0
if [[ $count =~ ^[0-9]+$ ]] && ((count > 0)); then
  printf 'PRESENT|%s dispositivi dm-crypt attivi rilevati' "$count"
else
  printf 'ABSENT|nessun dispositivo dm-crypt attivo rilevato'
fi
