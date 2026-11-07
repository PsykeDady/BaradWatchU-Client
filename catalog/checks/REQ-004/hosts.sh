#!/usr/bin/bash
# /etc/hosts blocklist method of REQ-004 (skill audit-postazione R7, method A).
# Output: CODE|detail with CODE in PRESENT (>= threshold), FEW, ABSENT, UNKNOWN.
set -u -o pipefail
min_entries=${1:-10000}
if [[ ! -r /etc/hosts ]]; then
  printf 'UNKNOWN|/etc/hosts non leggibile'
  exit 0
fi
count=$(/usr/bin/awk '
  /^[[:space:]]*#/ {next}
  {
    line=$0
    sub(/#.*/, "", line)
    sub(/^[[:space:]]+/, "", line)
    if (line !~ /(^|[[:space:]])(0\.0\.0\.0|::)([[:space:]]|$)/) next
    n=split(line, fields, /[[:space:]]+/)
    for (i=2; i<=n; i++) {
      name=tolower(fields[i])
      if (name != "" && name != "localhost" && name !~ /\.localhost$/ && name != "ip6-localhost" && name != "ip6-loopback") {entries++ ; break}
    }
  }
  END {print entries+0}
' /etc/hosts 2>/dev/null) || count=0
if [[ ! $count =~ ^[0-9]+$ ]] || ((count == 0)); then
  printf 'ABSENT|nessuna voce di blocco rilevata'
elif ((count >= min_entries)); then
  printf 'PRESENT|%s voci di blocco (minimo %s); nomi host omessi' "$count" "$min_entries"
else
  printf 'FEW|solo %s voci di blocco (minimo %s): non è una blocklist completa' "$count" "$min_entries"
fi
