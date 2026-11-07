#!/usr/bin/bash
set -u -o pipefail
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
if [[ $count =~ ^[0-9]+$ ]] && ((count > 0)); then
  printf 'PRESENT|%s voci di blocco rilevate; nomi host omessi' "$count"
else
  printf 'ABSENT|nessuna voce di blocco personalizzata rilevata'
fi
