#!/bin/bash
# /etc/hosts blocklist method of REQ-004 on macOS (same contract as the Linux hosts.sh; BSD date).
# Operator decision 2026-11-08: the list must be HaGeZi (header "# Title: HaGeZi's", homepage
# under github.com/hagezi/) and complete: at least as many blocking lines as the headers
# declare ("# Number of entries"), with >= threshold blocked names; older than the age limit
# is inconclusive.
# Usage: hosts.sh MIN_ENTRIES MAX_AGE_DAYS REQUIRE_HAGEZI(true|false) [HOSTS_FILE]
# Output: CODE|detail with CODE in PRESENT, FEW, ABSENT, NOT_HAGEZI, INCOMPLETE, STALE, UNKNOWN.
set -u -o pipefail
min_entries=${1:-10000}
max_age_days=${2:-30}
require_hagezi=${3:-true}
hosts_file=${4:-/etc/hosts}
if [[ ! -r $hosts_file ]]; then
  printf 'UNKNOWN|%s non leggibile' "$hosts_file"
  exit 0
fi
read -r names lines headers declared oldest < <(/usr/bin/awk '
  BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", m, " ")
    for (i = 1; i <= 12; i++) month[m[i]] = i
    oldest = 0
  }
  /^[[:space:]]*#/ {
    text = $0
    sub(/^[[:space:]]+/, "", text)
    if (index(text, "# Title: HaGeZi'\''s") == 1) { hagezi = 1; headers++ ; next }
    if (hagezi && index(text, "# Homepage:") == 1 && text !~ /github\.com\/hagezi\//) { hagezi = 0; headers--; next }
    if (hagezi && index(text, "# Number of entries:") == 1) { declared += $NF + 0; next }
    if (hagezi && index(text, "# Last modified:") == 1) {
      # "# Last modified: 08 Nov 2026 09:08 UTC" -> sortable yyyymmddhhmm
      n = split(text, f, /[[:space:]]+/)
      if (n >= 7 && (f[5] in month)) {
        split(f[7], hm, ":")
        stamp = sprintf("%04d%02d%02d%02d%02d", f[6], month[f[5]], f[4], hm[1], hm[2])
        if (oldest == 0 || stamp < oldest) oldest = stamp
      }
    }
    next
  }
  {
    line = $0
    sub(/#.*/, "", line)
    sub(/^[[:space:]]+/, "", line)
    n = split(line, fields, /[[:space:]]+/)
    if (n < 2 || (fields[1] != "0.0.0.0" && fields[1] != "::")) next
    count = 0
    for (i = 2; i <= n; i++) {
      name = tolower(fields[i])
      if (name != "" && name != "localhost" && name !~ /\.localhost$/ && name != "ip6-localhost" && name != "ip6-loopback" && name != "0.0.0.0") count++
    }
    if (count > 0) { names += count; lines++ }
  }
  END { print names + 0, lines + 0, headers + 0, declared + 0, (oldest == 0 ? "0" : oldest) }
' "$hosts_file" 2>/dev/null) || { printf 'UNKNOWN|%s non interpretabile' "$hosts_file"; exit 0; }

if ((names == 0)); then
  printf 'ABSENT|nessuna voce di blocco rilevata'
  exit 0
fi
summary="$names nomi bloccati su $lines righe (minimo $min_entries); nomi host omessi"
if ((headers == 0)); then
  if [[ $require_hagezi == true ]]; then
    printf 'NOT_HAGEZI|%s, ma nessuna intestazione HaGeZi (# Title: HaGeZi'\''s …, # Homepage: https://github.com/hagezi/…)' "$summary"
    exit 0
  fi
elif ((lines < declared)); then
  printf 'INCOMPLETE|lista HaGeZi incompleta: %s righe di blocco su %s dichiarate' "$lines" "$declared"
  exit 0
fi
if ((names < min_entries)); then
  printf 'FEW|solo %s: non è una blocklist completa' "$summary"
  exit 0
fi
if ((headers > 0 && max_age_days > 0)); then
  if ((oldest == 0)); then
    printf 'STALE|lista HaGeZi senza data di aggiornamento leggibile; %s' "$summary"
    exit 0
  fi
  limit=$(/bin/date -u -v-"${max_age_days}"d +%Y%m%d%H%M 2>/dev/null) || limit=''
  if [[ -z $limit ]]; then
    printf 'STALE|data limite non calcolabile; %s' "$summary"
    exit 0
  elif ((oldest < limit)); then
    printf 'STALE|lista HaGeZi non aggiornata da più di %s giorni (%s UTC); %s' "$max_age_days" "${oldest:0:4}-${oldest:4:2}-${oldest:6:2}" "$summary"
    exit 0
  fi
  summary="lista HaGeZi ($headers, $declared voci dichiarate), $summary"
fi
printf 'PRESENT|%s' "$summary"
