#!/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-008 — password policy on macOS (REQUIREMENTS SEC-008/SEC-010) for local accounts.
# Unprivileged source: pwpolicy -getaccountpolicies (global) and pwpolicy -u ACCOUNT
# -getaccountpolicies (per account, including configuration-profile passcode payloads such as
# maxPINAgeInDays, minLength, requireAlphanumeric, minComplexChars). Effective policy of an
# account = global + its own policies (the strictest value wins).
#   FAIL: an enabled local account whose password never expires or expires after more than
#         maxPasswordAgeDays, minimum length below minimumLength, or (requireComplexity) no
#         required letter, digit and non-alphanumeric character.
#   WARN: policies not readable, or accounts managed by a directory (mobile/network accounts).
# SEC-009 (expiry warning days) has no macOS system setting: reported, not evaluated.
# Account names are never reported (ordinals only); passwords and hashes are never read.
set -u
id=REQ-008
input=''
[ -t 0 ] || input=$(/bin/cat 2>/dev/null || true)
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
param_type() { [ -n "$input" ] && printf '%s' "$input" | /usr/bin/plutil -type "parameters.$1" - 2>/dev/null; }
param_raw() { printf '%s' "$input" | /usr/bin/plutil -extract "parameters.$1" raw -o - - 2>/dev/null; }
int_param() { # VARIABLE NAME DEFAULT: a non-negative integer parameter, else ERROR
  local type value=$3
  if type=$(param_type "$2"); then
    value=$(param_raw "$2")
    if [ "$type" != integer ] || ! [[ $value =~ ^[0-9]+$ ]]; then
      emit ERROR "$2 deve essere un intero non negativo"
    fi
  fi
  printf -v "$1" '%s' "$value"
}
int_param max_age maxPasswordAgeDays 60
int_param min_length minimumLength 14
require_complexity=true
if type=$(param_type requireComplexity); then
  [ "$type" = bool ] || emit ERROR 'requireComplexity deve essere true o false'
  require_complexity=$(param_raw requireComplexity)
fi

tmp=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/baradwatchu-req008.XXXXXX") || emit ERROR 'Impossibile creare una cartella temporanea'
trap '/bin/rm -rf "$tmp"' EXIT

# policies OUTPUT_FILE [-u ACCOUNT]: the policy plist (pwpolicy prints a header line first).
policies() {
  local out=$1
  shift
  /usr/bin/pwpolicy "$@" -getaccountpolicies 2>/dev/null | /usr/bin/sed -n '/^<?xml/,$p' > "$out"
  [ -s "$out" ] && /usr/bin/plutil -lint "$out" >/dev/null 2>&1
}
value() { /usr/bin/plutil -extract "$2" raw -o - "$1" 2>/dev/null; }

# analyse FILE: updates age/length/letter/digit/special/upper/lower for the effective policy.
analyse() {
  local file=$1 count i content ident days
  count=$(value "$file" policyCategoryPasswordChange) || count=0
  [[ $count =~ ^[0-9]+$ ]] || count=0
  i=0
  while ((i < count)); do
    days=$(value "$file" "policyCategoryPasswordChange.$i.policyParameters.policyAttributeExpiresEveryNDays") || days=''
    if ! [[ $days =~ ^[0-9]+$ ]]; then
      content=$(value "$file" "policyCategoryPasswordChange.$i.policyContent") || content=''
      days=$(printf '%s' "$content" | /usr/bin/sed -n 's/.*policyAttributeLastPasswordChangeTime + (\([0-9][0-9]*\) \* 24 \* 60 \* 60).*/\1/p')
    fi
    if [[ $days =~ ^[0-9]+$ ]] && ((days > 0)); then
      if [ -z "$age" ] || ((days < age)); then age=$days; fi
    fi
    i=$((i + 1))
  done
  count=$(value "$file" policyCategoryPasswordContent) || count=0
  [[ $count =~ ^[0-9]+$ ]] || count=0
  i=0
  while ((i < count)); do
    content=$(value "$file" "policyCategoryPasswordContent.$i.policyContent") || content=''
    ident=$(value "$file" "policyCategoryPasswordContent.$i.policyIdentifier") || ident=''
    n=$(printf '%s' "$content" | /usr/bin/sed -n "s/.*matches '\\.{\\([0-9][0-9]*\\),.*/\\1/p")
    if [[ $n =~ ^[0-9]+$ ]] && ((n > length)); then length=$n; fi
    case $ident in *:requireAlphanumeric) letter=1 digit=1 ;; *:minComplexChars) special=1 ;; esac
    case $content in *'[^a-zA-Z0-9]'*|*'[^A-Za-z0-9]'*|*'[[:punct:]]'*) special=1 ;; esac
    case $content in *'[0-9]'*|*'[[:digit:]]'*|*'\d'*) digit=1 ;; esac
    case $content in *'[a-zA-Z]'*|*'[A-Za-z]'*|*'[[:alpha:]]'*) letter=1 ;; esac
    case $content in *'[A-Z]'*|*'[[:upper:]]'*) upper=1 ;; esac
    case $content in *'[a-z]'*|*'[[:lower:]]'*) lower=1 ;; esac
    i=$((i + 1))
  done
}

details=() failures=() warnings=()
global="$tmp/global.plist"
if ! policies "$global"; then
  emit WARN 'Le policy password di sistema non sono leggibili (pwpolicy)' 'pwpolicy -getaccountpolicies non ha restituito una policy valida'
fi
accounts=$(/usr/bin/dscl . -list /Users UniqueID 2>/dev/null | /usr/bin/awk '$2 >= 501 && $2 < 1000000 { print $1 }')
[ -n "$accounts" ] || emit WARN 'Nessun account locale leggibile' 'dscl . -list /Users UniqueID senza account con UID >= 501'
ordinal=0 evaluated=0
while IFS= read -r account; do
  [ -n "$account" ] || continue
  ordinal=$((ordinal + 1))
  authority=$(/usr/bin/dscl . -read "/Users/$account" AuthenticationAuthority 2>/dev/null) || authority=''
  case $authority in
    *DisabledUser*) details+=("account $ordinal: disattivato (non valutato)"); continue ;;
  esac
  case $authority in
    *ShadowHash*) ;;
    *) details+=("account $ordinal: senza password locale (non valutato)"); continue ;;
  esac
  case $authority in
    *LocalCachedUser*) warnings+=("account $ordinal gestito da un servizio di directory: le policy effettive sono decise dal server") ;;
  esac
  age='' length=0 letter=0 digit=0 special=0 upper=0 lower=0
  analyse "$global"
  user_file="$tmp/user-$ordinal.plist"
  if policies "$user_file" -u "$account"; then
    analyse "$user_file"
  else
    warnings+=("policy dell'account $ordinal non leggibili")
  fi
  evaluated=$((evaluated + 1))
  classes=''
  ((letter || upper || lower)) && classes+='lettere '
  ((upper && lower)) && classes+='(maiuscole e minuscole) '
  ((digit)) && classes+='cifre '
  ((special)) && classes+='caratteri speciali '
  classes=${classes% }
  failed=$(value "$user_file" policyCategoryAuthentication.0.policyParameters.policyAttributeMaximumFailedAuthentications) ||
    failed=$(value "$global" policyCategoryAuthentication.0.policyParameters.policyAttributeMaximumFailedAuthentications) || failed=''
  details+=("account $ordinal: scadenza ${age:-mai}$([ -n "$age" ] && printf ' giorni'), lunghezza minima $length, caratteri obbligatori: ${classes:-nessuno}${failed:+, tentativi falliti consentiti $failed}")
  if [ -z "$age" ]; then
    failures+=("password dell'account $ordinal senza scadenza")
  elif ((age > max_age)); then
    failures+=("password dell'account $ordinal valida $age giorni (massimo $max_age)")
  fi
  ((length >= min_length)) || failures+=("lunghezza minima $length per l'account $ordinal (richiesti $min_length)")
  if [ "$require_complexity" = true ] && ! (((letter || upper || lower) && digit && special)); then
    failures+=("l'account $ordinal non richiede lettere, cifre e caratteri speciali")
  fi
done <<EOF
$accounts
EOF
((evaluated > 0)) || warnings+=('nessun account locale con password da valutare')
details+=('Preavviso di scadenza (SEC-009): macOS non ha un’impostazione di sistema equivalente; non valutato')

join() { local IFS=';'; printf '%s' "$*" | /usr/bin/sed 's/;/; /g'; }
if ((${#failures[@]})); then
  for item in ${warnings[@]+"${warnings[@]}"}; do details+=("non verificato: $item"); done
  emit FAIL "Requisiti password non rispettati: $(join "${failures[@]}")" "${details[@]}"
fi
if ((${#warnings[@]})); then
  emit WARN "Requisiti password rispettati, ma: $(join "${warnings[@]}")" "${details[@]}"
fi
emit PASS 'Scadenza, lunghezza e complessità delle password rispettano i requisiti' "${details[@]}"
