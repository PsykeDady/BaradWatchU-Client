#!/usr/bin/bash
# shellcheck disable=SC1112
# REQ-008 — password policy (REQUIREMENTS SEC-008/009/010).
# Criterion: current account max age <= maxPasswordAgeDays (60) and not "never";
# expiry warning >= minimumWarningDays (10); /etc/login.defs PASS_MAX_DAYS within the same
# limit for new accounts; pwquality minlen >= minimumLength (14), minclass >= minimumClasses (4),
# u/l/d/ocredit <= -1 (one character of each class); pam_pwquality/passwdqc in PAM.
set -u -o pipefail
id=REQ-008
input=''
[[ -t 0 ]] || input=$(/usr/bin/cat 2>/dev/null || true)
read -r max_required min_warning min_length min_classes require_credits <<<"$(printf '%s' "$input" | /usr/bin/python3 -c '
import json, sys
try:
    p = json.load(sys.stdin).get("parameters", {})
except Exception:
    p = {}
credits = p.get("requireCharacterCredits", True)
print(p.get("maxPasswordAgeDays", 60), p.get("minimumWarningDays", 10), p.get("minimumLength", 14),
      p.get("minimumClasses", 4), "yes" if credits is True else ("no" if credits is False else credits))
' 2>/dev/null)"
max_required=${max_required:-60} min_warning=${min_warning:-10} min_length=${min_length:-14}
min_classes=${min_classes:-4} require_credits=${require_credits:-yes}
for value in "$max_required" "$min_warning" "$min_length" "$min_classes"; do
  if [[ ! $value =~ ^[0-9]+$ ]] || [[ $require_credits != yes && $require_credits != no ]]; then
    printf '{"id":"%s","status":"ERROR","summary":"Parametri password non validi: servono interi non negativi e requireCharacterCredits booleano","details":[]}' "$id"
    exit 0
  fi
done
user=${USER:-}
if [[ -z $user || ! -x /usr/bin/chage ]]; then
  printf '{"id":"%s","status":"WARN","summary":"Non è possibile leggere la scadenza della password dell’utente corrente","details":["Comando richiesto: /usr/bin/chage e account locale leggibile","Per installare chage su Arch: sudo pacman -S --needed shadow"]}' "$id"
  exit 0
fi
aging=$(/usr/bin/env LC_ALL=C /usr/bin/chage -l "$user" 2>/dev/null) || {
  rc=$?
  printf '{"id":"%s","status":"WARN","summary":"chage non ha potuto leggere i limiti password dell’account corrente","details":["chage exit-code=%s","possibili cause: interfaccia shadow non accessibile, account non locale o provider esterno; diagnostica grezza omessa"]}' "$id" "$rc"
  exit 0
}
field() { printf '%s\n' "$aging" | /usr/bin/awk -F: -v k="$1" 'index($1,k) {sub(/^[[:space:]]+/,"",$2); sub(/[[:space:]]+$/,"",$2); print $2}'; }
max_days=$(field 'Maximum number of days between password change')
warn_days=$(field 'Number of days of warning before password expires')
expires=$(field 'Password expires')
defs_max=$(/usr/bin/awk '$1=="PASS_MAX_DAYS" {v=$2} END {print v}' /etc/login.defs 2>/dev/null)
quality_files=(/etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
quality="$(/usr/bin/grep -hE '^[[:space:]]*(minlen|minclass|[uldo]credit)[[:space:]]*=' "${quality_files[@]}" 2>/dev/null || true)"
qvalue() { printf '%s\n' "$quality" | /usr/bin/awk -F= -v k="$1" '{key=$1; gsub(/[[:space:]]/,"",key); if (key==k) {v=$2; gsub(/[[:space:]]/,"",v)}} END {print v}'; }
configured_len=$(qvalue minlen)
configured_classes=$(qvalue minclass)
credits=()
for credit in ucredit lcredit dcredit ocredit; do credits+=("$credit=$(qvalue "$credit")"); done
pam_present=no
/usr/bin/grep -Eqs '^[^#]*(pam_pwquality\.so|pam_passwdqc\.so)' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/passwd && pam_present=yes

problems=() unknown=()
integer() { [[ $1 =~ ^-?[0-9]+$ ]]; }
if integer "$max_days"; then
  if ((max_days < 0 || max_days == 0 || max_days > max_required)) || [[ $expires == never ]]; then problems+=("scadenza password dell’account oltre $max_required giorni o assente"); fi
else unknown+=("scadenza account"); fi
if integer "$warn_days"; then ((warn_days >= min_warning)) || problems+=("preavviso scadenza di $warn_days giorni (minimo $min_warning)"); else unknown+=("preavviso"); fi
if integer "$defs_max"; then ((defs_max <= max_required)) || problems+=("PASS_MAX_DAYS=$defs_max in /etc/login.defs (massimo $max_required) per i nuovi account"); else unknown+=("PASS_MAX_DAYS"); fi
if integer "$configured_len"; then ((configured_len >= min_length)) || problems+=("minlen=$configured_len (minimo $min_length)"); else unknown+=("minlen"); fi
if integer "$configured_classes"; then ((configured_classes >= min_classes)) || problems+=("minclass=$configured_classes (minimo $min_classes)"); else unknown+=("minclass"); fi
if [[ $require_credits == yes ]]; then
  for entry in "${credits[@]}"; do
    value=${entry#*=}
    if integer "$value"; then ((value <= -1)) || problems+=("$entry (richiesto -1: almeno un carattere della classe)"); else unknown+=("${entry%%=*}"); fi
  done
fi
[[ $pam_present == yes ]] || unknown+=("modulo pam_pwquality in PAM")

join() { local IFS=';'; printf '%s' "$*" | /usr/bin/sed 's/;/; /g'; }
details=$(printf '"max-age-days=%s (soglia %s)","password-expires=%s","warning-days=%s (minimo %s)","login.defs PASS_MAX_DAYS=%s","minlen=%s (minimo %s)","minclass=%s (minimo %s)","%s","PAM-quality-module=%s"' \
  "${max_days:-unknown}" "$max_required" "${expires:-unknown}" "${warn_days:-unknown}" "$min_warning" "${defs_max:-unknown}" \
  "${configured_len:-unknown}" "$min_length" "${configured_classes:-unknown}" "$min_classes" "$(join "${credits[@]}")" "$pam_present")
if ((${#problems[@]})); then
  printf '{"id":"%s","status":"FAIL","summary":"Policy password non conforme: %s","details":[%s]}' "$id" "$(join "${problems[@]}")" "$details"
elif ((${#unknown[@]})); then
  printf '{"id":"%s","status":"WARN","summary":"Policy password non verificabile per: %s","details":[%s]}' "$id" "$(join "${unknown[@]}")" "$details"
else
  printf '{"id":"%s","status":"PASS","summary":"Scadenza, preavviso e complessità delle password rispettano le soglie richieste","details":[%s]}' "$id" "$details"
fi
