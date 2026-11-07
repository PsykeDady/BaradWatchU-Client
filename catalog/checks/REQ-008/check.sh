#!/usr/bin/bash
# shellcheck disable=SC1112
set -u -o pipefail
id=REQ-008
input=$(/usr/bin/cat)
max_required=$(printf '%s' "$input" | /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("parameters",{}).get("maxPasswordAgeDays",60))' 2>/dev/null) || max_required=60
min_length=$(printf '%s' "$input" | /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("parameters",{}).get("minimumLength",14))' 2>/dev/null) || min_length=14
min_classes=$(printf '%s' "$input" | /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("parameters",{}).get("minimumClasses",4))' 2>/dev/null) || min_classes=4
for value in "$max_required" "$min_length" "$min_classes"; do
  if [[ ! $value =~ ^[0-9]+$ ]]; then
    printf '{"id":"%s","status":"ERROR","summary":"I parametri di conformità password devono essere numeri interi non negativi","details":[]}' "$id"
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
max_days=$(printf '%s\n' "$aging" | /usr/bin/awk -F: '/Maximum number of days between password change/ {gsub(/[[:space:]]/,"",$2); print $2}')
warn_days=$(printf '%s\n' "$aging" | /usr/bin/awk -F: '/Number of days of warning before password expires/ {gsub(/[[:space:]]/,"",$2); print $2}')
quality_files=(/etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf)
quality="$(/usr/bin/grep -hE '^[[:space:]]*(minlen|minclass)[[:space:]]*=' "${quality_files[@]}" 2>/dev/null || true)"
configured_len=$(printf '%s\n' "$quality" | /usr/bin/awk -F= '/^[[:space:]]*minlen[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2); v=$2} END{print v}')
configured_classes=$(printf '%s\n' "$quality" | /usr/bin/awk -F= '/^[[:space:]]*minclass[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2); v=$2} END{print v}')
pam_present=no
/usr/bin/grep -Eq 'pam_pwquality\.so|pam_passwdqc\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/passwd 2>/dev/null && pam_present=yes
bad=no
[[ $max_days =~ ^[0-9]+$ ]] && (( max_days > max_required || max_days == 0 )) && bad=yes
[[ $configured_len =~ ^[0-9]+$ ]] && (( configured_len < min_length )) && bad=yes
[[ $configured_classes =~ ^[0-9]+$ ]] && (( configured_classes < min_classes )) && bad=yes
if [[ $bad == yes ]]; then
  printf '{"id":"%s","status":"FAIL","summary":"Almeno una soglia password configurata è più debole del valore richiesto","details":["max-age-days=%s (soglia=%s)","warning-days=%s","minlen=%s (soglia=%s)","minclass=%s (soglia=%s)","PAM-quality-module=%s"]}' "$id" "${max_days:-unknown}" "$max_required" "${warn_days:-unknown}" "${configured_len:-unknown}" "$min_length" "${configured_classes:-unknown}" "$min_classes" "$pam_present"
elif [[ $pam_present == yes && $max_days =~ ^[0-9]+$ && $configured_len =~ ^[0-9]+$ && $configured_classes =~ ^[0-9]+$ ]]; then
  printf '{"id":"%s","status":"PASS","summary":"Le soglie password osservate rispettano i valori richiesti e il modulo qualità è presente in PAM","details":["max-age-days=%s","warning-days=%s","minlen=%s","minclass=%s"]}' "$id" "$max_days" "${warn_days:-unknown}" "$configured_len" "$configured_classes"
else
  printf '{"id":"%s","status":"WARN","summary":"Le soglie password non sono tutte verificabili: i valori mancanti e la loro applicazione PAM restano da controllare","details":["max-age-days=%s (soglia=%s)","warning-days=%s","minlen=%s (soglia=%s)","minclass=%s (soglia=%s)","PAM-quality-module=%s"]}' "$id" "${max_days:-unknown}" "$max_required" "${warn_days:-unknown}" "${configured_len:-unknown}" "$min_length" "${configured_classes:-unknown}" "$min_classes" "$pam_present"
fi
