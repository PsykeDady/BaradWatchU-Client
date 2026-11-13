#!/bin/bash
# shellcheck disable=SC1112 # typographic apostrophes in Italian messages are intended
# REQ-009 — boot security on macOS (REQUIREMENTS SEC-012/SEC-013). Unprivileged sources:
#   - csrutil status: System Integrity Protection;
#   - system_profiler SPiBridgeDataType: Secure Boot policy, Signed System Volume, kernel CTRR on
#     Macs with an Apple security chip (Apple silicon or T2). Its values follow the user's
#     language; they are mapped back to Apple's English keys through the reporter's own
#     localization table, so the result does not depend on the interface language;
#   - hardware: Apple silicon or T2 provide the Secure Enclave (hardware key store, the role of
#     a TPM on other platforms). Intel Macs without T2 and virtual machines have no hardware
#     Secure Boot: that part is not applicable, never a failure (REQUIREMENTS §5.1).
#   PASS: Full Security (or T2 Full), SIP and Signed System Volume enabled.
#   FAIL: SIP or Signed System Volume disabled, Permissive/No Security boot policy.
#   WARN: Reduced/Medium Security, or a policy that cannot be read or recognised.
#   NOT_APPLICABLE: no Apple security chip (Intel without T2, virtual machine) with SIP enabled.
set -u
id=REQ-009
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

details=() problems=() unknown=()
model=$(/usr/sbin/sysctl -n hw.model 2>/dev/null) || model='?'
if [ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ]; then
  platform='Apple silicon' chip=1
else
  platform='Intel' chip=0
fi
virtual=$(/usr/sbin/sysctl -n kern.hv_vmm_present 2>/dev/null) || virtual=0

sip=$(/usr/bin/csrutil status 2>/dev/null) || sip=''
case $sip in
  *'status: enabled.'*) details+=('System Integrity Protection: attiva') ;;
  *'status: disabled.'*) problems+=('System Integrity Protection disattivata') ;;
  *'Custom Configuration'*|*'status: unknown'*) problems+=('System Integrity Protection in configurazione personalizzata (parzialmente disattivata)') ;;
  *) unknown+=('stato di System Integrity Protection non leggibile') ;;
esac

# Localized value -> Apple's English key, using the reporter's localization table.
reporter=/System/Library/SystemProfiler/SPiBridgeReporter.spreporter/Contents/Resources/Localizable.loctable
english() {
  local value=$1 key
  case $value in
    'Full Security'|'Medium Security'|'Reduced Security'|'Permissive Security'|'No Security'|Enabled|Disabled) printf '%s' "$value"; return 0 ;;
  esac
  [ -r "$reporter" ] || { printf '%s' "$value"; return 0; }
  value=${value//&/&amp;}; value=${value//</&lt;}; value=${value//>/&gt;}
  key=$(/usr/bin/plutil -convert xml1 -o - "$reporter" 2>/dev/null | /usr/bin/awk -v want="<string>$value</string>" '
    { sub(/^[[:space:]]+/, "") }
    /^<key>/ { last = $0 }
    $0 == want && last ~ /^<key>(Full|Medium|Reduced|Permissive|No) Security<\/key>$|^<key>(En|Dis)abled<\/key>$/ {
      gsub(/<\/?key>/, "", last); print last; exit
    }')
  printf '%s' "${key:-$1}"
}
report=$(/usr/sbin/system_profiler -json SPiBridgeDataType 2>/dev/null) || report=''
field() { # KEY -> raw value from the first SPiBridgeDataType item
  printf '%s' "$report" | /usr/bin/plutil -extract "SPiBridgeDataType.0.$1" raw -o - - 2>/dev/null
}
secure_boot=$(field ibridge_secure_boot) || secure_boot=''
if [ "$chip" = 0 ] && [ -n "$(field ibridge_model_name)$secure_boot" ]; then
  chip=1 platform='Intel con chip di sicurezza Apple T2'
fi
details+=("Piattaforma: $platform ($model)$([ "$virtual" = 1 ] && printf ', macchina virtuale')")

if [ "$chip" = 1 ] && [ -n "$secure_boot" ]; then
  policy=$(english "$secure_boot")
  ssv=$(english "$(field ibridge_sb_ssv)")
  ctrr=$(english "$(field ibridge_sb_ctrr)")
  details+=("Avvio sicuro: $secure_boot")
  details+=("Signed System Volume: ${ssv:-non riportato}; Kernel CTRR: ${ctrr:-non riportato}")
  details+=('Secure Enclave presente (archivio chiavi hardware, ruolo equivalente al TPM)')
  case $policy in
    'Full Security') ;;
    'Medium Security'|'Reduced Security') unknown+=("criterio di avvio ridotto ($secure_boot): consente sistemi o estensioni non pienamente verificati") ;;
    'Permissive Security'|'No Security') problems+=("avvio sicuro disattivato ($secure_boot)") ;;
    *) unknown+=("criterio di avvio non riconosciuto ($secure_boot)") ;;
  esac
  case $ssv in Disabled) problems+=('Signed System Volume disattivato') ;; esac
elif [ "$chip" = 1 ]; then
  unknown+=('criterio di avvio sicuro non leggibile (system_profiler SPiBridgeDataType)')
fi

join() { local IFS=';'; printf '%s' "$*" | /usr/bin/sed 's/;/; /g'; }
if ((${#problems[@]})); then
  for item in ${unknown[@]+"${unknown[@]}"}; do details+=("non verificato: $item"); done
  emit FAIL "Protezioni di avvio insufficienti: $(join "${problems[@]}")" "${details[@]}"
fi
if [ "$chip" = 0 ] || { [ "$virtual" = 1 ] && [ -z "$secure_boot" ]; }; then
  if ((${#unknown[@]})); then
    emit WARN "Protezioni di avvio non verificabili: $(join "${unknown[@]}")" "${details[@]}"
  fi
  emit NOT_APPLICABLE 'Avvio sicuro hardware non disponibile su questo Mac (nessun chip di sicurezza Apple); SIP attiva' "${details[@]}" \
    'Secure Boot e Secure Enclave richiedono Apple silicon o un chip T2: l’assenza non è considerata una violazione'
fi
if ((${#unknown[@]})); then
  emit WARN "Protezioni di avvio non pienamente verificate: $(join "${unknown[@]}")" "${details[@]}"
fi
emit PASS 'Avvio sicuro con Sicurezza totale, SIP e volume di sistema firmato attivi' "${details[@]}"
