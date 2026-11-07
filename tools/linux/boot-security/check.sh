#!/usr/bin/bash
# shellcheck disable=SC1112
set -u -o pipefail
id=REQ-009
efi=/sys/firmware/efi/efivars
guid=8be4df61-93ca-11d2-aa0d-00e098032b8c
secure=unknown
setup=unknown
details=()

read_efi_value() {
  local name=$1 variable file="$efi/$1-$guid" output value rc
  variable=secure
  [[ $name == SetupMode ]] && variable=setup
  if [[ ! -e $file ]]; then
    printf -v "$variable" '%s' unknown
    details+=("EFI $name: variabile assente; sistema non avviato in UEFI o firmware non la espone")
    return
  fi
  if [[ ! -r $file ]]; then
    printf -v "$variable" '%s' unknown
    details+=("EFI $name: file presente ma non leggibile dall’utente")
    return
  fi
  output=$(/usr/bin/od -An -tu1 -j4 -N1 -- "$file" 2>&1); rc=$?
  value=$(printf '%s' "$output" | /usr/bin/tr -d '[:space:]')
  if ((rc == 0)) && [[ $value =~ ^[01]$ ]]; then
    printf -v "$variable" '%s' "$value"
    details+=("Comando: /usr/bin/od -An -tu1 -j4 -N1 $file")
    details+=("EFI $name: valore=$value, codice uscita od=$rc; output esatto od: $output")
  else
    printf -v "$variable" '%s' unknown
    details+=("Comando: /usr/bin/od -An -tu1 -j4 -N1 $file")
    details+=("EFI $name: codice uscita od=$rc; output=${output:-<vuoto>}")
  fi
}

read_efi_value SecureBoot
read_efi_value SetupMode
details+=("TPM2 comando: /usr/bin/systemd-analyze has-tpm2")
if [[ -x /usr/bin/systemd-analyze ]]; then
  tpm_output=$(/usr/bin/systemd-analyze has-tpm2 2>&1); tpm_rc=$?
  details+=("TPM2 codice uscita: $tpm_rc" "TPM2 output: ${tpm_output:-<vuoto>}")
else
  details+=("TPM2 non verificabile: systemd-analyze non installato; pacchetto Arch: systemd")
fi

if [[ $secure == 1 && $setup == 0 ]]; then
  status=PASS
  summary='Il firmware riporta Secure Boot attivo e SetupMode disattivato'
elif [[ $secure == 0 || $setup == 1 ]]; then
  status=FAIL
  summary='Il firmware riporta Secure Boot disattivato oppure SetupMode attivo'
else
  status=WARN
  summary='Secure Boot non è determinabile; il log riporta perché le variabili EFI non sono state lette'
fi
/usr/bin/python3 -c 'import json,sys; print(json.dumps({"id":sys.argv[1],"status":sys.argv[2],"summary":sys.argv[3],"details":sys.argv[4:]}, ensure_ascii=False))' "$id" "$status" "$summary" "${details[@]}"
