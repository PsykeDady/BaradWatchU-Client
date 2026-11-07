#!/usr/bin/bash
# REQ-006 — data encryption (REQUIREMENTS SEC-006, skill audit-postazione R4).
# PASS when at least one supported method is active: LUKS/dm-crypt device, mounted eCryptfs,
# or mounted CryFS container. PASS does not certify that every data area is covered.
set -u -o pipefail
id=REQ-006
dir=${BASH_SOURCE[0]%/*}
luks_status=$("$dir/luks.sh") || luks_status='UNKNOWN|script LUKS non eseguibile'
ecryptfs_status=$("$dir/ecryptfs.sh") || ecryptfs_status='UNKNOWN|script eCryptfs non eseguibile'
cryfs_status=$("$dir/cryfs.sh") || cryfs_status='UNKNOWN|script CryFS non eseguibile'
present=0 unknown=0
for value in "$luks_status" "$ecryptfs_status" "$cryfs_status"; do
  [[ $value == PRESENT\|* ]] && ((present+=1))
  [[ $value == UNKNOWN\|* ]] && unknown=1
done
details=$(printf '"LUKS/dm-crypt: %s","eCryptfs: %s","CryFS: %s"' "${luks_status#*|}" "${ecryptfs_status#*|}" "${cryfs_status#*|}")
if ((present > 0)); then
  printf '{"id":"%s","status":"PASS","summary":"Cifratura attiva con %s metodo/i supportato/i","details":[%s,"PASS indica che almeno un metodo è attivo; non certifica la cifratura di tutte le aree"]}' "$id" "$present" "$details"
elif ((unknown)); then
  printf '{"id":"%s","status":"WARN","summary":"Non è stato possibile determinare la presenza dei metodi di cifratura supportati","details":[%s]}' "$id" "$details"
else
  printf '{"id":"%s","status":"FAIL","summary":"Non è stato rilevato alcun metodo di cifratura attivo","details":[%s,"Metodi supportati: LUKS/dm-crypt, eCryptfs, CryFS"]}' "$id" "$details"
fi
