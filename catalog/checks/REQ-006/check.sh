#!/usr/bin/bash
set -u -o pipefail
id=REQ-006
dir=${BASH_SOURCE[0]%/*}
luks_status=$("$dir/luks.sh") || luks_status=UNKNOWN
ecryptfs_status=$("$dir/ecryptfs.sh") || ecryptfs_status=UNKNOWN
present=0
unknown=0
[[ $luks_status == PRESENT\|* ]] && ((present+=1))
[[ $ecryptfs_status == PRESENT\|* ]] && ((present+=1))
[[ $luks_status == UNKNOWN\|* || $ecryptfs_status == UNKNOWN\|* ]] && unknown=1

if ((present > 0)); then
  printf '{"id":"%s","status":"PASS","summary":"Rilevato almeno un metodo di cifratura supportato","details":["LUKS: %s","eCryptfs: %s","PASS indica che almeno un metodo è presente; non certifica la cifratura di tutte le aree"]}' "$id" "${luks_status#*|}" "${ecryptfs_status#*|}"
elif ((unknown)); then
  printf '{"id":"%s","status":"WARN","summary":"Non è stato possibile determinare la presenza dei metodi di cifratura supportati","details":["LUKS: %s","eCryptfs: %s"]}' "$id" "${luks_status#*|}" "${ecryptfs_status#*|}"
else
  printf '{"id":"%s","status":"FAIL","summary":"Non è stato rilevato alcun metodo di cifratura supportato","details":["LUKS: %s","eCryptfs: %s","Metodi supportati: LUKS e eCryptfs"]}' "$id" "${luks_status#*|}" "${ecryptfs_status#*|}"
fi
