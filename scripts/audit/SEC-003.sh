#!/usr/bin/bash
# Shipped collector, executed from embedded source by the guarded Rust runner.
# Facts only: service state does not prove on-access prevention or fresh signatures.
set -u -o pipefail
state() {
    local value code
    value=$(/usr/bin/systemctl is-active "$1" 2>&1); code=$?
    case "$code:$value" in
        0:active) printf '"ACTIVE"';;
        3:inactive) printf '"INACTIVE"';;
        3:failed) printf '"FAILED"';;
        *) printf '"UNKNOWN"';;
    esac
}
prevention=null
config=/etc/clamav/clamd.conf
if [[ -f $config && -r $config ]]; then
    size=$(/usr/bin/stat -Lc '%s' -- "$config" 2>&1) || size=invalid
    if [[ $size =~ ^[0-9]+$ && ${#size} -le 7 ]] && (( size <= 65536 )); then
        value=$(/usr/bin/awk '$1=="OnAccessPrevention" {n++; if(NF==2 && $2=="yes") v="true"; else if(NF==2 && $2=="no") v="false"; else v="null"} END {if(n==1) print v; else print "null"}' "$config") && prevention=$value
    fi
fi
signature_mtime=null
for database in /var/lib/clamav/daily.cld /var/lib/clamav/daily.cvd; do
    if [[ -f $database && -r $database ]]; then
        value=$(/usr/bin/stat -Lc '%Y' -- "$database" 2>&1) || value=invalid
        if [[ $value =~ ^[0-9]+$ && ${#value} -le 12 ]]; then signature_mtime=$value; fi
        break
    fi
done
printf '{"candidatePrevention":%s,"candidateSignatureMtime":%s,"daemon":' "$prevention" "$signature_mtime"; state clamav-daemon.service
printf ',"updater":'; state clamav-freshclam.service
printf ',"onAccess":'; state clamav-clamonacc.service
printf '}\n'
