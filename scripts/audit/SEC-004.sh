#!/usr/bin/bash
# Offline configuration indicators. Never print domains, addresses or raw content.
set -u -o pipefail
bounded() {
    local size
    [[ -f "$1" && -r "$1" ]] || return 1
    size=$(/usr/bin/stat -Lc '%s' -- "$1" 2>&1) || return 1
    [[ $size =~ ^[0-9]+$ && ${#size} -le 9 ]] || return 1
    (( size <= 67108864 ))
}
hosts=null
if bounded /etc/hosts; then
    value=$(/usr/bin/awk '{sub(/#.*/, ""); if ($1=="0.0.0.0" || $1=="::") for(i=2;i<=NF;i++) if($i!="localhost" && $i!="ip6-localhost") n++} END {print n+0}' /etc/hosts) && hosts=$value
fi
resolver='"UNKNOWN"'
if bounded /etc/resolv.conf; then
    value=$(/usr/bin/awk '$1=="nameserver" {n++; if($2=="127.0.0.1" || $2=="::1") localn++} END {if(!n) print "UNKNOWN"; else if(localn==n) print "LOOPBACK_ONLY"; else if(localn) print "MIXED"; else print "OTHER"}' /etc/resolv.conf) && resolver="\"$value\""
fi
nss='"UNKNOWN"'
if bounded /etc/nsswitch.conf; then
    value=$(/usr/bin/awk '{sub(/#.*/, "")} /^[[:space:]]*hosts:/ {n++; for(i=2;i<=NF;i++) if($i=="files") f=1} END {if(n!=1) print "UNKNOWN"; else if(f) print "FILES_PRESENT"; else print "FILES_ABSENT"}' /etc/nsswitch.conf) && nss="\"$value\""
fi
rules=null
for path in /etc/dnsmasq.d/.hagezi-ultimate.servers /etc/dnsmasq.d/hagezi/hagezi-ultimate.servers /var/lib/dnsmasq-hagezi/hagezi-ultimate.servers; do
    if bounded "$path"; then
        value=$(/usr/bin/awk '/^server=\/[a-zA-Z0-9._-]+\/$/ {n++} END {print n+0}' "$path") && rules=$value
        break
    fi
done
service='"UNKNOWN"'
value=$(/usr/bin/systemctl is-active dnsmasq.service 2>&1); code=$?
case "$code:$value" in
    0:active) service='"ACTIVE"';;
    3:inactive) service='"INACTIVE"';;
    3:failed) service='"FAILED"';;
esac
printf '{"hostsSinkEntries":%s,"resolver":%s,"nss":%s,"candidateDnsmasqRules":%s,"dnsmasq":%s}\n' "$hosts" "$resolver" "$nss" "$rules" "$service"
