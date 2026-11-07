#!/usr/bin/bash
# External evidence v1. Only status; no start/stop/restart/recovery. Raw Cato output never leaves this pipeline.
set -u -o pipefail
[[ $# == 4 && $1 == --check-id && $2 == SEC-011 && $3 == --schema && $4 == baradwatchu.check-evidence.v1 ]] || exit 2
if [[ ! -x /usr/bin/cato-sdp ]]; then
    printf '{"schemaVersion":"baradwatchu.check-evidence.v1","checkId":"SEC-011","availability":"UNKNOWN","data":null}\n'
    exit 0
fi
token=$(/usr/bin/cato-sdp status 2>&1 | /usr/bin/awk '
{ while(match($0, /STATE_[A-Z0-9_]+/)) {t=substr($0,RSTART,RLENGTH); seen[t]=1; $0=substr($0,RSTART+RLENGTH)} }
END {for(t in seen) {n++; only=t} if(n==1) print only; else print "UNKNOWN"}') || token=UNKNOWN
case "$token" in
    STATE_AUTHENTICATED|STATE_CONNECTED|STATE_CONNECTED_AUTH) state=CONNECTED;;
    STATE_CONNECTED_UNAUTH|STATE_UNAUTHENTICATED) state=AUTH_REQUIRED;;
    STATE_AUTHENTICATING|STATE_CONNECTING|STATE_RECONNECTING|STATE_RESOLVING) state=CONNECTING;;
    STATE_DISCONNECTING|STATE_DISCONNECTED|STATE_IDLE|STATE_INIT|STATE_STOPPED) state=DISCONNECTED;;
    STATE_ERROR|STATE_FAILED) state=ERROR;;
    *) state=UNKNOWN;;
esac
printf '{"schemaVersion":"baradwatchu.check-evidence.v1","checkId":"SEC-011","availability":"AVAILABLE","data":{"kind":"VPN_INDICATORS","values":{"state":"%s"}}}\n' "$state"
