#!/usr/bin/bash
# Only status; no start/stop/restart/recovery. Raw Cato output never leaves this pipeline.
set -u -o pipefail
if [[ ! -x /usr/bin/cato-sdp ]]; then
    printf '{"state":"UNAVAILABLE"}\n'
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
printf '{"state":"%s"}\n' "$state"
