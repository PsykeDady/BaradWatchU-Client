#!/usr/bin/bash
# Protocol fixture only, no real firmware inspection.
set -eu
[[ $# == 4 && $1 == --check-id && $2 == SEC-013 && $3 == --schema && $4 == baradwatchu.check-evidence.v1 ]] || exit 2
printf '%s\n' '{"schemaVersion":"baradwatchu.check-evidence.v1","checkId":"SEC-013","availability":"AVAILABLE","data":{"kind":"SECURE_BOOT","values":{"state":"ENABLED","secureBoot":true,"setupMode":false}}}'
