#!/usr/bin/bash
# Observation-only wrapper. Pass the absolute path of the trusted agent binary.
# Complex security parsing stays in the tested Rust adapter, not duplicated in shell.
set -eu
[[ $# == 1 && $1 == /* && -x $1 ]] || { printf 'Usage: bash SEC-014.sh /absolute/path/baradwatchu-agent\n' >&2; exit 2; }
exec "$1" workstation check SEC-014
