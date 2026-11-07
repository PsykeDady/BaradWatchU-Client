#!/usr/bin/bash
set -u -o pipefail
id=REQ-003
dir=${BASH_SOURCE[0]%/*}
ufw_status=WARN; ufw_evidence='controllo non eseguito'
firewalld_status=WARN; firewalld_evidence='controllo non eseguito'
nftables_status=WARN; nftables_evidence='controllo non eseguito'

read_method() {
  local output=$1
  local method=$2
  local code=${output%%|*}
  local evidence=${output#*|}
  case $code in
    PASS|FAIL|WARN) ;;
    *) code=WARN; evidence='output del controllo non interpretabile';;
  esac
  printf -v "${method}_status" '%s' "$code"
  printf -v "${method}_evidence" '%s' "$evidence"
}

output=$("$dir/ufw.sh") || output='WARN|script UFW non eseguibile'
read_method "$output" ufw
output=$("$dir/firewalld.sh") || output='WARN|script firewalld non eseguibile'
read_method "$output" firewalld
output=$("$dir/nftables.sh") || output='WARN|script nftables non eseguibile'
read_method "$output" nftables

status=FAIL
if [[ $ufw_status == PASS || $firewalld_status == PASS || $nftables_status == PASS ]]; then
  status=PASS
elif [[ $ufw_status == FAIL && $firewalld_status == FAIL && $nftables_status == WARN && $nftables_evidence == *'nftables.service is-active=inactive'* && $nftables_evidence == *'is-enabled=disabled'* ]]; then
  # The managed firewall services are all explicitly disabled/inactive. Keep
  # the inaccessible kernel ruleset caveat in the details, but don't let it
  # mask the host's explicit no-firewall configuration as a generic WARN.
  status=FAIL
elif [[ $ufw_status == WARN || $firewalld_status == WARN || $nftables_status == WARN ]]; then
  status=WARN
fi

case $status in
  PASS) summary='Almeno un firewall supportato risulta operativo';;
  WARN) summary='Nessun firewall operativo è stato verificato; restano evidenze inconclusive';;
  FAIL)
    if [[ $nftables_status == WARN ]]; then
      summary='I firewall gestiti risultano non operativi; ruleset kernel non verificabile'
    else
      summary='Tutti i firewall supportati risultano assenti o non operativi'
    fi
    ;;
esac
printf '{"id":"%s","status":"%s","summary":"%s","details":["UFW [%s]: %s","firewalld [%s]: %s","nftables [%s]: %s"]}' \
  "$id" "$status" "$summary" "$ufw_status" "$ufw_evidence" \
  "$firewalld_status" "$firewalld_evidence" "$nftables_status" "$nftables_evidence"
