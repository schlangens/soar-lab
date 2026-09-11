#!/bin/bash
# Wazuh Active Response: block/unblock IP on pfSense via pfctl table.
# Replaces the ss-prox3 block API (decommissioned): SSHes to pfSense and
# manipulates the Blocked_IPs table directly. No config.xml writes, so no
# easyrule config-corruption risk and blocks take effect instantly.
# Stateful: execd re-invokes with command=delete when <timeout> expires.
# NOTE: pfctl table entries do not survive a pfSense reboot; with the
# timeout/auto-unblock model that is acceptable (re-offenders re-trigger).

LOCAL_LOG="/var/ossec/logs/active-responses.log"
TIMESTAMP=$(date '+%a %b %e %T %Z %Y')
PFSENSE="admin@10.0.0.1"
SSH_OPTS="-i /var/ossec/.ssh/pfsense_ar -o KexAlgorithms=ecdh-sha2-nistp256 -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=10"
TABLE="Blocked_IPs"

# Read one line of JSON from stdin.
# read -t bounds the wait: wazuh-execd holds the pipe open after sending the
# alert, so `cat` would block forever (caused ~2.5h-cycle alert blindness on
# 2026-08-11 by exhausting execd slots). A plain read returns non-zero when
# the line is EOF-terminated rather than newline-terminated but still
# populates INPUT, so test INPUT itself rather than the exit status.
IFS= read -r -t 15 INPUT

if [ -z "$INPUT" ]; then
    echo "$TIMESTAMP pfsense-block.sh ERROR: no input on stdin (timeout or empty)" >> $LOCAL_LOG
    exit 1
fi

PARSED=$(echo "$INPUT" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    cmd = d.get('command', '')
    srcip = d.get('parameters', {}).get('alert', {}).get('data', {}).get('srcip', '')
    print(f'{cmd}|{srcip}')
except Exception as e:
    print(f'error|{e}')
" 2>&1)

ACTION=$(echo "$PARSED" | cut -d'|' -f1)
SRCIP=$(echo "$PARSED" | cut -d'|' -f2)

if [ -z "$SRCIP" ] || ! echo "$SRCIP" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    echo "$TIMESTAMP pfsense-block.sh ERROR: bad/missing srcip (action=$ACTION parsed=$PARSED)" >> $LOCAL_LOG
    exit 1
fi

# Never block RFC1918/loopback/link-local or Anthropic (Claude Code) ranges.
case "$SRCIP" in
    192.168.*|10.*|127.*|169.254.*|203.0.113.*) exit 0 ;;
esac
case "$SRCIP" in
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) exit 0 ;;
esac

# Dedup cache: an already-blocked IP keeps generating blocked-traffic alerts,
# which would re-run this script forever (one IP: 882 retries in a day).
# Cleared harmlessly by manager restart. Entries removed again on delete so
# a re-offending IP can be re-blocked after its timeout expires.
SEEN_CACHE=/var/ossec/tmp/pfsense-block.seen
touch "$SEEN_CACHE" 2>/dev/null || SEEN_CACHE=/tmp/pfsense-block.seen
touch "$SEEN_CACHE"

case "$ACTION" in
  add)
    if grep -qxF "$SRCIP" "$SEEN_CACHE" 2>/dev/null; then
        exit 0   # silent: logging every retry buries the real signal
    fi
    RESULT=$(ssh $SSH_OPTS $PFSENSE "pfctl -t $TABLE -T add $SRCIP && { grep -qxF $SRCIP /var/db/wazuh_ar_blocked.txt 2>/dev/null || echo $SRCIP >> /var/db/wazuh_ar_blocked.txt; }" 2>&1)
    if [ $? -eq 0 ]; then
        echo "$SRCIP" >> "$SEEN_CACHE"
        echo "$TIMESTAMP pfsense-block.sh BLOCKED $SRCIP ($RESULT)" >> $LOCAL_LOG
    else
        # Real failures (pfSense down, ssh broken) stay loud and are NOT
        # cached, so the block is retried on the next alert.
        echo "$TIMESTAMP pfsense-block.sh ERROR blocking $SRCIP: $RESULT" >> $LOCAL_LOG
        exit 1
    fi
    ;;
  delete)
    RESULT=$(ssh $SSH_OPTS $PFSENSE "pfctl -t $TABLE -T delete $SRCIP; grep -vxF $SRCIP /var/db/wazuh_ar_blocked.txt > /var/db/wazuh_ar_blocked.txt.new 2>/dev/null; mv /var/db/wazuh_ar_blocked.txt.new /var/db/wazuh_ar_blocked.txt" 2>&1)
    grep -vxF "$SRCIP" "$SEEN_CACHE" > "$SEEN_CACHE.tmp" 2>/dev/null && mv "$SEEN_CACHE.tmp" "$SEEN_CACHE"
    echo "$TIMESTAMP pfsense-block.sh UNBLOCKED $SRCIP ($RESULT)" >> $LOCAL_LOG
    ;;
  *)
    echo "$TIMESTAMP pfsense-block.sh action=$ACTION srcip=$SRCIP (skipped)" >> $LOCAL_LOG
    ;;
esac
exit 0
