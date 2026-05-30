#!/bin/bash
# Anomaly (1)/(2): link delay / loss / fault via tc netem on an interface.
#
# Usage:
#   inject_delay.sh add <intf> <delay_ms> [loss_pct] [duration_s]
#   inject_delay.sh del <intf>
#
# <intf> is a switch/host veth name (e.g. s1-eth1).  Run in the root netns
# for switch veths.  loss_pct>0 emulates packet loss / a flaky link.
set -u
ACTION="${1:?action: add|del}"
INTF="${2:?interface}"

if [ "$ACTION" = "del" ]; then
    tc qdisc del dev "$INTF" root 2>/dev/null
    echo "[inject] cleared netem on $INTF"
    exit 0
fi

DELAY_MS="${3:-50}"
LOSS_PCT="${4:-0}"
DURATION="${5:-0}"

NETEM="delay ${DELAY_MS}ms"
[ "$LOSS_PCT" != "0" ] && NETEM="$NETEM loss ${LOSS_PCT}%"

tc qdisc replace dev "$INTF" root netem $NETEM
echo "[inject] $INTF <- netem $NETEM"
tc qdisc show dev "$INTF"

if [ "$DURATION" != "0" ]; then
    sleep "$DURATION"
    tc qdisc del dev "$INTF" root 2>/dev/null
    echo "[inject] auto-cleared netem on $INTF after ${DURATION}s"
fi
