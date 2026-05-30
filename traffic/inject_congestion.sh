#!/bin/bash
# Anomaly (3): utilisation / congestion via a sustained iperf flow.
#
# Meant to be executed *inside a Mininet host netns* (h.cmd(...)).  Starts a
# UDP iperf client toward an already-running iperf server, at a rate high
# enough to saturate the bottleneck link.
#
# Usage (server side): inject_congestion.sh server
#        (client side): inject_congestion.sh client <server_ip> <mbps> <secs>
set -u
ROLE="${1:?role: client|server}"

if [ "$ROLE" = "server" ]; then
    exec iperf -s -u
fi

SERVER="${2:?server_ip}"
MBPS="${3:-50}"
SECS="${4:-10}"
echo "[inject] congestion: iperf UDP -> $SERVER ${MBPS}Mbit for ${SECS}s"
iperf -c "$SERVER" -u -b "${MBPS}M" -t "$SECS"
