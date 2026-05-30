#!/bin/bash
# Anomaly (2): queue build-up / micro-burst.
#
# In bmv2 the TCLink bandwidth cap lives in the *Linux* qdisc, AFTER the
# switch, so it does NOT fill the switch's internal egress queue.  To make
# queue_depth / hop_latency (deq_qdepth / deq_timedelta) observable we
# throttle the bmv2 egress port itself with `set_queue_rate`; a burst of
# traffic then backs up inside the switch.
#
# Usage:
#   inject_queue.sh rate  <thrift_port> <rate_pps> [eg_port]
#   inject_queue.sh depth <thrift_port> <max_pkts> [eg_port]
#   inject_queue.sh clear <thrift_port> [eg_port]
set -u
ACTION="${1:?action: rate|depth|clear}"
TPORT="${2:?thrift_port}"
CLI="simple_switch_CLI --thrift-port $TPORT"

case "$ACTION" in
  rate)
    RATE="${3:?rate_pps}"; PORT="${4:-}"
    echo "set_queue_rate $RATE $PORT" | $CLI
    echo "[inject] queue_rate=$RATE pps on thrift:$TPORT port=${PORT:-all}" ;;
  depth)
    DEPTH="${3:?max_pkts}"; PORT="${4:-}"
    echo "set_queue_depth $DEPTH $PORT" | $CLI
    echo "[inject] queue_depth=$DEPTH on thrift:$TPORT port=${PORT:-all}" ;;
  clear)
    PORT="${3:-}"
    echo "set_queue_rate 100000 $PORT" | $CLI
    echo "[inject] queue_rate restored on thrift:$TPORT port=${PORT:-all}" ;;
  *) echo "unknown action $ACTION"; exit 1 ;;
esac
