#!/bin/bash
# One-shot PoolINT M1 demo:
#   compile baseline INT -> clean mininet -> bring up leaf-spine ->
#   load+populate switches -> baseline capture -> inject delay & queue ->
#   print acceptance summary.
#
# Needs root for Mininet.  If not root, re-runs the network step under sudo
# (uses SUDO_ASKPASS if set, else interactive sudo).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SCENARIO="${1:-demo}"

echo "== compiling baseline INT =="
p4c --target bmv2 --arch v1model --std p4-16 -o build \
    p4src/baseline_int/baseline_int.p4
echo "   build/baseline_int.json: $(stat -c%s build/baseline_int.json) bytes"

echo "== bringing up network / scenario: $SCENARIO =="
NET_CMD="cd '$ROOT' && mn -c >/dev/null 2>&1; python3 scripts/net_runner.py --scenario '$SCENARIO'"
if [ "$(id -u)" -eq 0 ]; then
    bash -c "$NET_CMD"
elif [ -n "${SUDO_ASKPASS:-}" ]; then
    sudo -A bash -c "$NET_CMD"
else
    sudo bash -c "$NET_CMD"
fi

echo
python3 scripts/summarize.py
