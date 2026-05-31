#!/usr/bin/env python3
"""M3d capture-point probe (small, memory-light).

Question to answer empirically (P4 source too display-mangled to trust): when a
PoolINT-stamped packet egresses to a NON-collector host port (which has no
tb_sink decap entry), does the host-side interface still carry the 0x1213 frame
so we can capture it there? If yes -> multi-sink capture for growing |O| works.

Brings up the k=4 fat-tree ONCE (serial), starts tcpdump (ether proto 0x1213,
streamed to disk = low mem) at the collector + two non-collector hosts in
different pods, sends a few short cross-pod UDP flows to each, and reports the
per-capture-point frame count + peak memory. No analysis here.
"""
import os
import subprocess
import sys
import time

THIS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(THIS)
for sub in ("topo", "control", "collector"):
    sys.path.insert(0, os.path.join(ROOT, sub))

from mininet.log import setLogLevel, info
from fat_tree import FatTree
import m3a_runner as M   # reuse build_net/populate/static_arp/mem_avail_mb

RAW = os.path.join(ROOT, "results/raw")
LOGD = os.path.join(ROOT, "logs")
PCAP = "/tmp/m3d_probe"


def main():
    os.makedirs(RAW, exist_ok=True)
    os.makedirs(PCAP, exist_ok=True)
    setLogLevel("info")
    topo = FatTree(k=4)
    info("[probe] %s\n" % topo.summary())
    info("[mem] before bring-up: %d MB\n" % M.mem_avail_mb())
    net, thrift = M.build_net(topo, M.POOL_JSON, LOGD)
    net.start()
    time.sleep(1.0)
    info("[mem] after net.start: %d MB\n" % M.mem_avail_mb())
    M.populate(topo, thrift, os.path.join(ROOT, "results/ftcmds"))
    M.static_arp(net, topo)

    col = topo.collector_name()                      # hcol on e3_1
    cap_hosts = [col, "h0_0_0", "h1_1_0"]            # collector + 2 non-collector
    peak_used = 0

    procs = {}
    for hn in cap_hosts:
        h = net.get(hn)
        pc = os.path.join(PCAP, "%s.pcap" % hn)
        cmd = "tcpdump -i %s-eth0 -w %s ether proto 0x1213 2>/dev/null" % (hn, pc)
        procs[hn] = h.popen(cmd, shell=True)
    time.sleep(1.5)

    # senders: a handful of cross-pod sources to each capture host
    srcs = ["h2_0_0", "h2_1_0", "h3_0_0", "h0_1_0", "h1_0_0"]
    for dst in cap_hosts:
        dip = topo.host_ip(dst)
        for s in srcs:
            if s == dst:
                continue
            sh = net.get(s)
            for sp in (40001, 40002):
                sh.cmd("iperf -c %s -u -b 2M -t 6 -l 200 -p 5001 -B %s:%d "
                       ">/dev/null 2>&1 &" % (dip, topo.host_ip(s), sp))
    for _ in range(8):
        time.sleep(1.0)
        avail = M.mem_avail_mb()
        used = 11960 - avail
        peak_used = max(peak_used, used)
    time.sleep(2.0)

    for hn in cap_hosts:
        net.get(hn).cmd("pkill -f iperf 2>/dev/null")
    time.sleep(1.0)
    for hn, p in procs.items():
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(1.0)
    net.stop()

    # count frames per pcap (tcpdump -r ... | wc -l), via subprocess
    counts = {}
    for hn in cap_hosts:
        pc = os.path.join(PCAP, "%s.pcap" % hn)
        try:
            out = subprocess.run("tcpdump -r %s 2>/dev/null | wc -l" % pc,
                                 shell=True, capture_output=True, text=True)
            counts[hn] = int(out.stdout.strip() or "0")
        except Exception as e:
            counts[hn] = "ERR:%s" % e
    res = {"counts": counts, "peak_used_mb": peak_used,
           "cap_hosts": cap_hosts}
    import json
    json.dump(res, open("/tmp/m3d_probe_result.json", "w"), indent=2)
    info("[probe] RESULT counts=%s peak_used=%dMB\n" % (counts, peak_used))


if __name__ == "__main__":
    main()
