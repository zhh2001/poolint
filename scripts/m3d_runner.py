#!/usr/bin/env python3
"""M3d-1 (NETWORK run): grow |O| via many-to-many + multi-sink capture.

- k=4 fat-tree, serial bring-up (memory-conscious; abort if MemAvailable drops).
- Many-to-many cross-pod UDP: every host sends to every host in the OTHER pods,
  several source ports for ECMP path diversity -> traffic traverses (ideally) all
  directed switch egress ports.
- Multi-aggregation capture: tcpdump (ether proto 0x1213, streamed to disk =
  low mem) at ALL 16 hosts; each host's edge does NOT decap (only the collector
  port has a tb_sink entry, verified by m3d_probe), so every host carries the
  raw PoolINT frame. Merging all 16 pcaps == aggregating all edge sinks at one
  analyzer.
- Output: per-host pcap (kept) + merged results/raw/m3d.jsonl (stream-parsed).
  |O| / coverage / gate#0 are computed OFFLINE by scripts/m3d_analyze.py.

OOM discipline: sample MemAvailable each second; if it falls below MEM_FLOOR_MB,
kill everything, write status=OOM_ABORT, stop (NO DATA for the run).
"""
import json
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
import m3a_runner as M
from poolint_collector import parse_pool

RAW = os.path.join(ROOT, "results/raw")
PCAPS = os.path.join(RAW, "m3d_pcaps")
LOGD = os.path.join(ROOT, "logs")
MEM_TOTAL = 11960
MEM_FLOOR_MB = 1200
SECS = 12


def main():
    os.makedirs(PCAPS, exist_ok=True)
    setLogLevel("info")
    topo = FatTree(k=4)
    info("[m3d] %s\n" % topo.summary())
    info("[mem] before bring-up: %d MB\n" % M.mem_avail_mb())
    net, thrift = M.build_net(topo, M.POOL_JSON, LOGD)
    net.start()
    time.sleep(1.0)
    info("[mem] after net.start: %d MB\n" % M.mem_avail_mb())
    M.populate(topo, thrift, os.path.join(ROOT, "results/ftcmds"))
    M.static_arp(net, topo)

    hosts = list(topo.hosts.keys())                 # all 16 + collector
    # capture at ALL hosts
    procs = {}
    for hn in hosts:
        pc = os.path.join(PCAPS, "%s.pcap" % hn)
        cmd = "tcpdump -i %s-eth0 -w %s ether proto 0x1213 2>/dev/null" % (hn, pc)
        procs[hn] = net.get(hn).popen(cmd, shell=True)
    time.sleep(2.0)
    info("[mem] after %d tcpdumps: %d MB\n" % (len(procs), M.mem_avail_mb()))

    # many-to-many cross-pod: host -> every host in other pods, 2 sports
    sports = [40001, 40002, 40003]
    nflows = 0
    for s in hosts:
        if topo.hosts[s].get("collector"):
            continue
        sp_pod = topo.hosts[s]["pod"]
        sh = net.get(s)
        sip = topo.host_ip(s)
        for d in hosts:
            if d == s:
                continue
            if topo.hosts[d]["pod"] == sp_pod:
                continue                            # cross-pod only
            dip = topo.host_ip(d)
            for sp in sports:
                sh.cmd("iperf -c %s -u -b 1M -t %d -l 200 -p 5001 -B %s:%d "
                       ">/dev/null 2>&1 &" % (dip, SECS, sip, sp))
                nflows += 1
    info("[m3d] launched %d cross-pod flows\n" % nflows)

    peak_used = 0
    oom = False
    for _ in range(SECS + 6):
        time.sleep(1.0)
        avail = M.mem_avail_mb()
        peak_used = max(peak_used, MEM_TOTAL - avail)
        if avail < MEM_FLOOR_MB:
            oom = True
            info("[m3d] MEM FLOOR HIT avail=%d -> abort\n" % avail)
            break
    time.sleep(2.0)

    for hn in hosts:
        net.get(hn).cmd("pkill -f iperf 2>/dev/null")
    time.sleep(1.0)
    for hn, p in procs.items():
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(1.5)
    net.stop()

    status = "OOM_ABORT" if oom else "OK"
    meta = {"status": status, "peak_used_mb": peak_used, "n_flows": nflows,
            "n_capture_hosts": len(hosts), "secs": SECS,
            "n_monitored_ports": topo.n_monitored_ports()}
    json.dump(meta, open(os.path.join(ROOT, "results/m3d_runmeta.json"), "w"),
              indent=2)
    info("[m3d] status=%s peak_used=%dMB flows=%d\n"
         % (status, peak_used, nflows))
    if oom:
        info("[m3d] NO DATA (OOM). pcaps partial; not merging.\n")
        return

    # stream-parse all pcaps -> merged jsonl (low mem)
    from scapy.all import PcapReader
    merged = os.path.join(RAW, "m3d.jsonl")
    n_written = 0
    per_host = {}
    with open(merged, "w") as jf:
        for hn in hosts:
            pc = os.path.join(PCAPS, "%s.pcap" % hn)
            if not os.path.exists(pc):
                per_host[hn] = 0
                continue
            c = 0
            try:
                for pk in PcapReader(pc):
                    r = parse_pool(bytes(pk))
                    if r is None:
                        continue
                    r["cap_host"] = hn
                    jf.write(json.dumps(r) + "\n")
                    c += 1
            except Exception:
                pass
            per_host[hn] = c
            n_written += c
    meta["merged_frames"] = n_written
    meta["per_host_frames"] = per_host
    json.dump(meta, open(os.path.join(ROOT, "results/m3d_runmeta.json"), "w"),
              indent=2)
    info("[m3d] merged %d frames -> %s\n" % (n_written, merged))


if __name__ == "__main__":
    main()
