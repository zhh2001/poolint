#!/usr/bin/env python3
"""M3a orchestrator: k-ary fat-tree + PoolINT, raw capture to results/raw/.

Serial bring-up (memory-conscious: ~20 bmv2 switches on a 7.8 GB box).  Each
scenario: optionally inject d FAIL ports chosen to SPAN the test-coverage
distribution (incl. low-coverage ports), drive many fixed-5-tuple iperf flows
(deterministic ECMP paths) from multiple source edges to the collector, and
dump the raw PoolINT frames with collector/m3a_capture.py.  Decoding/metrics
are done OFFLINE by control/m3a_aggregate.py from the raw .jsonl.

Scenarios: gate0 | d1 | d2 | d3 | d5   (--scenario)
"""
import argparse
import json
import os
import subprocess
import sys
import time

THIS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(THIS)
for sub in ("topo", "control", "collector"):
    sys.path.insert(0, os.path.join(ROOT, sub))

from mininet.net import Mininet
from mininet.link import TCLink, Link
from mininet.log import setLogLevel, info

from fat_tree import FatTree
from p4_switch import P4Switch as _P4Switch, P4Host as _P4Host
import fat_tree_cmds
import port_index
import poolint_hash as H

POOL_JSON = os.path.join(ROOT, "build/poolint.json")


def build_net(topo, json_path, log_dir):
    net = Mininet(controller=None, link=TCLink, host=_P4Host, switch=_P4Switch)
    thrift = {}
    for idx, sw in enumerate(topo.all_switches):
        tport = 9090 + idx
        thrift[sw] = tport
        net.addSwitch(sw, cls=_P4Switch, json_path=json_path,
                      thrift_port=tport, device_id=idx, log_dir=log_dir)
    for name, h in topo.hosts.items():
        net.addHost(name, cls=_P4Host, ip=h["ip"], mac=h["mac"])
    for lk in topo.links:
        if lk["host_link"]:
            net.addLink(lk["a"], lk["b"], port1=lk["ap"], port2=lk["bp"], cls=Link)
        else:
            net.addLink(lk["a"], lk["b"], port1=lk["ap"], port2=lk["bp"],
                        cls=TCLink, bw=lk["bw"], delay=lk["delay"])
    return net, thrift


def populate(topo, thrift, cmd_dir, cli="simple_switch_CLI"):
    paths = fat_tree_cmds.write_files(topo, cmd_dir)
    for sw in sorted(paths):
        with open(paths[sw]) as fh:
            subprocess.run("%s --thrift-port %d" % (cli, thrift[sw]),
                           shell=True, stdin=fh, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    info("[populate] loaded %d switch command files\n" % len(paths))


def static_arp(net, topo):
    for hname in topo.hosts:
        h = net.get(hname)
        for g, gi in topo.hosts.items():
            if g != hname:
                h.cmd("arp -s %s %s" % (topo.host_ip(g), gi["mac"]))


def mem_avail_mb():
    for ln in open("/proc/meminfo"):
        if ln.startswith("MemAvailable:"):
            return int(ln.split()[1]) // 1024
    return -1


# ---- flow set: multiple source edges -> collector, fixed source ports ----
def flow_set(topo):
    """One source host per edge (the .0 host), each with 3 fixed source ports
    for ECMP path diversity, all to the collector.  Skip the collector's own
    host.  Returns list of (host, sport)."""
    col = topo.collector_name()
    flows = []
    sports = [40001, 40002, 40003]
    for p in range(topo.k):
        for e in range(topo.h):
            sh = "h%d_%d_0" % (p, e)
            if sh not in topo.hosts or sh == col:
                continue
            for sp in sports:
                flows.append((sh, sp))
    return flows


def coverage_from_flows(topo, flows):
    cov = {}
    paths = {}
    for sh, sp in flows:
        pp = topo.reconstruct_path(topo.host_ip(sh), topo.host_ip("hcol"),
                                   17, sp, 5001)
        paths[(sh, sp)] = pp
        for u in (pp or []):
            cov[u] = cov.get(u, 0) + 1
    return cov, paths


def pick_targets(cov, d):
    """Pick d fault ports spanning the coverage distribution: always include the
    min-coverage port; spread the rest across the sorted-by-coverage list.
    `cov` MUST be OBSERVED coverage (ports on actually-captured collector-bound
    packets), not theoretical -- otherwise a target may carry no real traffic."""
    order = sorted(cov, key=lambda u: (cov[u], u))   # ascending coverage
    if d == 1:
        return [order[0]]
    idxs = sorted(set(round(i * (len(order) - 1) / (d - 1)) for i in range(d)))
    return [order[i] for i in idxs][:d]


def observed_coverage(net, topo, raw_dir, secs=5, mbit=3, dgram=200):
    """No-fault WARM-UP probe: run the flow set, capture at the collector, and
    return {port_uid: #captured packets traversing it} from the raw capture.
    This is the observable set O -- every port in it provably carries real
    collector-bound traffic this session, so targets picked from it can't be
    'on 0 captured paths' (the d1 bug)."""
    import json as _json
    col = topo.collector_name()
    hcol = net.get(col)
    colip = topo.host_ip(col)
    flows = flow_set(topo)
    cap = ("python3 %s/collector/m3a_capture.py --iface %s-eth0 --timeout %d "
           "--label _probe --raw-dir %s > %s/_probe_capture.log 2>&1"
           % (ROOT, col, secs + 6, raw_dir, raw_dir))
    cproc = hcol.popen(cap, shell=True)
    time.sleep(2.0)
    for sh, sp in flows:
        net.get(sh).cmd("iperf -c %s -u -b %dM -t %d -l %d -p 5001 -B %s:%d "
                        ">/dev/null 2>&1 &"
                        % (colip, mbit, secs, dgram, topo.host_ip(sh), sp))
    try:
        cproc.wait(timeout=secs + 12)
    except subprocess.TimeoutExpired:
        cproc.kill()
    hcol.cmd('pkill -f iperf 2>/dev/null')
    cov = {}
    probe = os.path.join(raw_dir, "_probe.jsonl")
    npk = 0
    if os.path.exists(probe):
        for line in open(probe):
            line = line.strip()
            if not line:
                continue
            p = _json.loads(line)
            npk += 1
            pp = topo.reconstruct_path(p["src"], p["dst"], p["proto"],
                                       p["sport"], p["dport"])
            for u in (pp or []):
                cov[u] = cov.get(u, 0) + 1
    return cov, npk


def inject_fault(thrift, topo, port_uid, val, cli="simple_switch_CLI"):
    swid = port_uid >> 8
    egp = port_uid & 0xff
    sw = next(s for s, i in topo.swid.items() if i == swid)
    idx = port_index.local_idx(topo, sw, egp)
    subprocess.run('echo "register_write PoolEgress.r_fault %d %d" | %s '
                   '--thrift-port %d' % (idx, val, cli, thrift[sw]),
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_scenario(net, topo, thrift, label, results_dir, raw_dir, d=0,
                 secs=10, mbit=3, dgram=200):
    col = topo.collector_name()
    hcol = net.get(col)
    colip = topo.host_ip(col)
    flows = flow_set(topo)

    # OBSERVED coverage from a no-fault warm-up probe (the set O); targets are
    # chosen ONLY from ports with real captured traffic.
    cov, probe_pkts = observed_coverage(net, topo, raw_dir)
    info("[%s] probe: %d pkts, |O|=%d observed ports (n=%d)\n"
         % (label, probe_pkts, len(cov), topo.n_monitored_ports()))

    targets = pick_targets(cov, d) if d > 0 else []
    for puid in targets:
        inject_fault(thrift, topo, puid, 1)

    gt = {"fail_ports": targets,
          "d": len(targets),
          "n_monitored_ports": topo.n_monitored_ports(),
          "n_effective_ports": len(cov),
          "probe_packets": probe_pkts,
          "target_coverage": {str(u): cov[u] for u in targets},
          "coverage_distribution": {str(u): cov[u] for u in cov}}
    json.dump(gt, open(os.path.join(results_dir, "%s_gt.json" % label), "w"),
              indent=2)

    # start raw capture at the collector
    cap = ("python3 %s/collector/m3a_capture.py --iface %s-eth0 "
           "--timeout %d --label %s --raw-dir %s > %s/%s_capture.log 2>&1"
           % (ROOT, col, secs + 8, label, raw_dir, raw_dir, label))
    cproc = hcol.popen(cap, shell=True)
    time.sleep(2.0)

    # launch all flows (fixed source ports)
    for sh, sp in flows:
        h = net.get(sh)
        srcip = topo.host_ip(sh)
        h.cmd("iperf -c %s -u -b %dM -t %d -l %d -p 5001 -B %s:%d "
              ">/dev/null 2>&1 &" % (colip, mbit, secs, dgram, srcip, sp))
    info("[%s] %d flows, d=%d targets=%s mem_avail=%dMB\n"
         % (label, len(flows), len(targets), targets, mem_avail_mb()))
    try:
        cproc.wait(timeout=secs + 14)
    except subprocess.TimeoutExpired:
        cproc.kill()
    hcol.cmd('pkill -f iperf 2>/dev/null')
    for puid in targets:
        inject_fault(thrift, topo, puid, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True,
                    choices=["gate0", "d1", "d2", "d3", "d5"])
    ap.add_argument("--k", type=int, default=4)
    ap.add_argument("--results-dir", default=os.path.join(ROOT, "results"))
    ap.add_argument("--raw-dir", default=os.path.join(ROOT, "results/raw"))
    ap.add_argument("--log-dir", default=os.path.join(ROOT, "logs"))
    ap.add_argument("--cmd-dir", default=os.path.join(ROOT, "results/ftcmds"))
    ap.add_argument("--secs", type=int, default=10)
    args = ap.parse_args()
    os.makedirs(args.results_dir, exist_ok=True)
    os.makedirs(args.raw_dir, exist_ok=True)
    os.makedirs(args.log_dir, exist_ok=True)
    setLogLevel("info")

    topo = FatTree(k=args.k)
    info(topo.summary() + "\n")
    info("[mem] before bring-up: %d MB avail\n" % mem_avail_mb())
    net, thrift = build_net(topo, POOL_JSON, args.log_dir)
    net.start()
    time.sleep(1.0)
    info("[mem] after net.start: %d MB avail\n" % mem_avail_mb())
    populate(topo, thrift, args.cmd_dir)
    static_arp(net, topo)
    time.sleep(1.0)

    d = {"gate0": 0, "d1": 1, "d2": 2, "d3": 3, "d5": 5}[args.scenario]
    label = "pool_ft_%s" % args.scenario
    try:
        run_scenario(net, topo, thrift, label, args.results_dir, args.raw_dir,
                     d=d, secs=args.secs)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
