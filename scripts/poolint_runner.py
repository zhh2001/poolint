#!/usr/bin/env python3
"""PoolINT M2 orchestrator.

Builds a Mininet network (leaf-spine OR line), loads poolint.json on every
bmv2 switch, populates forwarding tables, injects anomalies via register
writes / queue throttling, drives high-rate iperf load (each flow = a fixed
5-tuple => a deterministic path, with thousands of distinct per-packet
test_ids), captures with collector/poolint_collector.py, and writes the
decoded acceptance JSON to results/.

Scenarios (--scenario):
  gate0  : leaf-spine, multi-flow, no anomaly -> check gate #0(a)/(b)
  d1     : line topo, 1 FAIL port           -> COMP/DD F1 (#1)
  d2     : line topo, 3 FAIL ports          -> COMP/DD F1 (#2)
  hops   : leaf 3-hop reference for the overhead invariance check (#3)
  quant  : line topo, queue build-up        -> NNLS severity (#4)
  loss   : line topo, d2 + 10% report drop  -> F1 degradation (#5)

NOTE on iperf: this iperf 2.0.x has NO client source-port option (-B is
host-only, no --cport).  We bind only the source IP (-B <srcip>); the OS
picks the source port.  Path reconstruction stays exact because the
collector reads the ACTUAL 5-tuple per captured packet, and the line topo
has no ECMP (path is source-port-independent).
"""
import argparse
import json
import os
import subprocess
import sys
import time

THIS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(THIS)
for sub in ("topo", "control"):
    sys.path.insert(0, os.path.join(ROOT, sub))

from mininet.net import Mininet
from mininet.link import TCLink, Link
from mininet.log import setLogLevel, info

from leaf_spine import LeafSpine
from line_topo import LineTopo, write_files_line
import gen_commands
import poolint_hash as H
from p4_switch import P4Switch as _P4Switch, P4Host as _P4Host

POOL_JSON = os.path.join(ROOT, "build/poolint.json")
# None => reconstruct_path/ecmp_select use the locked default H.CRC16_CHOSEN (ARC)
CRC_VARIANT = None


# --------------------------------------------------------- build / load
def build_net(topo, json_path, log_dir, is_line):
    net = Mininet(controller=None, link=TCLink, host=_P4Host, switch=_P4Switch)
    swlist = topo.all_switches if is_line else (topo.spines + topo.leaves)
    thrift = {}
    for idx, sw in enumerate(swlist):
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


def populate(topo, thrift, cmd_dir, is_line, cli="simple_switch_CLI"):
    if is_line:
        paths = write_files_line(topo, cmd_dir)
    else:
        paths = gen_commands.write_files(topo, cmd_dir, poolint=True)
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


# --------------------------------------------------------- injectors
def _sw_of(topo, port_uid):
    swid = port_uid >> 8
    return next(s for s, i in topo.swid.items() if i == swid), (port_uid & 0xff)


def _fault_write(thrift, topo, port_uid, val, cli="simple_switch_CLI"):
    """Set/clear M_FAIL for a port_uid: r_fault is indexed by the compact
    local_idx (same mapping as tb_port_idx), NOT by egress_port."""
    import port_index
    sw, egp = _sw_of(topo, port_uid)
    idx = port_index.local_idx(topo, sw, egp)
    subprocess.run('echo "register_write PoolEgress.r_fault %d %d" | %s '
                   '--thrift-port %d' % (idx, val, cli, thrift[sw]),
                   shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return sw


def inject_fail(thrift, topo, port_uid, cli="simple_switch_CLI"):
    return _fault_write(thrift, topo, port_uid, 1, cli)


def clear_fail(thrift, topo, port_uid, cli="simple_switch_CLI"):
    return _fault_write(thrift, topo, port_uid, 0, cli)


def set_queue_rate(thrift, topo, port_uid, rate, cli="simple_switch_CLI"):
    sw, egp = _sw_of(topo, port_uid)
    subprocess.run('echo "set_queue_rate %d %d" | %s --thrift-port %d'
                   % (rate, egp, cli, thrift[sw]), shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return sw


# --------------------------------------------------------- load + capture
def run_flows_and_capture(net, topo, flows, label, results_dir, gt,
                          is_line, topo_args, secs=6, mbit=8, dgram=200,
                          drop_frac=0.0):
    """flows: list of source host names OR (host, sport) tuples.  Each becomes
    one iperf UDP flow to the collector.  When a sport is given we bind it
    (`-B ip:sport`) so the ECMP path is DETERMINISTIC and matches what the
    injector reconstructed; otherwise the OS picks an ephemeral port.  Returns
    the parsed collector summary dict."""
    col = topo.collector_name()
    hcol = net.get(col)
    colip = topo.host_ip(col)

    json_out = os.path.join(results_dir, "%s.json" % label)
    log_out = os.path.join(results_dir, "%s.log" % label)
    gt_out = os.path.join(results_dir, "%s_gt.json" % label)
    if os.path.exists(json_out):
        os.remove(json_out)
    json.dump(gt, open(gt_out, "w"), indent=2)

    hcol.cmd('pkill -f "iperf -s" 2>/dev/null; iperf -s -u -p 5001 '
             '>/tmp/iperf_srv.log 2>&1 &')
    time.sleep(1.0)

    coll = ("python3 %s/collector/poolint_collector.py --iface %s-eth0 "
            "--count 100000 --timeout %d --label %s --json-out %s %s "
            "--gt %s --drop-frac %g > %s 2>&1"
            % (ROOT, col, secs + 6, label, json_out, topo_args, gt_out,
               drop_frac, log_out))
    cproc = hcol.popen(coll, shell=True)
    time.sleep(2.0)

    for f in flows:
        sh, sport = f if isinstance(f, (tuple, list)) else (f, None)
        h = net.get(sh)
        srcip = topo.host_ip(sh)
        bind = "%s:%d" % (srcip, sport) if sport else srcip
        h.cmd("iperf -c %s -u -b %dM -t %d -l %d -p 5001 -B %s "
              ">/tmp/iperf_%s.log 2>&1 &"
              % (colip, mbit, secs, dgram, bind, sh))
    try:
        cproc.wait(timeout=secs + 12)
    except subprocess.TimeoutExpired:
        cproc.kill()
    hcol.cmd('pkill -f "iperf -s" 2>/dev/null')

    summary = {}
    if os.path.exists(json_out):
        summary = json.load(open(json_out))
    info("[%s] pkts=%d gate0a=%s gate0b=%s\n"
         % (label, summary.get("packets", 0),
            summary.get("gate0a_hash"), summary.get("gate0b_path_spine")))
    return summary


# --------------------------------------------------------- scenarios
def scen_gate0(net, topo, results_dir, ta):
    flows = ["h1_1", "h2_1", "h3_1", "h1_2", "h2_2"]
    return run_flows_and_capture(net, topo, flows, "pool_gate0", results_dir,
                                 {"fail_ports": []}, False, ta, secs=6)


def scen_d(net, topo, thrift, results_dir, ta, n_defect, label, drop_frac=0.0):
    flows = ["hA"]
    ports = topo.reconstruct_path(topo.host_ip("hA"), topo.host_ip("hcol"),
                                  17, 40001, 5001, CRC_VARIANT)
    cand = ports[:-1] if len(ports) > n_defect else ports
    targets = [cand[i] for i in
               sorted(set(int(round(k * (len(cand) - 1) / max(1, n_defect - 1)))
                          for k in range(n_defect)))][:n_defect]
    for puid in targets:
        inject_fail(thrift, topo, puid)
    gt = {"fail_ports": targets, "path_ports": ports}
    summ = run_flows_and_capture(net, topo, flows, label, results_dir, gt,
                                 True, ta, secs=8, drop_frac=drop_frac)
    for puid in targets:
        clear_fail(thrift, topo, puid)
    return summ


def scen_d2_leaf(net, topo, thrift, results_dir, ta, label, drop_frac=0.0):
    """Multi-fault d=3 on the LEAF-SPINE topo, deliberately spanning a
    low / medium / high test-coverage port (line topo can't: its coverage is
    uniform).  Flows from 3 source leaves to the collector:
      - collector-leaf egress -> hcol  : on EVERY flow (HIGH coverage)
      - each source-leaf uplink         : on ONE flow  (LOW coverage)
      - a spine downlink to the col leaf: on the flows via that spine (MED)
    We compute per-port flow-coverage from the reconstructed paths, then pick
    the max-, a mid-, and the min-coverage port as the 3 injected faults."""
    # fixed source ports => deterministic ECMP path per flow (so the injector
    # marks the SAME port_uid the packets actually traverse).
    SPORT = 40001
    src_hosts = ["h1_1", "h2_1", "h3_1"]
    flows = [(sh, SPORT) for sh in src_hosts]
    paths = {}
    cover = {}
    for sh in src_hosts:
        pth = topo.reconstruct_path(topo.host_ip(sh), topo.host_ip("hcol"),
                                    17, SPORT, 5001, CRC_VARIANT)
        paths[sh] = pth
        for u in (pth or []):
            cover[u] = cover.get(u, 0) + 1
    order = sorted(cover, key=lambda u: cover[u])     # ascending coverage
    lo = order[0]
    hi = order[-1]
    mid = order[len(order) // 2]
    targets = sorted({lo, mid, hi})
    for puid in targets:
        inject_fail(thrift, topo, puid)
    gt = {"fail_ports": targets,
          "flow_coverage": {str(u): cover[u] for u in cover},
          "target_coverage": {str(u): cover[u] for u in targets},
          "paths": {sh: paths[sh] for sh in paths},
          "n_flows": len(flows)}
    summ = run_flows_and_capture(net, topo, flows, label, results_dir, gt,
                                 False, ta, secs=8, drop_frac=drop_frac)
    for puid in targets:
        clear_fail(thrift, topo, puid)
    return summ


def scen_quant(net, topo, thrift, results_dir, ta):
    flows = ["hA"]
    ports = topo.reconstruct_path(topo.host_ip("hA"), topo.host_ip("hcol"),
                                  17, 40001, 5001, CRC_VARIANT)
    target = ports[len(ports) // 2]
    set_queue_rate(thrift, topo, target, 100)
    gt = {"qdepth_ports": [target], "qhi_ports": [target], "path_ports": ports}
    summ = run_flows_and_capture(net, topo, flows, "pool_quant", results_dir,
                                 gt, True, ta, secs=10, mbit=8)
    set_queue_rate(thrift, topo, target, 100000)
    return summ


# --------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", required=True,
                    choices=["gate0", "d1", "d2", "hops", "quant", "loss"])
    ap.add_argument("--results-dir", default=os.path.join(ROOT, "results"))
    ap.add_argument("--log-dir", default=os.path.join(ROOT, "logs"))
    ap.add_argument("--cmd-dir", default=os.path.join(ROOT, "results/poolcmds"))
    ap.add_argument("--line-n", type=int, default=5)
    args = ap.parse_args()

    os.makedirs(args.results_dir, exist_ok=True)
    os.makedirs(args.log_dir, exist_ok=True)
    setLogLevel("info")

    # d2/loss use leaf-spine (needs coverage variation for the low-coverage
    # port requirement); d1/quant use the line topo (deterministic >3-hop path).
    is_line = args.scenario in ("d1", "quant")
    if is_line:
        topo = LineTopo(n=args.line_n)
        ta = "--topo line --line-n %d" % args.line_n
    else:
        topo = LeafSpine()
        ta = "--topo leaf --spines 2 --leaves 4 --hosts 2"

    info((topo.summary() if hasattr(topo, "summary") else "") + "\n")
    net, thrift = build_net(topo, POOL_JSON, args.log_dir, is_line)
    net.start()
    time.sleep(1.0)
    populate(topo, thrift, args.cmd_dir, is_line)
    static_arp(net, topo)
    time.sleep(1.0)

    try:
        if args.scenario == "gate0":
            scen_gate0(net, topo, args.results_dir, ta)
        elif args.scenario == "d1":
            scen_d(net, topo, thrift, args.results_dir, ta, 1, "pool_d1")
        elif args.scenario == "d2":
            scen_d2_leaf(net, topo, thrift, args.results_dir, ta, "pool_d2")
        elif args.scenario == "loss":
            scen_d2_leaf(net, topo, thrift, args.results_dir, ta, "pool_loss",
                         drop_frac=0.10)
        elif args.scenario == "quant":
            scen_quant(net, topo, thrift, args.results_dir, ta)
        elif args.scenario == "hops":
            run_flows_and_capture(net, topo, ["h1_1"], "pool_hops_leaf",
                                  args.results_dir, {"fail_ports": []},
                                  False, ta, secs=5)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
