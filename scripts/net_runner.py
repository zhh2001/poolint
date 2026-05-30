#!/usr/bin/env python3
"""PoolINT M1 orchestrator: build the leaf-spine Mininet network, load the
baseline INT program onto every bmv2 switch, populate tables, then run the
demo / anomaly-injection scenarios and capture collector output.

Run as root (Mininet).  Typically invoked by scripts/run_demo.sh.

Scenarios (--scenario):
  demo   : baseline capture, then 50ms link-delay, then queue build-up
  baseline | delay | queue   : a single phase (for targeted re-runs)
  cli    : bring everything up and drop into the Mininet CLI
"""
import argparse
import json
import os
import subprocess
import sys
import time

THIS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(THIS)
sys.path.insert(0, os.path.join(ROOT, "topo"))
sys.path.insert(0, os.path.join(ROOT, "control"))

from mininet.net import Mininet
from mininet.link import TCLink, Link
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from leaf_spine import LeafSpine
from p4_switch import P4Switch, P4Host
import gen_commands


def build_net(topo, json_path, log_dir):
    net = Mininet(controller=None, link=TCLink, host=P4Host, switch=P4Switch)

    thrift = {}
    for idx, sw in enumerate(topo.spines + topo.leaves):
        tport = 9090 + idx
        thrift[sw] = tport
        net.addSwitch(sw, cls=P4Switch, json_path=json_path,
                      thrift_port=tport, device_id=idx, log_dir=log_dir)

    for name, h in topo.hosts.items():
        net.addHost(name, cls=P4Host, ip=h["ip"], mac=h["mac"])

    for lk in topo.links:
        if lk["host_link"]:
            net.addLink(lk["a"], lk["b"], port1=lk["ap"], port2=lk["bp"],
                        cls=Link)
        else:
            net.addLink(lk["a"], lk["b"], port1=lk["ap"], port2=lk["bp"],
                        cls=TCLink, bw=lk["bw"], delay=lk["delay"])
    return net, thrift


def populate(topo, thrift, cmd_dir, cli="simple_switch_CLI"):
    paths = gen_commands.write_files(topo, cmd_dir)
    for sw in sorted(paths):
        n = len(open(paths[sw]).read().splitlines())
        with open(paths[sw]) as fh:
            r = subprocess.run("%s --thrift-port %d" % (cli, thrift[sw]),
                               shell=True, stdin=fh,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        info("[populate] %s (thrift %d): %d cmds\n" % (sw, thrift[sw], n))
        if r.returncode != 0:
            info(r.stdout.decode(errors="replace"))


def static_arp(net, topo):
    for hname in topo.hosts:
        h = net.get(hname)
        for g, gi in topo.hosts.items():
            if g == hname:
                continue
            h.cmd("arp -s %s %s" % (topo.host_ip(g), gi["mac"]))


def run_capture(net, topo, label, results_dir, count=30, timeout=15, pps=20):
    """scapy known-flow capture: start the collector on hcol, send a precise
    low-rate UDP flow from h1_1, return the parsed JSON summary.  Used for the
    #1 trace and #2 link-delay phases (rate accuracy matters, volume doesn't)."""
    col = topo.collector_name()
    hcol = net.get(col)
    src = net.get("h1_1")
    src_info = topo.hosts["h1_1"]
    dst_info = topo.hosts[col]

    json_out = os.path.join(results_dir, "%s.json" % label)
    log_out = os.path.join(results_dir, "%s.log" % label)
    if os.path.exists(json_out):
        os.remove(json_out)

    coll_cmd = ("python3 %s/collector/int_collector.py --iface %s-eth0 "
                "--count %d --timeout %d --label %s --json-out %s > %s 2>&1"
                % (ROOT, col, count, timeout, label, json_out, log_out))
    cproc = hcol.popen(coll_cmd, shell=True)
    time.sleep(2.0)   # let the sniffer come up

    send_cmd = ("python3 %s/traffic/send.py --iface h1_1-eth0 "
                "--src-ip %s --dst-ip %s --src-mac %s --dst-mac %s "
                "--count %d --pps %d"
                % (ROOT, topo.host_ip("h1_1"), topo.host_ip(col),
                   src_info["mac"], dst_info["mac"], count, pps))
    info("[%s] %s\n" % (label, src.cmd(send_cmd).strip()))

    try:
        cproc.wait(timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        cproc.kill()
    summary = {}
    if os.path.exists(json_out):
        summary = json.load(open(json_out))
    info("[%s] collector captured %d INT pkts -> %s\n"
         % (label, summary.get("packets", 0), json_out))
    return summary


def run_iperf_capture(net, topo, label, results_dir, mbit=5, secs=6,
                      dgram=200, timeout=16):
    """iperf-driven capture: drives load with iperf UDP (kernel-rate, far
    faster than scapy) so a throttled bmv2 egress queue actually fills.  The
    flow originates on h1_1's host port, so the source leaf pushes INT onto
    every datagram exactly as for the scapy flow.  Used for the #3 queue phase.
    (scapy sendp tops out at a few tens of pps -- too slow to fill the queue.)"""
    col = topo.collector_name()
    hcol = net.get(col)
    src = net.get("h1_1")
    colip = topo.host_ip(col)

    json_out = os.path.join(results_dir, "%s.json" % label)
    log_out = os.path.join(results_dir, "%s.log" % label)
    if os.path.exists(json_out):
        os.remove(json_out)

    hcol.cmd('pkill -f "iperf -s" 2>/dev/null; iperf -s -u '
             '>/tmp/iperf_srv.log 2>&1 &')
    time.sleep(1.0)

    coll_cmd = ("python3 %s/collector/int_collector.py --iface %s-eth0 "
                "--count 80 --timeout %d --label %s --json-out %s > %s 2>&1"
                % (ROOT, col, timeout - 2, label, json_out, log_out))
    cproc = hcol.popen(coll_cmd, shell=True)
    time.sleep(2.0)

    src.cmd("iperf -c %s -u -b %dM -t %d -l %d >/tmp/iperf_cli.log 2>&1"
            % (colip, mbit, secs, dgram))
    try:
        cproc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        cproc.kill()
    hcol.cmd('pkill -f "iperf -s" 2>/dev/null')

    summary = {}
    if os.path.exists(json_out):
        summary = json.load(open(json_out))
    info("[%s] iperf-driven capture: %d INT pkts -> %s\n"
         % (label, summary.get("packets", 0), json_out))
    return summary


def onpath_delay_intf(net, topo, baseline):
    """Return (spine, intf) for the on-path spine's egress veth toward the
    collector's leaf.

    The link delay is injected on the spine -> collector-leaf hop (the last
    link before the sink) rather than the source-leaf -> spine hop: a directed
    timestamp diagnostic showed a netem delay on the source-leaf uplink is
    attributed one hop downstream by bmv2's per-switch ingress clocks, whereas
    a delay on the spine downlink lands exactly on that inter-hop segment,
    giving an unambiguous +50ms on the matching link (see REPORT.md E-6)."""
    path = baseline.get("path_swids", [])
    if len(path) < 3:
        return None, None
    mid = path[1]
    spine = next((s for s in topo.spines if topo.swid[s] == mid), None)
    if not spine:
        return None, None
    leaf = topo.hosts[topo.collector_name()]["leaf"]
    sp, lf = net.get(spine), net.get(leaf)
    links = net.linksBetween(sp, lf)
    if not links:
        return None, None
    lk = links[0]
    intf = lk.intf1 if lk.intf1.node.name == spine else lk.intf2
    return spine, intf.name


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=os.path.join(ROOT, "build/baseline_int.json"))
    ap.add_argument("--scenario", default="demo",
                    choices=["demo", "baseline", "delay", "queue", "cli"])
    ap.add_argument("--results-dir", default=os.path.join(ROOT, "results"))
    ap.add_argument("--log-dir", default=os.path.join(ROOT, "logs"))
    ap.add_argument("--cmd-dir", default=os.path.join(ROOT, "results/cmds"))
    ap.add_argument("--spines", type=int, default=2)
    ap.add_argument("--leaves", type=int, default=4)
    ap.add_argument("--hosts", type=int, default=2)
    ap.add_argument("--bw", type=int, default=10)
    ap.add_argument("--delay", default="1ms")
    ap.add_argument("--delay-ms", type=int, default=50)
    ap.add_argument("--queue-rate", type=int, default=100,
                    help="bmv2 egress pps cap used to build the queue")
    ap.add_argument("--cli-path", default="simple_switch_CLI")
    args = ap.parse_args()

    os.makedirs(args.results_dir, exist_ok=True)
    os.makedirs(args.log_dir, exist_ok=True)
    setLogLevel("info")

    topo = LeafSpine(spines=args.spines, leaves=args.leaves,
                     hosts_per_leaf=args.hosts, bw=args.bw, delay=args.delay)
    info(topo.summary() + "\n")

    net, thrift = build_net(topo, args.json, args.log_dir)
    net.start()
    time.sleep(1.0)
    populate(topo, thrift, args.cmd_dir, cli=args.cli_path)
    static_arp(net, topo)
    time.sleep(1.0)

    try:
        if args.scenario == "cli":
            CLI(net)
            return

        baseline = {}
        if args.scenario in ("demo", "baseline", "delay", "queue"):
            baseline = run_capture(net, topo, "baseline", args.results_dir)

        if args.scenario in ("demo", "delay"):
            spine, intf = onpath_delay_intf(net, topo, baseline)
            if intf:
                col_leaf = topo.hosts[topo.collector_name()]["leaf"]
                info("[delay] netem %dms on %s (%s -> %s)\n"
                     % (args.delay_ms, intf, spine, col_leaf))
                subprocess.run("tc qdisc replace dev %s root netem delay %dms"
                               % (intf, args.delay_ms), shell=True)
                run_capture(net, topo, "delay_after", args.results_dir)
                subprocess.run("tc qdisc del dev %s root" % intf,
                               shell=True, stderr=subprocess.DEVNULL)
            else:
                info("[delay] could not resolve on-path delay intf\n")

        if args.scenario in ("demo", "queue"):
            col = topo.collector_name()
            eg_port = topo.hosts[col]["leaf_port"]   # l4 egress -> collector
            l4_thrift = thrift["l4"]
            rate = args.queue_rate
            info("[queue] throttle l4 egress port %d to %d pps (thrift %d)\n"
                 % (eg_port, rate, l4_thrift))
            subprocess.run('echo "set_queue_rate %d %d" | %s --thrift-port %d'
                           % (rate, eg_port, args.cli_path, l4_thrift),
                           shell=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            run_iperf_capture(net, topo, "queue_after", args.results_dir)
            subprocess.run('echo "set_queue_rate 100000 %d" | %s --thrift-port %d'
                           % (eg_port, args.cli_path, l4_thrift), shell=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
