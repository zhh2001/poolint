#!/usr/bin/env python3
"""M3a raw capture: sniff PoolINT report frames at the collector and dump the
RAW evidence (no decoding here) to results/raw/:
  - <label>.jsonl : one JSON object per captured packet (all header fields)
  - <label>.pcap  : the raw frames (scapy wrpcap)
The aggregator (control/m3a_aggregate.py) recomputes every REPORT metric from
the .jsonl alone, so the pipeline is auditable end-to-end.
"""
import argparse
import json
import os
import sys

from scapy.all import sniff, wrpcap

THIS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(THIS)
# poolint_collector imports leaf_spine/line_topo/poolint_hash at module load,
# so put topo/ and control/ on the path too.
for _sub in ("collector", "topo", "control"):
    sys.path.insert(0, os.path.join(ROOT, _sub))
from poolint_collector import parse_pool, TYPE_POOLINT


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--count", type=int, default=200000)
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--label", required=True)
    ap.add_argument("--raw-dir", default=os.path.join(ROOT, "results/raw"))
    args = ap.parse_args()
    os.makedirs(args.raw_dir, exist_ok=True)

    jsonl_path = os.path.join(args.raw_dir, "%s.jsonl" % args.label)
    pcap_path = os.path.join(args.raw_dir, "%s.pcap" % args.label)
    jf = open(jsonl_path, "w")
    raw_frames = []
    n = [0]

    def handle(pk):
        b = bytes(pk)
        r = parse_pool(b)
        if r is None:
            return
        raw_frames.append(pk)
        jf.write(json.dumps(r) + "\n")
        n[0] += 1

    sys.stdout.write("[m3a_capture:%s] sniffing %s\n" % (args.label, args.iface))
    sys.stdout.flush()
    sniff(iface=args.iface, prn=handle, count=args.count, timeout=args.timeout,
          store=False, lfilter=lambda p: bytes(p)[12:14] == b"\x12\x13")
    jf.close()
    if raw_frames:
        wrpcap(pcap_path, raw_frames)
    sys.stdout.write("[m3a_capture:%s] wrote %d pkts -> %s (+ pcap)\n"
                     % (args.label, n[0], jsonl_path))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
