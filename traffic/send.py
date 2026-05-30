#!/usr/bin/env python3
"""Send a known UDP flow with scapy (used to drive the INT demo).

Crafts L2 frames directly (dst MAC = the collector's MAC, matching the
static ARP the runner installs) so the flow id is fully controlled and
reproducible.
"""
import argparse

from scapy.all import Ether, IP, UDP, sendp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--src-ip", required=True)
    ap.add_argument("--dst-ip", required=True)
    ap.add_argument("--src-mac", required=True)
    ap.add_argument("--dst-mac", required=True)
    ap.add_argument("--sport", type=int, default=4321)
    ap.add_argument("--dport", type=int, default=5001)
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--pps", type=float, default=10.0)
    ap.add_argument("--payload", type=int, default=64)
    args = ap.parse_args()

    pkt = (Ether(src=args.src_mac, dst=args.dst_mac) /
           IP(src=args.src_ip, dst=args.dst_ip) /
           UDP(sport=args.sport, dport=args.dport) /
           (b"P" * args.payload))
    interval = 1.0 / args.pps if args.pps > 0 else 0
    sendp(pkt, iface=args.iface, count=args.count, inter=interval, verbose=False)
    print("[send] %d pkts %s:%d -> %s:%d on %s"
          % (args.count, args.src_ip, args.sport, args.dst_ip, args.dport,
             args.iface))


if __name__ == "__main__":
    main()
