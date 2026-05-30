#!/usr/bin/env python3
"""Print the M1 acceptance evidence from results/*.json."""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "results")


def load(name):
    p = os.path.join(RES, name)
    return json.load(open(p)) if os.path.exists(p) else None


def links_map(s):
    return {(l["from_swid"], l["to_swid"]): l["avg_link_latency_us"]
            for l in s.get("links", [])}


def qd_map(s):
    return {h["switch_id"]: (h["avg_queue_depth"], h["max_queue_depth"])
            for h in s.get("per_hop", [])}


print("=" * 64)
print("PoolINT M1 - acceptance summary")
print("=" * 64)

b = load("baseline.json")
if b:
    print("\n[#1] Baseline full per-hop trace  (packets=%d)" % b.get("packets"))
    print("  path (src->dst swids):", b.get("path_swids"))
    for h in b.get("per_hop", []):
        print("  swid %-4d avg_qdepth=%.1f avg_hop_lat=%.1fus"
              % (h["switch_id"], h["avg_queue_depth"], h["avg_hop_latency_us"]))
    print("\n[#4] Per-packet INT overhead")
    print("  hops=%d  total=%d B (core 5-field=%d B)"
          % (b["hop_count"], b["int_bytes_per_pkt"], b["core_int_bytes_per_pkt"]))
    print("  layout: shim %dB + %dB/hop x %d  (core %dB/hop)"
          % (b["shim_bytes"], b["perhop_bytes"], b["hop_count"],
             b["core_perhop_bytes"]))

d = load("delay_after.json")
if b and d:
    print("\n[#2] Link delay injection (before vs after)")
    lb, ld = links_map(b), links_map(d)
    for k in lb:
        if k in ld:
            print("  link %d->%d : %.1f us  ->  %.1f us   (delta %+.1f us)"
                  % (k[0], k[1], lb[k], ld[k], ld[k] - lb[k]))

q = load("queue_after.json")
if b and q:
    print("\n[#3] Queue build-up (before vs after)")
    qb, qq = qd_map(b), qd_map(q)
    for sw in qb:
        if sw in qq:
            print("  swid %-4d avg_qdepth %.1f->%.1f  max_qdepth %d->%d"
                  % (sw, qb[sw][0], qq[sw][0], qb[sw][1], qq[sw][1]))
print()
