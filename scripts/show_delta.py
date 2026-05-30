#!/usr/bin/env python3
"""Print before/after deltas for acceptance criteria #2 (link delay) and
#3 (queue build-up) from results/*.json."""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RES = os.path.join(ROOT, "results")


def load(n):
    p = os.path.join(RES, n)
    return json.load(open(p)) if os.path.exists(p) else None


def links(s):
    return {(l["from_swid"], l["to_swid"]): l["avg_link_latency_us"]
            for l in s.get("links", [])}


def qmap(s):
    return {h["switch_id"]: h for h in s.get("per_hop", [])}


b = load("baseline.json")
d = load("delay_after.json")
q = load("queue_after.json")

if b and d:
    lb, ld = links(b), links(d)
    print("[#2 DELAY] pkts before=%d after=%d  path=%s -> %s"
          % (b["packets"], d["packets"], b.get("path_swids"), d.get("path_swids")))
    for k in sorted(lb):
        if k in ld:
            print("  link %d->%d : %.0f us -> %.0f us  (delta %+.0f us)"
                  % (k[0], k[1], lb[k], ld[k], ld[k] - lb[k]))

if b and q:
    qb, qq = qmap(b), qmap(q)
    print("[#3 QUEUE] pkts before=%d after=%d  path=%s -> %s"
          % (b["packets"], q["packets"], b.get("path_swids"), q.get("path_swids")))
    for sw in sorted(qq):
        a = qq[sw]
        z = qb.get(sw, {})
        print("  swid %d : avg_qd %.1f -> %.1f , max_qd %d -> %d , "
              "avg_hoplat %.0f -> %.0f us"
              % (sw, z.get("avg_queue_depth", 0.0), a["avg_queue_depth"],
                 z.get("max_queue_depth", 0), a["max_queue_depth"],
                 z.get("avg_hop_latency_us", 0.0), a["avg_hop_latency_us"]))
