#!/usr/bin/env python3
"""M3d-1 OFFLINE analysis of the many-to-many multi-sink capture.

Reads results/raw/m3d.jsonl (merged 0x1213 frames from all 16 host sinks).
Computes:
  - |O| = # distinct directed egress ports on any reconstructed path (vs n=81)
  - per-port coverage distribution
  - gate#0a: crc32 membership hash recompute vs in-packet dbg_hash (must be 100%)
  - gate#0b: pack_path(reconstruct_path) vs in-packet dbg_path over the captured
    distinct 5-tuples (report >=15 distinct, must be 100%)
Writes results/m3d_analyze.json. Numbers only from JSON; no hand entry.
"""
import collections
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("topo", "control", "collector"):
    sys.path.insert(0, os.path.join(ROOT, sub))
from fat_tree import FatTree
import poolint_hash as H
from poolint_collector import pack_path

RAW = os.path.join(ROOT, "results/raw/m3d.jsonl")
T = FatTree(k=4)
N = T.n_monitored_ports()


def main():
    cov = collections.Counter()
    a_ok = a_tot = 0
    b_ok = b_tot = 0
    flows = {}                       # 5-tuple -> (recon_ok bool)
    hops = collections.Counter()
    nframes = 0
    with open(RAW) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            p = json.loads(line)
            nframes += 1
            pp = T.reconstruct_path(p["src"], p["dst"], p["proto"],
                                    p["sport"], p["dport"])
            if not pp:
                continue
            hops[len(pp)] += 1
            for u in pp:
                cov[u] += 1
            # gate0a membership
            if p.get("dbg_port_uid"):
                k7 = H.membership_key(p["test_id"], p["epoch_id"],
                                      p["dbg_port_uid"], H.MID_FAIL, 0)
                a_tot += 1
                a_ok += (H._crc32(k7) == p["dbg_hash"])
            # gate0b path
            if p.get("dbg_path"):
                b_tot += 1
                ok = (pack_path(pp) == p["dbg_path"])
                b_ok += ok
                key = (p["src"], p["dst"], p["proto"], p["sport"], p["dport"])
                if key not in flows:
                    flows[key] = ok

    cv = sorted(cov.values())
    covhist = dict(sorted(collections.Counter(
        # bucket coverage into decades-ish for a compact histogram
        (v // 500) * 500 for v in cov.values()).items()))
    distinct_flows = len(flows)
    distinct_flow_ok = sum(1 for v in flows.values() if v)

    out = {
        "n_monitored_ports": N,
        "frames": nframes,
        "observable_ports": len(cov),
        "observable_pct": round(100.0 * len(cov) / N, 1),
        "coverage_min": cv[0] if cv else 0,
        "coverage_median": cv[len(cv) // 2] if cv else 0,
        "coverage_max": cv[-1] if cv else 0,
        "coverage_hist_by500": covhist,
        "hop_distribution": dict(sorted(hops.items())),
        "gate0a_membership": {"matched": a_ok, "total": a_tot,
                              "exact": a_ok == a_tot and a_tot > 0},
        "gate0b_path": {"matched": b_ok, "total": b_tot,
                        "exact": b_ok == b_tot and b_tot > 0},
        "gate0b_distinct_flows": distinct_flows,
        "gate0b_distinct_flows_ok": distinct_flow_ok,
        "gate0b_distinct_all_ok": distinct_flow_ok == distinct_flows
        and distinct_flows >= 15,
        "per_port_coverage": {str(k): cov[k] for k in sorted(cov)},
        "unobserved_ports": N - len(cov),
    }
    json.dump(out, open(os.path.join(ROOT, "results/m3d_analyze.json"), "w"),
              indent=2)
    print("ANALYZE frames=%d |O|=%d/%d (%.1f%%) g0a=%d/%d g0b=%d/%d "
          "distinct_flows=%d/%d cov[min/med/max]=%d/%d/%d"
          % (nframes, len(cov), N, out["observable_pct"], a_ok, a_tot,
             b_ok, b_tot, distinct_flow_ok, distinct_flows,
             out["coverage_min"], out["coverage_median"], out["coverage_max"]))


if __name__ == "__main__":
    main()
