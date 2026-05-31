#!/usr/bin/env python3
"""M3b-1b offline fault simulator.

From an existing capture (paths + test_id/epoch_id, no network) synthesise the
boolean FAIL syndrome for ANY fault set S:

    synth_r(p, S) = OR_{e in path(p)} [ member(e, test_id_p, epoch_p, FAIL, r)
                                        AND e in S ]

- path(p)      : reconstruct_path (bit-exact vs in-packet dbg_path, gate #0b).
- member(...)  : the crc32 membership gate (bit-exact vs dbg_hash, gate #0a).
- Only the boolean FAIL metric is synthesised. QHI/QDEPTH/UTIL are load-driven
  dynamic quantities that cannot be synthesised offline -> excluded.

VERIFICATION GATE (must pass before any study): synthesise with S = the capture's
real injected fault set and compare bit-for-bit, per packet per round, against the
real FAIL bits in the capture's `bsynd`. Anything < 100% => simulator invalid.

The per-packet membership rows are INDEPENDENT of S, so build_baseboard() computes
them once; a study then only flips y per S (cheap).
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "topo"))
sys.path.insert(0, os.path.join(ROOT, "control"))
sys.path.insert(0, os.path.join(ROOT, "collector"))
from fat_tree import FatTree
import poolint_hash as H

T = FatTree(k=4)
RES = os.path.join(ROOT, "results")
RAW = os.path.join(RES, "raw")
BI = H.BOOL_METRICS.index(H.MID_FAIL)


def build_baseboard(label):
    """Return per-packet structure for a capture:
       pkts = [{path:set, hops:int, rows:[set_per_round],
                real_fail:[bit_per_round]}], plus coverage Counter."""
    pkts = []
    cov = {}
    path_set = set()
    for line in open(os.path.join(RAW, "pool_ft_%s.jsonl" % label)):
        line = line.strip()
        if not line:
            continue
        p = json.loads(line)
        path = T.reconstruct_path(p["src"], p["dst"], p["proto"],
                                  p["sport"], p["dport"])
        if not path:
            continue
        pset = set(path)
        rows = []
        real = []
        for r in range(H.R):
            mem = {e for e in pset
                   if H.member(p["test_id"], p["epoch_id"], e, H.MID_FAIL, r)}
            rows.append(mem)
            real.append((p["bsynd"] >> (BI * H.R + r)) & 1)
            for e in mem:
                cov[e] = cov.get(e, 0) + 1
        pkts.append({"path": pset, "hops": len(path), "rows": rows,
                     "real_fail": real})
        path_set.add(tuple(sorted(pset)))
    return pkts, cov, len(path_set)


def synth_fail(rows, S):
    """y per round for fault set S: 1 iff some member port is faulty."""
    return [1 if (mem & S) else 0 for mem in rows]


def verify_gate(label):
    gt = json.load(open(os.path.join(RES, "pool_ft_%s_gt.json" % label)))
    S = set(gt["fail_ports"])
    pkts, cov, npaths = build_baseboard(label)
    nbits = match = real_pos = synth_pos = 0
    for p in pkts:
        syn = synth_fail(p["rows"], S)
        for r in range(H.R):
            nbits += 1
            match += (syn[r] == p["real_fail"][r])
            real_pos += p["real_fail"][r]
            synth_pos += syn[r]
    return {"label": label, "S": sorted(S), "pkts": len(pkts),
            "obs_ports": len(cov), "distinct_paths": npaths,
            "nbits": nbits, "match": match,
            "exact": match == nbits and nbits > 0,
            "real_pos": real_pos, "synth_pos": synth_pos}


if __name__ == "__main__":
    labels = sys.argv[1:] or ["d1", "d2", "d3", "d5"]
    out = {}
    for lab in labels:
        r = verify_gate(lab)
        out[lab] = r
        print("GATE %s: bits=%d match=%d EXACT=%s pkts=%d obs=%d paths=%d "
              "real_pos=%d synth_pos=%d"
              % (lab, r["nbits"], r["match"], r["exact"], r["pkts"],
                 r["obs_ports"], r["distinct_paths"], r["real_pos"],
                 r["synth_pos"]))
    json.dump(out, open(os.path.join(RES, "m3b1b_gate.json"), "w"), indent=2)
    allok = all(v["exact"] for v in out.values())
    print("ALL_GATES_EXACT:%s" % ("YES" if allok else "NO"))
