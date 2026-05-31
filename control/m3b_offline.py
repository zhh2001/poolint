#!/usr/bin/env python3
"""M3b-1: OFFLINE overhead-vs-F1 comparison of three INT schemes on the SAME
captured raw / topology / injected faults (no network, no new runs).

Schemes (all localise the injected FAIL ports from results/raw/pool_ft_d*.jsonl):
  * Full-INT   : every packet reveals the true status of every egress port on
                 its path. Collector flags a port faulty iff some revealed path
                 shows it failed. Precision is always 1.0 (truth revealed);
                 recall grows as faulty ports get crossed. F1=1 once every
                 faulty port has been crossed by >=1 revealed packet.
                 per-packet bytes = BASE + PERHOP(K) * hops.
  * Sampling-INT: Full-INT but only on a 1/stride subsample (s in S_GRID).
                 Non-sampled packets carry 0 telemetry. Same per-sampled-packet
                 cost as Full-INT.
  * PoolINT    : every packet carries the fixed 9-byte syndrome; COMP+DD decode
                 over the accumulated tests. per-packet bytes = POOL_BYTES.

X axis = cumulative network-side telemetry bytes; Y = F1 vs the injected fault
set. Because support is stationary, the first N packets are a valid prefix.

COST MODEL (documented; conservative toward Full-INT = small per-hop):
  BASE      = 8   INT shim/instruction header (per the M3b spec)
  PERHOP(K) = PERHOP_ID + PERMETRIC*K  per hop  (port id + K metric fields)
  PERHOP_ID = 2   (port_uid: swid 1B + egress port 1B)
  PERMETRIC = 1   byte per metric per hop
  POOL_BYTES= 9   deployed poolint_t syndrome (constant, all metrics)
A larger per-hop only helps PoolINT, so this choice is conservative for it.
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
from poolint_collector import comp_dd

BASE = 8
PERHOP_ID = 2
PERMETRIC = 1
POOL_BYTES = 9
S_GRID = [1.0, 0.5, 0.25, 0.125, 0.0625, 0.03125]   # 1, 1/2 .. 1/32
SCENARIOS = ["d1", "d2", "d3", "d5"]
RES = os.path.join(ROOT, "results")
RAW = os.path.join(RES, "raw")
T = FatTree(k=4)
BI = H.BOOL_METRICS.index(H.MID_FAIL)


def perhop(k):
    return PERHOP_ID + PERMETRIC * k


def fullint_pkt_bytes(hops, k=1):
    return BASE + perhop(k) * hops


def f1(pred, truth):
    pred, truth = set(pred), set(truth)
    if not pred and not truth:
        return 1.0
    tp = len(pred & truth)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(truth) if truth else 0.0
    return (2 * p * r / (p + r)) if (p + r) else 0.0


def load_scenario(lab):
    gt = json.load(open(os.path.join(RES, "pool_ft_%s_gt.json" % lab)))
    truth = set(gt["fail_ports"])
    pkts = []
    for line in open(os.path.join(RAW, "pool_ft_%s.jsonl" % lab)):
        line = line.strip()
        if not line:
            continue
        p = json.loads(line)
        path = T.reconstruct_path(p["src"], p["dst"], p["proto"],
                                  p["sport"], p["dport"])
        if not path:
            continue
        hops = len(path)
        # pool test rows (R per packet)
        rows = []
        for r in range(H.R):
            mem = {u for u in path
                   if H.member(p["test_id"], p["epoch_id"], u, H.MID_FAIL, r)}
            if mem:
                y = (p["bsynd"] >> (BI * H.R + r)) & 1
                rows.append((mem, y))
        pkts.append({"path": set(path), "hops": hops, "rows": rows})
    return truth, pkts


def prefix_grid(n):
    g, m = [], 8
    while m < n:
        g.append(m)
        m = int(m * 1.6) + 1
    g.append(n)
    return g


def simulate(lab):
    truth, pkts = load_scenario(lab)
    n = len(pkts)
    grid = prefix_grid(n)

    # ---- Full-INT: cumulative bytes + observed-faulty recall -----------
    full_bytes = [0] * (n + 1)
    for i, p in enumerate(pkts):
        full_bytes[i + 1] = full_bytes[i] + fullint_pkt_bytes(p["hops"], 1)
    full_curve = []
    obs = set()
    gi = 0
    seen_to = 0
    for m in grid:
        while seen_to < m:
            obs |= (pkts[seen_to]["path"] & truth)
            seen_to += 1
        full_curve.append({"bytes": full_bytes[m], "f1": f1(obs, truth),
                           "pkts": m})

    # ---- Sampling-INT per s -------------------------------------------
    samp = {}
    for s in S_GRID:
        stride = int(round(1.0 / s))
        b = 0
        obs_s = set()
        cur = []
        ptr = 0
        cumb = [0] * (n + 1)
        for i, p in enumerate(pkts):
            cost = fullint_pkt_bytes(p["hops"], 1) if (i % stride == 0) else 0
            cumb[i + 1] = cumb[i] + cost
        seen = 0
        obs_s = set()
        for m in grid:
            while seen < m:
                if seen % stride == 0:
                    obs_s |= (pkts[seen]["path"] & truth)
                seen += 1
            cur.append({"bytes": cumb[m], "f1": f1(obs_s, truth), "pkts": m})
        samp["%.5f" % s] = cur

    # ---- PoolINT: 9B/pkt, COMP+DD over accumulated tests --------------
    pool_curve = []
    for m in grid:
        rows = []
        ys = []
        for p in pkts[:m]:
            for (mem, y) in p["rows"]:
                rows.append(mem)
                ys.append(y)
        definite, _s, _c = comp_dd(rows, ys)
        pool_curve.append({"bytes": POOL_BYTES * m, "f1": f1(definite, truth),
                           "pkts": m, "tests": len(rows)})

    return {"label": lab, "n_pkts": n, "truth": sorted(truth),
            "d": len(truth), "full": full_curve, "sampling": samp,
            "pool": pool_curve}


def bytes_to_f1(curve, thr=0.95):
    """min cumulative bytes at which f1>=thr and stays >=thr to the end."""
    pts = curve
    for i, c in enumerate(pts):
        if all(pts[j]["f1"] >= thr for j in range(i, len(pts))):
            return c["bytes"]
    return None


def main():
    out = {"cost_model": {"BASE": BASE, "PERHOP_ID": PERHOP_ID,
                          "PERMETRIC": PERMETRIC, "POOL_BYTES": POOL_BYTES,
                          "perhop_K1": perhop(1)},
           "scenarios": {}}
    for lab in SCENARIOS:
        out["scenarios"][lab] = simulate(lab)

    # bytes-to-F1>=0.95 table per scheme per scenario
    tab = {}
    for lab in SCENARIOS:
        sc = out["scenarios"][lab]
        row = {"full": bytes_to_f1(sc["full"]),
               "pool": bytes_to_f1(sc["pool"])}
        for s, cur in sc["sampling"].items():
            row["samp_%s" % s] = bytes_to_f1(cur)
        tab[lab] = row
    out["bytes_to_f1_0.95"] = tab

    # ---- overhead vs K (analytic) -------------------------------------
    # metric mix by K: K1={FAIL bool}; K2=+QHI bool; K4=+QDEPTH,UTIL quant
    def pool_synd_bytes(nbool, nquant):
        bits = H.R * nbool + 8 * H.R * nquant
        return (bits + 7) // 8
    kmix = {1: (1, 0), 2: (2, 0), 4: (2, 2)}
    ohk = {}
    for K, (nb, nq) in kmix.items():
        ohk[str(K)] = {
            "pool_synd_bytes_analytic": pool_synd_bytes(nb, nq),
            "pool_deployed_bytes": POOL_BYTES,
            "full_per_pkt_hops1": fullint_pkt_bytes(1, K),
            "full_per_pkt_hops3": fullint_pkt_bytes(3, K),
            "full_per_pkt_hops5": fullint_pkt_bytes(5, K)}
    out["overhead_vs_K"] = ohk

    json.dump(out, open(os.path.join(RES, "m3b_offline.json"), "w"), indent=2)
    print("m3b_offline written: scenarios=%s" % SCENARIOS)
    for lab in SCENARIOS:
        sc = out["scenarios"][lab]
        print("  %s n=%d d=%d full_last_f1=%.3f pool_last_f1=%.3f"
              % (lab, sc["n_pkts"], sc["d"], sc["full"][-1]["f1"],
                 sc["pool"][-1]["f1"]))


if __name__ == "__main__":
    main()
