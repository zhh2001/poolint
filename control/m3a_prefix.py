#!/usr/bin/env python3
"""Offline PREFIX sample-complexity analysis for PoolINT M3a.

A single stationary-support run (faults injected before flows, constant all run)
is captured to results/raw/<label>.jsonl in time order. Each captured packet
yields R pooled tests (one per round): a test's row of A = the on-path ports
pooled by the crc32 membership gate (H.member) for the FAIL metric; y = the FAIL
syndrome bit (bsynd) it carried.

Because the support is constant for the whole run, the first m tests form a valid
m-test group-testing instance for ANY m. So we sweep m over a grid, decode
(COMP+DD, poolint_decode.comp_dd) the prefix, and report F1-vs-m -- a sample
complexity curve from ONE run, zero extra captures.

Membership / decode are IDENTICAL to control/m3a_aggregate.py (same H.member,
same bsynd bit, same comp_dd); only the batching differs (cumulative prefix of
tests in time order, vs per-epoch).

Output results/prefix_<label>.json:
  f1_vs_m, min_m_global_f1_0.95 (first grid m that stays >=0.95),
  per_target (coverage + first/stable recovered m), target_coverage,
  indistinguishable_groups (ports with identical non-empty test-columns).
"""
import argparse
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


def prf1(pred, truth):
    pred, truth = set(pred), set(truth)
    if not pred and not truth:
        return 1.0, 1.0, 1.0
    tp = len(pred & truth)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(truth) if truth else 0.0
    f = (2 * p * r / (p + r)) if (p + r) else 0.0
    return p, r, f


def m_grid(n):
    g, m = [], 10
    while m < n:
        g.append(m)
        m *= 2
    if not g or g[-1] != n:
        g.append(n)
    return g


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--gt", default=None)
    ap.add_argument("--raw-dir", default=os.path.join(ROOT, "results/raw"))
    ap.add_argument("--results-dir", default=os.path.join(ROOT, "results"))
    ap.add_argument("--k", type=int, default=4)
    args = ap.parse_args()

    topo = FatTree(k=args.k)
    gt = json.load(open(args.gt)) if (args.gt and os.path.exists(args.gt)) else {}
    truth = set(gt.get("fail_ports", []))
    bi = H.BOOL_METRICS.index(H.MID_FAIL)

    pkts = []
    with open(os.path.join(args.raw_dir, "%s.jsonl" % args.label)) as fh:
        for line in fh:
            line = line.strip()
            if line:
                pkts.append(json.loads(line))

    out = {"label": args.label, "k": args.k, "packets": len(pkts),
           "truth": sorted(truth)}
    if not pkts:
        json.dump(out, open(os.path.join(args.results_dir,
                  "prefix_%s.json" % args.label), "w"), indent=2)
        print("NO DATA for %s" % args.label)
        return

    def recon(p):
        return topo.reconstruct_path(p["src"], p["dst"], p["proto"],
                                     p["sport"], p["dport"])

    # ---- tests in capture (time) order: (members:set, y:int) --------------
    rows, ys = [], []
    cov = {}                       # port -> #tests pooling it (FAIL metric)
    src_pods = set()
    for p in pkts:
        pp = recon(p)
        if not pp:
            continue
        src_pods.add(p["src"].split(".")[1])
        path = set(pp)
        for r in range(H.R):
            mem = {u for u in path
                   if H.member(p["test_id"], p["epoch_id"], u, H.MID_FAIL, r)}
            if not mem:
                continue
            yi = (p["bsynd"] >> (bi * H.R + r)) & 1
            rows.append(mem)
            ys.append(yi)
            for u in mem:
                cov[u] = cov.get(u, 0) + 1
    out["n_tests"] = len(rows)
    out["observed_ports"] = len(cov)
    out["src_pods"] = sorted(src_pods)
    out["target_coverage"] = {str(t): cov.get(t, 0) for t in sorted(truth)}

    def decode_prefix(m):
        definite, _suspects, _cols = comp_dd(rows[:m], ys[:m])
        return set(definite)

    grid = m_grid(len(rows))
    curve = []
    first_m = {t: None for t in truth}
    preds = {}
    for m in grid:
        pred = decode_prefix(m)
        preds[m] = pred
        p, r, f = prf1(pred, truth)
        curve.append({"m": m, "prec": round(p, 4), "rec": round(r, 4),
                      "f1": round(f, 4), "positives": int(sum(ys[:m])),
                      "pred_n": len(pred)})
        for t in truth:
            if t in pred and first_m[t] is None:
                first_m[t] = m
    out["f1_vs_m"] = curve

    mm = None
    for i, c in enumerate(curve):
        if all(curve[j]["f1"] >= 0.95 for j in range(i, len(curve))):
            mm = c["m"]
            break
    out["min_m_global_f1_0.95"] = mm

    per_t = []
    for t in sorted(truth):
        stable = None
        for i, m in enumerate(grid):
            if all(t in preds[grid[j]] for j in range(i, len(grid))):
                stable = m
                break
        per_t.append({"port_uid": t, "coverage": cov.get(t, 0),
                      "first_recovered_m": first_m[t],
                      "stable_recovered_m": stable})
    out["per_target"] = per_t

    # ---- indistinguishable: ports with identical NON-EMPTY test-columns ----
    col_tests = {}
    for i, mem in enumerate(rows):
        for u in mem:
            col_tests.setdefault(u, set()).add(i)
    groups = {}
    for u, ts in col_tests.items():
        groups.setdefault(frozenset(ts), []).append(u)
    indist = [sorted(g) for g in groups.values() if len(g) > 1]
    out["indistinguishable_groups"] = indist
    out["target_in_indist"] = [g for g in indist if set(g) & truth]

    json.dump(out, open(os.path.join(args.results_dir,
              "prefix_%s.json" % args.label), "w"), indent=2)
    print("prefix %s: pkts=%d tests=%d O=%d pods=%s targets=%s last_f1=%s "
          "min_m=%s indist=%d" % (args.label, len(pkts), len(rows), len(cov),
          out["src_pods"], sorted(truth), curve[-1]["f1"], mm, len(indist)))


if __name__ == "__main__":
    main()
