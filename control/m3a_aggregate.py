#!/usr/bin/env python3
"""M3a aggregator: recompute ALL acceptance metrics from a raw capture
(results/raw/<label>.jsonl) + ground truth + topology.  This is the script the
reviewer can re-run to verify REPORT numbers come from the raw evidence.

Outputs results/pool_<label>.json with:
  packets, crc16/crc32 variants,
  gate0a_hash, gate0b_path, crc32_variant_sweep, crc16_variant_sweep,
  overhead (constant syndrome bytes, observed hop counts),
  coverage (per-port #FAIL-tests over the run: distribution + per-port),
  boolean (per-epoch FAIL decode: m_tests,n_cols,positive,dd,truth,eval_dd),
  f1_vs_m (per-epoch (m,F1) points), min_m_for_f1_0.95, weighted_f1.

Usage: m3a_aggregate.py --label pool_ft_d1 --gt results/pool_ft_d1_gt.json
"""
import argparse
import json
import os
import sys

THIS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(THIS)
for sub in ("topo", "control", "collector"):
    sys.path.insert(0, os.path.join(ROOT, sub))

import poolint_hash as H
from poolint_collector import comp_dd, prf1, pack_path
from fat_tree import FatTree

POOL_LEN = 9   # core syndrome bytes (constant, hop-count independent)


def load_raw(label, raw_dir):
    path = os.path.join(raw_dir, "%s.jsonl" % label)
    if not os.path.exists(path):
        return None
    pkts = []
    for line in open(path):
        line = line.strip()
        if line:
            pkts.append(json.loads(line))
    return pkts


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
    out = {"label": args.label, "k": args.k,
           "crc16_ecmp_variant": H.CRC16_CHOSEN,
           "crc32_membership_variant": H.CRC32_CHOSEN,
           "n_monitored_ports": topo.n_monitored_ports()}

    pkts = load_raw(args.label, args.raw_dir)
    out["packets"] = 0 if pkts is None else len(pkts)
    if not pkts:
        json.dump(out, open(os.path.join(args.results_dir,
                  "%s.json" % args.label), "w"), indent=2)
        print("NO DATA for %s" % args.label)
        return

    def recon(p):
        return topo.reconstruct_path(p["src"], p["dst"], p["proto"],
                                     p["sport"], p["dport"])

    # ---- gate #0a (crc32 membership) & #0b (full path) -----------------
    a_ok = a_tot = b_ok = b_tot = malformed = 0
    for p in pkts:
        if p["dbg_port_uid"]:
            key = H.membership_key(p["test_id"], p["epoch_id"],
                                   p["dbg_port_uid"], H.MID_FAIL, 0)
            a_tot += 1
            if H._crc32(key) == p["dbg_hash"]:
                a_ok += 1
        pp = recon(p)
        if pp is None:
            malformed += 1
            continue
        if p["dbg_path"]:
            b_tot += 1
            if pack_path(pp) == p["dbg_path"]:
                b_ok += 1
    out["gate0a_hash"] = {"matched": a_ok, "total": a_tot,
                          "exact": a_ok == a_tot and a_tot > 0}
    out["gate0b_path"] = {"matched": b_ok, "total": b_tot,
                          "exact": b_ok == b_tot and b_tot > 0}
    out["malformed_dropped"] = malformed

    # ---- CRC variant sweeps (uniqueness evidence) ---------------------
    c32 = {n: 0 for n in H.CRC32_VARIANTS}
    c16 = {n: 0 for n in H.CRC16_VARIANTS}
    c32n = c16n = 0
    for p in pkts:
        if p["dbg_port_uid"]:
            c32n += 1
            key = H.membership_key(p["test_id"], p["epoch_id"],
                                   p["dbg_port_uid"], H.MID_FAIL, 0)
            for nm in H.CRC32_VARIANTS:
                if H._crc32(key, nm) == p["dbg_hash"]:
                    c32[nm] += 1
        if p["dbg_path"]:
            c16n += 1
            for nm in H.CRC16_VARIANTS:
                pp = topo.reconstruct_path(p["src"], p["dst"], p["proto"],
                                           p["sport"], p["dport"], nm)
                if pp and pack_path(pp) == p["dbg_path"]:
                    c16[nm] += 1
    out["crc32_variant_sweep"] = {"n": c32n, "matched": c32}
    out["crc16_variant_sweep"] = {"n": c16n, "matched": c16}

    # ---- overhead (constant, hop-count independent) -------------------
    hopcts = sorted({len(recon(p)) for p in pkts if recon(p)})
    out["overhead"] = {"core_syndrome_bytes": POOL_LEN,
                       "core_syndrome_bits": POOL_LEN * 8,
                       "bsynd_bits_used": H.R * len(H.BOOL_METRICS),
                       "qsynd_bits_used": 8 * H.R * len(H.QUANT_METRICS),
                       "observed_hop_counts": hopcts, "bytes_per_hop": 0}

    # ---- build FAIL tests per epoch (A rows) -------------------------
    bi = H.BOOL_METRICS.index(H.MID_FAIL)     # boolean slot index for FAIL
    rows_by_ep = {}     # epoch -> (list[set members], list[y])
    cov_total = {}      # port -> total #FAIL tests covering it (whole run)
    for p in pkts:
        pp = recon(p)
        if not pp:
            continue
        ep = p["epoch_id"]
        path = set(pp)
        for r in range(H.R):
            mem = {u for u in path
                   if H.member(p["test_id"], ep, u, H.MID_FAIL, r)}
            if not mem:
                continue
            yi = (p["bsynd"] >> (bi * H.R + r)) & 1
            rows_by_ep.setdefault(ep, ([], []))
            rows_by_ep[ep][0].append(mem)
            rows_by_ep[ep][1].append(yi)
            for u in mem:
                cov_total[u] = cov_total.get(u, 0) + 1

    # coverage distribution over the whole run
    cov_vals = sorted(cov_total.values())
    if cov_vals:
        out["coverage"] = {
            "per_port": {str(k): cov_total[k] for k in sorted(cov_total)},
            "n_ports_seen": len(cov_vals),
            "min": cov_vals[0], "max": cov_vals[-1],
            "median": cov_vals[len(cov_vals) // 2],
            "mean": round(sum(cov_vals) / len(cov_vals), 2)}

    truth = gt.get("fail_ports")
    boolean = []
    f1pts = []
    for ep, (rows, y) in sorted(rows_by_ep.items()):
        definite, suspects, cols = comp_dd(rows, y)
        cov = {}
        for rset in rows:
            for u in rset:
                cov[u] = cov.get(u, 0) + 1
        rec = {"epoch": ep, "m_tests": len(rows), "n_cols": len(cols),
               "positive_tests": int(sum(y)),
               "dd_defective": sorted(definite),
               "comp_suspects": sorted(suspects),
               "coverage": {str(k): cov[k] for k in sorted(cov)}}
        if truth is not None:
            rec["truth"] = sorted(truth)
            rec["eval_dd"] = prf1(definite, truth)
            rec["eval_comp"] = prf1(suspects, truth)
            f1pts.append([len(rows), rec["eval_dd"]["f1"]])
        boolean.append(rec)
    out["boolean"] = boolean

    if truth is not None and f1pts:
        wt = sum(m for m, _ in f1pts)
        out["weighted_f1"] = round(sum(m * f for m, f in f1pts) / wt, 4) if wt else None
        out["f1_vs_m"] = sorted(f1pts)
        good = [m for m, f in f1pts if f >= 0.95]
        out["min_m_for_f1_0.95"] = min(good) if good else None
        # binned curve: mean F1 per m-bucket
        buckets = [(0, 10), (10, 30), (30, 60), (60, 100), (100, 1 << 30)]
        curve = []
        for lo, hi in buckets:
            fs = [f for m, f in f1pts if lo <= m < hi]
            if fs:
                curve.append({"m_range": "%d-%s" % (lo, "inf" if hi > 1 << 20 else hi),
                              "n_epochs": len(fs),
                              "mean_f1": round(sum(fs) / len(fs), 4),
                              "min_f1": round(min(fs), 4)})
        out["f1_by_m_bucket"] = curve
        if truth:
            d = len(truth)
            out["d"] = d
            out["d_over_n"] = round(d / topo.n_monitored_ports(), 4)

    json.dump(out, open(os.path.join(args.results_dir,
              "%s.json" % args.label), "w"), indent=2)
    print("aggregated %s: pkts=%d gate0a=%d/%d gate0b=%d/%d"
          % (args.label, out["packets"], a_ok, a_tot, b_ok, b_tot))


if __name__ == "__main__":
    main()
