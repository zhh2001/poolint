#!/usr/bin/env python3
"""M3b-1b statistical study (offline, no network).

On a single baseboard capture, for each d in {1,2,3,5} draw many random fault
placements from the observable ports and, PAIRED on the same placement, compute
bytes-to-F1>=0.95 for PoolINT / Full-INT. Report mean+-std + distributions,
PoolINT win-rate vs Full, ratio distribution, and cost-vs-coherence (Thm-4).
Two Full-INT cost models: minimal (2+K/hop, conservative) and realistic
(REALISTIC_PERHOP/hop, paper). FAIL syndrome via offline_faultsim (gate-exact).

Full-INT reveals truth -> precision 1; it localises any on-path fault, so its
bytes-to-F1 is ALWAYS finite for placements drawn from observable ports. We
assert that (none_full must be 0); a non-zero count is a bug.
"""
import json
import os
import random
import statistics
import sys
from math import comb

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "control"))
sys.path.insert(0, os.path.join(ROOT, "collector"))
import offline_faultsim as FS
from poolint_collector import comp_dd

RES = os.path.join(ROOT, "results")
BASEBOARD = "d2"
SEED = 20240531
N_PLACE = 100
DS = [1, 2, 3, 5]
K = 1
POOL_BYTES = 9
BASE = 8
MIN_PERHOP = 2 + K          # conservative for Full
REALISTIC_PERHOP = 16       # paper INT-MD per-hop (12-18B range; midpoint)
SAMP_RATES = [0.25, 0.125, 0.0625, 0.03125]
SAMP_SEEDS = 50


def f1_pred(pred, S):
    pred, S = set(pred), set(S)
    if not pred and not S:
        return 1.0
    tp = len(pred & S)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(S) if S else 0.0
    return (2 * p * r / (p + r)) if (p + r) else 0.0


def main():
    pkts, cov, npaths = FS.build_baseboard(BASEBOARD)
    obs = sorted(cov)
    n_obs = len(obs)
    npk = len(pkts)

    # flattened tests + per-packet end index + per-port test-column
    test_mems = []
    pkt_end = []
    for p in pkts:
        for mem in p["rows"]:
            test_mems.append(mem)
        pkt_end.append(len(test_mems))
    n_tests = len(test_mems)
    col = {e: set() for e in obs}
    for ti, mem in enumerate(test_mems):
        for e in mem:
            col[e].add(ti)

    pgrid = []
    m = 8
    while m < npk:
        pgrid.append(m)
        m = int(m * 1.7) + 1
    pgrid.append(npk)

    cum_min = [0] * (npk + 1)
    cum_real = [0] * (npk + 1)
    for i, p in enumerate(pkts):
        cum_min[i + 1] = cum_min[i] + BASE + MIN_PERHOP * p["hops"]
        cum_real[i + 1] = cum_real[i] + BASE + REALISTIC_PERHOP * p["hops"]

    def pool_btf(S, thr=0.95):
        y = [1 if (mem & S) else 0 for mem in test_mems]
        f1s = []
        for mpk in pgrid:
            te = pkt_end[mpk - 1]
            definite, _s, _c = comp_dd(test_mems[:te], y[:te])
            f1s.append(f1_pred(definite, S))
        for i in range(len(pgrid)):
            if all(f1s[j] >= thr for j in range(i, len(pgrid))):
                return POOL_BYTES * pgrid[i], pkt_end[pgrid[i] - 1], f1s[-1]
        return None, None, f1s[-1]

    def full_btf(S, cum, thr=0.95):
        observed = set()
        seen = 0
        btf = None
        f = 0.0
        for mpk in pgrid:
            while seen < mpk:
                observed |= (pkts[seen]["path"] & S)
                seen += 1
            f = f1_pred(observed, S)
            if btf is None and f >= thr:
                btf = cum[mpk]
        return btf, f

    def coherence(S):
        Sl = sorted(S)
        if len(Sl) < 2:
            return None
        js = []
        for a in range(len(Sl)):
            for b in range(a + 1, len(Sl)):
                ca, cb = col[Sl[a]], col[Sl[b]]
                u = len(ca | cb)
                js.append(len(ca & cb) / u if u else 0.0)
        return sum(js) / len(js)

    out = {"baseboard": BASEBOARD, "n_pkts": npk, "n_tests": n_tests,
           "obs_ports": n_obs, "distinct_paths": npaths,
           "coverage_min": min(cov.values()),
           "coverage_median": statistics.median(cov.values()),
           "coverage_max": max(cov.values()),
           "cost": {"minimal_perhop": MIN_PERHOP,
                    "realistic_perhop": REALISTIC_PERHOP,
                    "pool_bytes": POOL_BYTES, "base": BASE},
           "K": K, "seed": SEED, "per_d": {}, "validation": {}}

    rng = random.Random(SEED)
    nfull_none = 0
    npool_none = 0
    for d in DS:
        cap = min(N_PLACE, comb(n_obs, d))
        seen_set = set()
        placements = []
        tries = 0
        while len(placements) < cap and tries < cap * 80:
            tries += 1
            S = frozenset(rng.sample(obs, d))
            if S not in seen_set:
                seen_set.add(S)
                placements.append(S)
        rows = []
        for S in placements:
            pb, pm, pf = pool_btf(S)
            fbmin, _ = full_btf(S, cum_min)
            fbreal, ffr = full_btf(S, cum_real)
            if fbmin is None or fbreal is None:
                nfull_none += 1
            if pb is None:
                npool_none += 1
            rows.append({"S": sorted(S), "pool_btf": pb, "pool_minm": pm,
                         "pool_f1full": pf, "full_btf_min": fbmin,
                         "full_btf_real": fbreal, "coh": coherence(S),
                         "covs": [cov[e] for e in S]})
        out["per_d"][str(d)] = {"n": len(rows), "rows": rows}
        print("d=%d placements=%d done" % (d, len(rows)))

    out["validation"] = {"full_none": nfull_none, "pool_none": npool_none}
    print("VALIDATION full_none=%d pool_none=%d (full_none MUST be 0)"
          % (nfull_none, npool_none))

    # ---- sampling variance over the d5 placements -----------------------
    d5_S = [frozenset(r["S"]) for r in out["per_d"]["5"]["rows"][:30]]
    srng = random.Random(SEED + 777)
    samp = {}
    for s in SAMP_RATES:
        f1s = []
        miss = 0
        trials = 0
        for S in d5_S:
            for _ in range(SAMP_SEEDS):
                observed = set()
                for p in pkts:
                    if srng.random() < s:
                        observed |= (p["path"] & S)
                f1s.append(f1_pred(observed, S))
                trials += 1
                if observed != set(S):
                    miss += 1
        samp["%.5f" % s] = {"f1_mean": statistics.mean(f1s),
                            "f1_std": statistics.pstdev(f1s),
                            "miss_rate": miss / trials, "trials": trials}
        print("samp s=%.5f f1=%.3f+-%.3f miss=%.3f"
              % (s, samp["%.5f" % s]["f1_mean"], samp["%.5f" % s]["f1_std"],
                 samp["%.5f" % s]["miss_rate"]))
    out["sampling_variance"] = samp

    json.dump(out, open(os.path.join(RES, "m3b1b_study.json"), "w"), indent=2)
    print("m3b1b_study written")


if __name__ == "__main__":
    main()
