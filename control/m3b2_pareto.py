#!/usr/bin/env python3
"""M3b-2 (offline): fixed-byte-budget Pareto of F1 AND miss-rate, stratified by
fault on-path coverage, to answer "if sampling is cheaper, why PoolINT?".

Schemes on the same baseboard, paired per fault placement:
  Full-INT     : reveals truth of every on-path port; a fault is revealed the
                 first time a packet crosses it. Deterministic. cost = realistic
                 per-hop. bytes = cum_real[first-crossing].
  Sampling(s)  : Bernoulli(s); a fault is revealed at the first SAMPLED crossing.
                 Stochastic over seeds; can spend at most ~s*total bytes, so it
                 has a miss FLOOR = 1 - prod_e (1-(1-s)^cov_e).
  PoolINT      : flat 9 B/packet; COMP+DD decode of the gate-verified synthesised
                 FAIL syndrome; bytes = 9 * packets decoded.

Reveal coverage = ON-PATH crossings (Full/Sampling reveal by crossing, not by
membership). Faults are drawn from the observable ports; stratified low/mid/high
by on-path coverage. d in {1,3}. Reports F1/recall/miss vs byte budget per layer
+ the headline: bytes for sampling to reach zero-miss vs PoolINT's bytes.
"""
import json
import os
import random
import statistics
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "control"))
sys.path.insert(0, os.path.join(ROOT, "collector"))
import offline_faultsim as FS
from poolint_collector import comp_dd

RES = os.path.join(ROOT, "results")
BASEBOARD = "d2"
SEED = 7
PER_LAYER = 50
SAMP_RATES = [0.25, 0.125, 0.0625, 0.03125, 0.015625]   # 1/4 .. 1/64
SAMP_SEEDS = 40
REAL_PERHOP = 16
BASE = 8
POOL_BYTES = 9
LOW_THR = 300            # low coverage = on-path crossings < 300


def f1_from_recall(recall):
    # precision = 1 for truth-revealing schemes; F1 = 2r/(1+r)
    return (2 * recall / (1 + recall)) if recall > 0 else 0.0


def main():
    pkts, cov_mem, npaths = FS.build_baseboard(BASEBOARD)
    obs = sorted(cov_mem)
    npk = len(pkts)

    onpath_idx = {e: [] for e in obs}
    for i, p in enumerate(pkts):
        for e in p["path"]:
            if e in onpath_idx:
                onpath_idx[e].append(i)
    cov_op = {e: len(onpath_idx[e]) for e in obs}

    cum_real = [0] * (npk + 1)
    for i, p in enumerate(pkts):
        cum_real[i + 1] = cum_real[i] + BASE + REAL_PERHOP * p["hops"]
    total_real = cum_real[npk]

    # PoolINT flattened tests
    test_mems = []
    pkt_end = []
    for p in pkts:
        for mem in p["rows"]:
            test_mems.append(mem)
        pkt_end.append(len(test_mems))

    # coverage layers (by on-path coverage)
    hi_lo = sorted(e for e in obs if cov_op[e] >= LOW_THR)
    mid_cut = cov_op[hi_lo[len(hi_lo) // 2]] if hi_lo else LOW_THR
    layer_of = {}
    for e in obs:
        if cov_op[e] < LOW_THR:
            layer_of[e] = "low"
        elif cov_op[e] < mid_cut:
            layer_of[e] = "mid"
        else:
            layer_of[e] = "high"
    layers = {L: sorted(e for e in obs if layer_of[e] == L)
              for L in ("low", "mid", "high")}

    # byte-budget grid (geometric, realistic-byte scale)
    bgrid = []
    b = 500
    while b < total_real:
        bgrid.append(b)
        b = int(b * 1.7)
    bgrid.append(total_real)

    rng = random.Random(SEED)

    def placements(layer, d):
        ports = layers[layer]
        if d == 1:
            return [frozenset([e]) for e in ports]
        out = []
        seen = set()
        tries = 0
        while len(out) < PER_LAYER and tries < PER_LAYER * 400:
            tries += 1
            if len(ports) >= d:
                S = frozenset(rng.sample(ports, d))
            else:
                # not enough ports in-layer: bottleneck port in-layer + fillers
                base = rng.choice(ports)
                rest = rng.sample([e for e in obs if e != base], d - 1)
                S = frozenset([base] + rest)
                if min(cov_op[e] for e in S) >= LOW_THR and layer == "low":
                    continue
            if S in seen:
                continue
            # classify by bottleneck (min) coverage layer
            mn = min(cov_op[e] for e in S)
            lab = ("low" if mn < LOW_THR else
                   "mid" if mn < mid_cut else "high")
            if lab != layer:
                continue
            seen.add(S)
            out.append(S)
        return out

    def full_reveal_bytes(S):
        # bytes at which each fault first revealed (Full-INT)
        return {e: cum_real[onpath_idx[e][0]] for e in S}

    def pool_curve(S):
        Sset = set(S)
        y = [1 if (mem & Sset) else 0 for mem in test_mems]
        # decode at packet prefixes matching byte grid (npk = B/9)
        out = {}
        for B in bgrid:
            mpk = min(npk, max(1, B // POOL_BYTES))
            te = pkt_end[mpk - 1]
            definite, _s, _c = comp_dd(test_mems[:te], y[:te])
            rec = len(set(definite) & Sset) / len(Sset)
            out[B] = rec
        # bytes to zero-miss (recall=1 stays)
        bzero = None
        ks = sorted(out)
        for i, B in enumerate(ks):
            if all(out[ks[j]] >= 1.0 for j in range(i, len(ks))):
                bzero = B
                break
        return out, bzero

    def samp_trials(S, s):
        Sl = list(S)
        # per seed: reveal bytes per fault = s*cum_real[first sampled crossing]
        recby_budget = {B: [] for B in bgrid}
        Tlist = []
        for _ in range(SAMP_SEEDS):
            rbytes = []
            for e in Sl:
                fe = None
                for idx in onpath_idx[e]:
                    if rng.random() < s:
                        fe = idx
                        break
                rbytes.append(s * cum_real[fe] if fe is not None else None)
            T = None
            if all(r is not None for r in rbytes):
                T = max(rbytes)
            Tlist.append(T)
            for B in bgrid:
                got = sum(1 for r in rbytes if r is not None and r <= B)
                recby_budget[B].append(got / len(Sl))
        return recby_budget, Tlist

    out = {"baseboard": BASEBOARD, "npk": npk, "total_real_bytes": total_real,
           "cost": {"realistic_perhop": REAL_PERHOP, "pool_bytes": POOL_BYTES,
                    "base": BASE},
           "low_thr": LOW_THR, "mid_cut": mid_cut,
           "layers": {L: {"ports": layers[L], "n": len(layers[L]),
                          "cov_range": ([min(cov_op[e] for e in layers[L]),
                                         max(cov_op[e] for e in layers[L])]
                                        if layers[L] else None)}
                      for L in layers},
           "bgrid": bgrid, "samp_rates": SAMP_RATES, "seeds": SAMP_SEEDS,
           "results": {}}

    for d in (1, 3):
        for L in ("low", "mid", "high"):
            P = placements(L, d)
            if not P:
                continue
            key = "d%d_%s" % (d, L)
            # Full-INT
            full_rec = {B: [] for B in bgrid}
            full_bzero = []
            for S in P:
                rb = full_reveal_bytes(S)
                bz = max(rb.values())
                full_bzero.append(bz)
                for B in bgrid:
                    full_rec[B].append(sum(1 for e in S if rb[e] <= B) / len(S))
            # PoolINT
            pool_rec = {B: [] for B in bgrid}
            pool_bzero = []
            for S in P:
                pc, bz = pool_curve(S)
                pool_bzero.append(bz if bz is not None else total_real * 99)
                for B in bgrid:
                    pool_rec[B].append(pc[B])
            # Sampling per s
            samp = {}
            for s in SAMP_RATES:
                rec_acc = {B: [] for B in bgrid}
                Tall = []
                for S in P:
                    rb, Tl = samp_trials(S, s)
                    for B in bgrid:
                        rec_acc[B].extend(rb[B])
                    Tall.extend(Tl)
                # miss-floor (analytic): mean over placements of
                # 1 - prod_e (1-(1-s)^cov_e)
                floors = []
                for S in P:
                    pr = 1.0
                    for e in S:
                        pr *= (1 - (1 - s) ** cov_op[e])
                    floors.append(1 - pr)
                missfloor = statistics.mean(floors)
                samp["%.6f" % s] = {
                    "rec_mean": {str(B): statistics.mean(rec_acc[B])
                                 for B in bgrid},
                    "miss_by_B": {str(B): sum(1 for t in Tall
                                  if t is None or t > B) / len(Tall)
                                  for B in bgrid},
                    "miss_floor": missfloor,
                    "bytes_at_full": s * total_real,
                    "f1_full": f1_from_recall(statistics.mean(rec_acc[bgrid[-1]]))}
            out["results"][key] = {
                "n_placements": len(P),
                "cov_range": [min(cov_op[e] for S in P for e in S),
                              max(cov_op[e] for S in P for e in S)],
                "full": {"rec_mean": {str(B): statistics.mean(full_rec[B])
                                      for B in bgrid},
                         "miss_by_B": {str(B): sum(1 for bz in full_bzero
                                       if bz > B) / len(full_bzero)
                                       for B in bgrid},
                         "bytes_zeromiss_mean": statistics.mean(full_bzero)},
                "pool": {"rec_mean": {str(B): statistics.mean(pool_rec[B])
                                      for B in bgrid},
                         "miss_by_B": {str(B): sum(1 for bz in pool_bzero
                                       if bz > B) / len(pool_bzero)
                                       for B in bgrid},
                         "bytes_zeromiss_mean": statistics.mean(pool_bzero)},
                "sampling": samp}
            print("%s n=%d cov[%d,%d] done"
                  % (key, len(P), out["results"][key]["cov_range"][0],
                     out["results"][key]["cov_range"][1]))

    json.dump(out, open(os.path.join(RES, "m3b2_pareto.json"), "w"), indent=2)
    print("m3b2_pareto written; layers low/mid/high n=%d/%d/%d"
          % (len(layers["low"]), len(layers["mid"]), len(layers["high"])))


if __name__ == "__main__":
    main()
