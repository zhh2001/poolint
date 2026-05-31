#!/usr/bin/env python3
"""M3-seed (offline): validate Thm 4 — greedy submodular seed selection lowers
coherence-driven PoolINT cost. O29 board, gate#0-exact membership, no network.

The PoolINT "round seed" is the round_r byte of the membership key; member() =
crc32(test_id,epoch,puid,FAIL,seed) % HASH_MOD < RHO_PERMIL. A candidate pool of
M seeds = round_r values {0..M-1} (each a distinct, reproducible hash). PoolINT
uses R such seeds (R tests per packet); syndrome is a fixed 9 B regardless, so a
better seed choice shows up as FEWER packets (lower m / bytes) to reach F1, not
fewer bytes/packet.

  - baseline : R random seeds (status quo).
  - optimized: greedy R seeds maximizing |∪_s D(s)|, D(s) = observable port pairs
    distinguished by seed s (some packet's path holds both but seed-s membership
    includes exactly one). Submodular coverage.

Static sparse support (prefix sample-complexity, as in [M3b-1b], where the
coherence→cost r≈0.46 was measured). Placements tiered low/mid/high by baseline
column-coherence. Reports f, mean column coherence, and per-tier F1-vs-m /
bytes-to-F1≥0.95 / min-m for random vs optimized.
"""
import json
import os
import random
import statistics
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("topo", "control", "collector"):
    sys.path.insert(0, os.path.join(ROOT, sub))
from fat_tree import FatTree
import poolint_hash as H
from poolint_collector import comp_dd

RES = os.path.join(ROOT, "results")
T = FatTree(k=4)
BOARD = "raw/pool_ft_d2.jsonl"
M_POOL = 32                 # candidate seeds = round_r 0..31
R = 2                       # seeds PoolINT uses (= rounds)
D = 3
POOL_BYTES = 9
N_PLACE = 120
SEED = 2024
THR = 0.95


def load(jsonl):
    pkts = []
    obs = set()
    for line in open(os.path.join(RES, jsonl)):
        line = line.strip()
        if not line:
            continue
        p = json.loads(line)
        path = T.reconstruct_path(p["src"], p["dst"], p["proto"],
                                  p["sport"], p["dport"])
        if not path:
            continue
        pkts.append({"path": list(path), "test_id": p["test_id"],
                     "epoch": p["epoch_id"]})
        for e in path:
            obs.add(e)
    return pkts, sorted(obs)


def membership(pk, seed):
    return [e for e in pk["path"]
            if H.member(pk["test_id"], pk["epoch"], e, H.MID_FAIL, seed)]


def f1(pred, truth):
    pred, truth = set(pred), set(truth)
    if not pred and not truth:
        return 1.0
    tp = len(pred & truth)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(truth) if truth else 0.0
    return (2 * p * r / (p + r)) if (p + r) else 0.0


def main():
    pkts, obs = load(BOARD)
    npk = len(pkts)

    # precompute membership per seed (set per packet) for the whole pool
    mem = {s: [set(membership(pk, s)) for pk in pkts] for s in range(M_POOL)}

    # co-occurring observable pairs (universe) + per-seed distinguished pairs
    def pair(i, j):
        return (i, j) if i < j else (j, i)
    universe = set()
    for pk in pkts:
        pth = pk["path"]
        for a in range(len(pth)):
            for b in range(a + 1, len(pth)):
                universe.add(pair(pth[a], pth[b]))
    Dset = {}
    for s in range(M_POOL):
        d = set()
        ms = mem[s]
        for k, pk in enumerate(pkts):
            inm = ms[k]
            pth = pk["path"]
            for a in range(len(pth)):
                for b in range(a + 1, len(pth)):
                    i, j = pth[a], pth[b]
                    if (i in inm) != (j in inm):
                        d.add(pair(i, j))
        Dset[s] = d

    # greedy submodular cover of R seeds
    chosen = []
    covered = set()
    remaining = set(range(M_POOL))
    for _ in range(R):
        best = max(remaining, key=lambda s: len(Dset[s] - covered))
        chosen.append(best)
        covered |= Dset[best]
        remaining.discard(best)
    opt_seeds = chosen
    f_opt = len(covered) / len(universe)

    rng = random.Random(SEED)
    rand_seeds = rng.sample(range(M_POOL), R)
    rand_cov = set()
    for s in rand_seeds:
        rand_cov |= Dset[s]
    f_rand = len(rand_cov) / len(universe)

    # column-coherence over observable pairs for a seed-set: mean Jaccard of
    # test-columns (which (pkt,seed) tests include each port)
    def columns(seeds):
        col = {e: set() for e in obs}
        for s in seeds:
            ms = mem[s]
            for k in range(npk):
                for e in ms[k]:
                    col[e].add((s, k))
        return col

    def mean_coherence(seeds):
        col = columns(seeds)
        js = []
        for (i, j) in universe:
            a, b = col[i], col[j]
            u = len(a | b)
            js.append(len(a & b) / u if u else 0.0)
        return statistics.mean(js)

    coh_rand = mean_coherence(rand_seeds)
    coh_opt = mean_coherence(opt_seeds)

    # prefix decode helper for a seed-set on a placement
    pgrid = []
    m = 16
    while m < npk:
        pgrid.append(m)
        m = int(m * 1.8) + 1
    pgrid.append(npk)

    def prefix_curve(seeds, S):
        Sset = set(S)
        rows, ys = [], []
        # interleave seeds per packet, in packet order
        per_pkt = [[mem[s][k] for s in seeds] for k in range(npk)]
        out = []
        idx = 0
        built_to = 0
        flat_rows, flat_ys = [], []
        # build incrementally to pgrid
        gi = 0
        for k in range(npk):
            for r in range(len(seeds)):
                mm = per_pkt[k][r]
                if mm:
                    flat_rows.append(mm)
                    flat_ys.append(1 if (mm & Sset) else 0)
            if gi < len(pgrid) and (k + 1) == pgrid[gi]:
                est = set(comp_dd(flat_rows, flat_ys)[0]) if flat_rows else set()
                out.append((pgrid[gi], f1(est, Sset)))
                gi += 1
        return out

    def bytes_to_f1(curve):
        for i, (mpk, fv) in enumerate(curve):
            if all(curve[j][1] >= THR for j in range(i, len(curve))):
                return POOL_BYTES * mpk, mpk
        return None, None

    # column coherence of a placement's fault ports under baseline seeds
    base_col = columns(rand_seeds)

    def placement_coh(S):
        Sl = sorted(S)
        js = []
        for a in range(len(Sl)):
            for b in range(a + 1, len(Sl)):
                ca, cb = base_col[Sl[a]], base_col[Sl[b]]
                u = len(ca | cb)
                js.append(len(ca & cb) / u if u else 0.0)
        return statistics.mean(js) if js else 0.0

    # generate placements, tier by coherence
    prng = random.Random(SEED + 1)
    placements = []
    seen = set()
    while len(placements) < N_PLACE:
        S = tuple(sorted(prng.sample(obs, D)))
        if S in seen:
            continue
        seen.add(S)
        placements.append((S, placement_coh(S)))
    placements.sort(key=lambda x: x[1])
    t = len(placements) // 3
    tiers = {"low": placements[:t], "mid": placements[t:2 * t],
             "high": placements[2 * t:]}

    out = {"board": "O29", "npk": npk, "obs": len(obs),
           "M_pool": M_POOL, "R": R, "d": D, "pool_bytes": POOL_BYTES,
           "universe_pairs": len(universe),
           "rand_seeds": rand_seeds, "opt_seeds": opt_seeds,
           "f_rand": f_rand, "f_opt": f_opt,
           "coherence_rand": coh_rand, "coherence_opt": coh_opt,
           "tiers": {}}
    for tname, plist in tiers.items():
        agg = {"rand": {"btf": [], "minm": [], "curve_f1": {}},
               "opt": {"btf": [], "minm": [], "curve_f1": {}}}
        coh_vals = []
        for (S, c) in plist:
            coh_vals.append(c)
            for key, seeds in (("rand", rand_seeds), ("opt", opt_seeds)):
                cur = prefix_curve(seeds, S)
                b, mm = bytes_to_f1(cur)
                if b is not None:
                    agg[key]["btf"].append(b)
                    agg[key]["minm"].append(mm)
                for (mpk, fv) in cur:
                    agg[key]["curve_f1"].setdefault(mpk, []).append(fv)
        rec = {"n": len(plist),
               "coh_range": [min(coh_vals), max(coh_vals)],
               "coh_mean": statistics.mean(coh_vals)}
        for key in ("rand", "opt"):
            rec[key] = {
                "btf_mean": statistics.mean(agg[key]["btf"]) if agg[key]["btf"] else None,
                "btf_n_reached": len(agg[key]["btf"]),
                "minm_mean": statistics.mean(agg[key]["minm"]) if agg[key]["minm"] else None,
                "curve": {str(mpk): statistics.mean(v)
                          for mpk, v in sorted(agg[key]["curve_f1"].items())}}
        out["tiers"][tname] = rec
        rb = rec["rand"]["btf_mean"]
        ob = rec["opt"]["btf_mean"]
        red = (100 * (rb - ob) / rb) if (rb and ob) else None
        print("tier %s n=%d coh[%.3f,%.3f] | rand btf=%s opt btf=%s reduce=%s%%"
              % (tname, len(plist), rec["coh_range"][0], rec["coh_range"][1],
                 round(rb) if rb else None, round(ob) if ob else None,
                 round(red, 1) if red is not None else "NA"))

    json.dump(out, open(os.path.join(RES, "m3seed.json"), "w"), indent=2)
    print("f_rand=%.3f f_opt=%.3f coh_rand=%.4f coh_opt=%.4f seeds rand=%s opt=%s"
          % (f_rand, f_opt, coh_rand, coh_opt, rand_seeds, opt_seeds))
    print("m3seed written")


if __name__ == "__main__":
    main()
