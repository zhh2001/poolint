#!/usr/bin/env python3
"""M3d-2 (offline): PoolINT vs DeltaINT-E bytes-at-matched-F1 vs monitored-set
size m_O — the scaling crossover. On the |O|=74 m3d capture (+ |O|=29 cross-check).

Model (reuses M3b-3/M3c-1 dynamic + loss mechanics; same realism caveat:
synthetic fault timing + synthetic loss over REAL captured paths/test_ids):
  - Time = capture order split into W windows.
  - Monitored set M = random m_O-subset of the observable ports. Faults (d) drawn
    from M; F1 scored on M only.
  - PoolINT: per window COMP+DD over surviving report packets, columns/rows
    restricted to M. bytes = 9 x surviving packets (m_O-INDEPENDENT).
  - DeltaINT-E: change-report (only on state flip vs switch last-reported) +
    periodic full refresh of ALL monitored on-path ports every P windows
    (refresh cost ∝ m_O). Loss q drops each report's delivery (bytes counted as
    transmitted). Steelman: pick the P giving MIN bytes s.t. mean F1 >= PoolINT
    mean F1 - 0.01.
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
BI = H.BOOL_METRICS.index(H.MID_FAIL)

W = 32
D = 3
N_PLACE = 30
LOSS_SEEDS = 8
CHURN = 0.20
QS = [0.10, 0.20]
M_OS = [20, 30, 40, 50, 60, 74]
P_GRID = [1, 2, 4, 8, 16]        # refresh every P windows (1 = every window)
BASE = 8
PERHOP = 16
POOL_BYTES = 9
SEED = 41


def load_baseboard(jsonl):
    """-> pkts list [{path:set,hops,rows:[set per round]}], cov Counter."""
    import collections
    pkts = []
    cov = collections.Counter()
    for line in open(jsonl):
        line = line.strip()
        if not line:
            continue
        p = json.loads(line)
        path = T.reconstruct_path(p["src"], p["dst"], p["proto"],
                                  p["sport"], p["dport"])
        if not path:
            continue
        rows = []
        for r in range(H.R):
            mem = {e for e in path
                   if H.member(p["test_id"], p["epoch_id"], e, H.MID_FAIL, r)}
            rows.append(mem)
            for e in mem:
                cov[e] += 1
        pkts.append({"path": set(path), "hops": len(path), "rows": rows})
    return pkts, cov


def f1(pred, truth):
    pred, truth = set(pred), set(truth)
    if not pred and not truth:
        return 1.0
    tp = len(pred & truth)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(truth) if truth else 0.0
    return (2 * p * r / (p + r)) if (p + r) else 0.0


def make_windows(npk):
    win_of = [i * W // npk for i in range(npk)]
    win_pkts = [[] for _ in range(W)]
    for i in range(npk):
        win_pkts[win_of[i]].append(i)
    return win_pkts


def schedule(pool, rng):
    s = {}
    for e in pool:
        st = rng.random() < 0.5
        seq = []
        for w in range(W):
            if w > 0 and rng.random() < CHURN:
                st = not st
            seq.append(st)
        s[e] = seq
    return s


def truth_at(s, w):
    return {e for e, seq in s.items() if seq[w]}


def run_pool(pkts, win_pkts, sched, M, q, lr):
    Mset = set(M)
    f1s = []
    nbytes = 0
    for w in range(W):
        tw = truth_at(sched, w)
        rows, ys = [], []
        for i in win_pkts[w]:
            if lr.random() < q:
                continue
            nbytes += POOL_BYTES
            for r in range(H.R):
                mem = pkts[i]["rows"][r] & Mset
                if mem:
                    rows.append(mem)
                    ys.append(1 if (mem & tw) else 0)
        definite = comp_dd(rows, ys)[0] if rows else set()
        f1s.append(f1(set(definite) & Mset, tw))
    return statistics.mean(f1s), nbytes


def run_delta_E(pkts, win_pkts, sched, M, q, lr, P):
    Mset = set(M)
    last_rep, known = {}, {}
    f1s = []
    nbytes = 0
    refresh_bytes = 0
    for w in range(W):
        tw = truth_at(sched, w)
        is_refresh = (w % P == 0)
        for i in win_pkts[w]:
            onM = [e for e in pkts[i]["path"] if e in Mset]
            if not onM:
                continue
            if is_refresh:
                nbytes += BASE + PERHOP * len(onM)
                refresh_bytes += BASE + PERHOP * len(onM)
                for e in onM:
                    last_rep[e] = (e in tw)
                    if lr.random() >= q:
                        known[e] = (e in tw)
            else:
                changed = []
                for e in onM:
                    cur = (e in tw)
                    if last_rep.get(e) != cur:
                        changed.append((e, cur))
                        last_rep[e] = cur
                if changed:
                    nbytes += BASE + PERHOP * len(changed)
                    for e, cur in changed:
                        if lr.random() >= q:
                            known[e] = cur
        est = {e for e in Mset if known.get(e)}
        f1s.append(f1(est, tw))
    return statistics.mean(f1s), nbytes, refresh_bytes


def study(jsonl, label, mos):
    pkts, cov = load_baseboard(jsonl)
    obs = sorted(cov)
    win_pkts = make_windows(len(pkts))
    rng = random.Random(SEED)
    out = {"label": label, "npk": len(pkts), "obs": len(obs),
           "W": W, "D": D, "churn": CHURN, "n_place": N_PLACE,
           "loss_seeds": LOSS_SEEDS, "P_grid": P_GRID, "points": {}}
    for m_O in mos:
        if m_O > len(obs):
            continue
        # fixed monitored subsets + fault placements (shared across q for pairing)
        subs = []
        for _ in range(N_PLACE):
            M = rng.sample(obs, m_O)
            pool = rng.sample(M, D)
            subs.append((M, pool))
        for q in QS:
            pool_f1s, pool_bys = [], []
            P_f1s = {P: [] for P in P_GRID}
            P_bys = {P: [] for P in P_GRID}
            P_refr = {P: [] for P in P_GRID}
            for si, (M, pool) in enumerate(subs):
                sched = schedule(pool, random.Random(SEED + si * 13 + m_O))
                for ls in range(LOSS_SEEDS):
                    lrp = random.Random(SEED * 3 + si * 101 + ls * 7
                                        + int(q * 100) + m_O * 1000)
                    fpool, bpool = run_pool(pkts, win_pkts, sched, M, q, lrp)
                    pool_f1s.append(fpool)
                    pool_bys.append(bpool)
                    for P in P_GRID:
                        lrd = random.Random(SEED * 5 + si * 211 + ls * 9
                                            + int(q * 100) + m_O * 1000 + P * 7)
                        fE, bE, rB = run_delta_E(pkts, win_pkts, sched, M, q,
                                                 lrd, P)
                        P_f1s[P].append(fE)
                        P_bys[P].append(bE)
                        P_refr[P].append(rB)
            pool_f1 = statistics.mean(pool_f1s)
            pool_by = statistics.mean(pool_bys)
            # steelman: min-bytes P with mean F1 >= pool_f1 - 0.01
            best = None
            for P in P_GRID:
                mf1 = statistics.mean(P_f1s[P])
                mby = statistics.mean(P_bys[P])
                if mf1 >= pool_f1 - 0.01:
                    if best is None or mby < best[2]:
                        best = (P, mf1, mby, statistics.mean(P_refr[P]))
            # if none match, take the highest-F1 P (most refresh)
            if best is None:
                P = min(P_GRID)
                best = (P, statistics.mean(P_f1s[P]), statistics.mean(P_bys[P]),
                        statistics.mean(P_refr[P]))
                best = best + ("UNMATCHED",)
            key = "mO%d_q%.2f" % (m_O, q)
            out["points"][key] = {
                "m_O": m_O, "q": q,
                "pool_f1": pool_f1, "pool_bytes": pool_by,
                "deltaE_bestP": best[0], "deltaE_f1": best[1],
                "deltaE_bytes": best[2], "deltaE_refresh_bytes": best[3],
                "deltaE_matched": (len(best) == 4),
                "pool_wins": pool_by <= best[2],
                "all_P": {str(P): {"f1": statistics.mean(P_f1s[P]),
                                   "bytes": statistics.mean(P_bys[P]),
                                   "refresh": statistics.mean(P_refr[P])}
                          for P in P_GRID}}
            print("%s %s mO=%d q=%.2f poolF1=%.3f poolB=%d | dE P=%d F1=%.3f "
                  "B=%d refr=%d | poolwins=%s"
                  % (label, key, m_O, q, pool_f1, pool_by, best[0], best[1],
                     best[2], best[3], pool_by <= best[2]))
    return out


def main():
    out = {"main": study(os.path.join(RES, "raw/m3d.jsonl"), "O74", M_OS)}
    # cross-check independent point: |O|=29 baseboard (pool_ft_d2)
    d2 = os.path.join(RES, "raw/pool_ft_d2.jsonl")
    if os.path.exists(d2):
        out["crosscheck"] = study(d2, "O29", [20, 29])
    json.dump(out, open(os.path.join(RES, "m3d2_scaling.json"), "w"), indent=2)
    print("m3d2_scaling written")


if __name__ == "__main__":
    main()
