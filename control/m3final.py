#!/usr/bin/env python3
"""M3-final: ONE faithful, self-consistent telemetry-cost model for all 5 schemes,
compared at a DEPLOYABLE operating point (PoolINT F1 >= 0.95). Replaces the
contradictory DeltaINT-E refresh accounting of M3c-1 / M3d-2.

UNIFIED COST MODEL (per-record, boolean FAIL, K=1)
  REC  = 3 B : one (port_uid 2B + state 1B) record.   (+1 REC per extra metric)
  BASE = 8 B : INT shim on any packet that carries >=1 record.
  POOL = 9 B : PoolINT syndrome, flat per packet.
  PINT = 4 B : one hash-chosen on-path port's status per packet.
Full-INT  : every packet declares all on-path monitored ports -> BASE + REC*|onM|.
Sampling  : Full-INT on a Bernoulli(s) fraction of packets.
DeltaINT-O: a port is declared (REC) only when its state changes vs the switch's
            last-reported value; carrying packet pays BASE once.
DeltaINT-E: DeltaINT-O + periodic refresh: every P windows each monitored port is
            re-declared **ONCE** (on its first crossing packet in the window) =
            REC per crossed monitored port + BASE per carrying packet. This is the
            faithful model: a fresh sample per port per period, NOT a full per-
            packet re-report (the M3c-1/M3d-2 bug that redundantly charged every
            packet in the refresh window).
Loss q drops each transmitted record's delivery independently; transmitted bytes
are still counted (you pay to send, loss only decides if the collector learns).
PoolINT  : per-window COMP+DD over surviving report packets (Prop 2: losing q of
           packets removes q of tests, no stale state).

Realism caveat (unchanged): synthetic fault timing + synthetic loss over REAL
captured paths/test_ids; not a capture of real dynamic injection/loss.
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

REC = 3
BASE = 8
POOL = 9
PINT = 4
D = 3
QS = [0.0, 0.05, 0.10, 0.20]
P_GRID = [1, 2, 4, 8, 16]
N_PLACE = 30
LOSS_SEEDS = 6
CHURN = 0.20
SEED = 91
# board -> W chosen so PoolINT reaches deployable F1 (verified in self-check)
BOARDS = [("O29", "raw/pool_ft_d2.jsonl", 32),
          ("O74", "raw/m3d.jsonl", 8)]


def load(jsonl):
    import collections
    pkts, cov = [], collections.Counter()
    for line in open(os.path.join(RES, jsonl)):
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


def windows(npk, W):
    wp = [[] for _ in range(W)]
    for i in range(npk):
        wp[i * W // npk].append(i)
    return wp


def schedule(pool, W, rng):
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


def on_events(s, W):
    ev = []
    for e, seq in s.items():
        for w in range(W):
            if seq[w] and (w == 0 or not seq[w - 1]):
                ev.append((e, w))
    return ev


def latency(sched, pow_, W):
    lat, miss = [], 0
    for (e, w0) in on_events(sched, W):
        det = None
        w = w0
        while w < W and sched[e][w]:
            if w in pow_[e]:
                det = w - w0
                break
            w += 1
        if det is None:
            miss += 1
        else:
            lat.append(det)
    return (statistics.mean(lat) if lat else None,
            (len(lat) / (len(lat) + miss)) if (lat or miss) else 1.0)


def run_pool(pkts, wp, sched, M, W, q, lr):
    Mset = set(M)
    f1s, pow_ = [], {e: set() for e in M}
    nbytes = 0
    for w in range(W):
        tw = truth_at(sched, w)
        rows, ys = [], []
        for i in wp[w]:
            if lr.random() < q:
                continue
            nbytes += POOL
            for r in range(H.R):
                mem = pkts[i]["rows"][r] & Mset
                if mem:
                    rows.append(mem)
                    ys.append(1 if (mem & tw) else 0)
        est = (set(comp_dd(rows, ys)[0]) & Mset) if rows else set()
        f1s.append(f1(est, tw))
        for e in est:
            pow_[e].add(w)
    lm, dr = latency(sched, pow_, W)
    return statistics.mean(f1s), nbytes, lm, dr


def run_full(pkts, wp, sched, M, W, q, lr, s=1.0):
    Mset = set(M)
    known = {}
    f1s, pow_ = [], {e: set() for e in M}
    nbytes = 0
    for w in range(W):
        tw = truth_at(sched, w)
        for i in wp[w]:
            if s < 1.0 and lr.random() >= s:
                continue
            onM = [e for e in pkts[i]["path"] if e in Mset]
            if not onM:
                continue
            nbytes += BASE + REC * len(onM)
            for e in onM:
                if lr.random() >= q:
                    known[e] = (e in tw)
        est = {e for e in Mset if known.get(e)}
        f1s.append(f1(est, tw))
        for e in est:
            pow_[e].add(w)
    lm, dr = latency(sched, pow_, W)
    return statistics.mean(f1s), nbytes, lm, dr


def run_pint(pkts, wp, sched, M, W, q, lr):
    Mset = set(M)
    known = {}
    f1s, pow_ = [], {e: set() for e in M}
    nbytes = 0
    for w in range(W):
        tw = truth_at(sched, w)
        for i in wp[w]:
            onM = [e for e in pkts[i]["path"] if e in Mset]
            nbytes += PINT
            if not onM:
                continue
            e = sorted(onM)[(i * 2654435761) % len(onM)]
            if lr.random() >= q:
                known[e] = (e in tw)
        est = {e for e in Mset if known.get(e)}
        f1s.append(f1(est, tw))
        for e in est:
            pow_[e].add(w)
    lm, dr = latency(sched, pow_, W)
    return statistics.mean(f1s), nbytes, lm, dr


def run_delta(pkts, wp, sched, M, W, q, lr, P=None):
    Mset = set(M)
    last_rep, known = {}, {}
    f1s, pow_ = [], {e: set() for e in M}
    nbytes, refresh_bytes = 0, 0
    for w in range(W):
        tw = truth_at(sched, w)
        is_refresh = (P is not None and w % P == 0)
        refreshed = set()
        for i in wp[w]:
            onM = [e for e in pkts[i]["path"] if e in Mset]
            if not onM:
                continue
            recs = []
            # periodic refresh: declare each monitored port ONCE this window
            if is_refresh:
                for e in onM:
                    if e not in refreshed:
                        refreshed.add(e)
                        recs.append(e)
                        last_rep[e] = (e in tw)
            # change-report: declare ports whose state changed (not already this pkt)
            for e in onM:
                cur = (e in tw)
                if last_rep.get(e) != cur and e not in recs:
                    recs.append(e)
                    last_rep[e] = cur
            if recs:
                nbytes += BASE + REC * len(recs)
                if is_refresh:
                    refresh_bytes += BASE + REC * len(recs)
                for e in recs:
                    if lr.random() >= q:
                        known[e] = (e in tw)
        est = {e for e in Mset if known.get(e)}
        f1s.append(f1(est, tw))
        for e in est:
            pow_[e].add(w)
    lm, dr = latency(sched, pow_, W)
    return statistics.mean(f1s), nbytes, lm, dr, refresh_bytes


def board_study(name, jsonl, W):
    pkts, cov = load(jsonl)
    obs = sorted(cov)
    M = obs                       # monitor the full observable set
    wp = windows(len(pkts), W)
    rng = random.Random(SEED)
    placements = [rng.sample(M, D) for _ in range(N_PLACE)]

    res = {"board": name, "npk": len(pkts), "obs": len(obs), "W": W,
           "m_O": len(M), "churn": CHURN, "d": D, "n_place": N_PLACE,
           "loss_seeds": LOSS_SEEDS, "by_q": {}}
    for q in QS:
        acc = {k: {"f1": [], "by": [], "lat": [], "dr": []}
               for k in ("full", "samp", "pint", "pool")}
        accE = {P: {"f1": [], "by": [], "lat": [], "dr": [], "rf": []}
                for P in P_GRID}
        srng = random.Random(SEED + 5)
        for pi, pool in enumerate(placements):
            sched = schedule(pool, W, random.Random(SEED + pi * 13))
            for ls in range(LOSS_SEEDS):
                base = SEED * 3 + pi * 101 + ls * 7 + int(q * 1000)
                fp = run_pool(pkts, wp, sched, M, W, q, random.Random(base + 1))
                acc["pool"]["f1"].append(fp[0]); acc["pool"]["by"].append(fp[1])
                if fp[2] is not None:
                    acc["pool"]["lat"].append(fp[2])
                acc["pool"]["dr"].append(fp[3])
                ff = run_full(pkts, wp, sched, M, W, q, random.Random(base + 2))
                acc["full"]["f1"].append(ff[0]); acc["full"]["by"].append(ff[1])
                if ff[2] is not None:
                    acc["full"]["lat"].append(ff[2])
                acc["full"]["dr"].append(ff[3])
                fs = run_full(pkts, wp, sched, M, W, q, random.Random(base + 3),
                              s=0.125)
                acc["samp"]["f1"].append(fs[0]); acc["samp"]["by"].append(fs[1])
                if fs[2] is not None:
                    acc["samp"]["lat"].append(fs[2])
                acc["samp"]["dr"].append(fs[3])
                fn = run_pint(pkts, wp, sched, M, W, q, random.Random(base + 4))
                acc["pint"]["f1"].append(fn[0]); acc["pint"]["by"].append(fn[1])
                if fn[2] is not None:
                    acc["pint"]["lat"].append(fn[2])
                acc["pint"]["dr"].append(fn[3])
                for P in P_GRID:
                    fe = run_delta(pkts, wp, sched, M, W, q,
                                   random.Random(base + 100 + P), P)
                    accE[P]["f1"].append(fe[0]); accE[P]["by"].append(fe[1])
                    if fe[2] is not None:
                        accE[P]["lat"].append(fe[2])
                    accE[P]["dr"].append(fe[3]); accE[P]["rf"].append(fe[4])

        def mean(x):
            return statistics.mean(x) if x else None
        out = {}
        for k in acc:
            out[k] = {"f1": mean(acc[k]["f1"]), "bytes": mean(acc[k]["by"]),
                      "lat": mean(acc[k]["lat"]), "detect": mean(acc[k]["dr"])}
        pool_f1 = out["pool"]["f1"]
        # DeltaINT-E steelman: min bytes s.t. F1 >= pool_f1 - 0.01
        best = None
        for P in P_GRID:
            mf1 = mean(accE[P]["f1"]); mby = mean(accE[P]["by"])
            if mf1 >= pool_f1 - 0.01 and (best is None or mby < best["bytes"]):
                best = {"P": P, "f1": mf1, "bytes": mby,
                        "lat": mean(accE[P]["lat"]),
                        "detect": mean(accE[P]["dr"]),
                        "refresh_bytes": mean(accE[P]["rf"])}
        if best is None:
            P = min(P_GRID)
            best = {"P": P, "f1": mean(accE[P]["f1"]),
                    "bytes": mean(accE[P]["by"]), "lat": mean(accE[P]["lat"]),
                    "detect": mean(accE[P]["dr"]),
                    "refresh_bytes": mean(accE[P]["rf"]), "unmatched": True}
        out["deltaE"] = best
        out["deltaE_allP"] = {str(P): {"f1": mean(accE[P]["f1"]),
                                       "bytes": mean(accE[P]["by"]),
                                       "refresh": mean(accE[P]["rf"])}
                              for P in P_GRID}
        res["by_q"]["%.2f" % q] = out
        print("%s q=%.2f poolF1=%.3f poolB=%d | dE P*=%d F1=%.3f B=%d rf=%d | "
              "full F1=%.3f B=%d | samp F1=%.3f | pint F1=%.3f"
              % (name, q, pool_f1, out["pool"]["bytes"], best["P"], best["f1"],
                 best["bytes"], best["refresh_bytes"], out["full"]["f1"],
                 out["full"]["bytes"], out["samp"]["f1"], out["pint"]["f1"]))
    return res


def main():
    out = {"cost_model": {"REC": REC, "BASE": BASE, "POOL": POOL, "PINT": PINT,
                          "P_grid": P_GRID}, "boards": {}}
    for name, jsonl, W in BOARDS:
        out["boards"][name] = board_study(name, jsonl, W)
    json.dump(out, open(os.path.join(RES, "m3final.json"), "w"), indent=2)
    print("m3final written")


if __name__ == "__main__":
    main()
