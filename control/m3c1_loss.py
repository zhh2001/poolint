#!/usr/bin/env python3
"""M3c-1 (offline): PoolINT vs DeltaINT under REPORT-PACKET LOSS q.

Reuses the M3b-3 dynamic timeline (W windows over capture order of baseboard) and
the gate#0-bit-exact synth. Adds independent loss prob q to every *report* packet.
Faithful-by-mechanism reimplementations (not original-author code).

Schemes:
  DeltaINT-O : switch reports a port only when its true state changes vs the
               switch's last-reported value (switch updates last_reported on
               emit, regardless of loss). The emitted packet reaches the
               collector w.p. (1-q). If dropped, the collector holds the STALE
               state until the port's NEXT change -> silent miss in between.
               This is the loss vulnerability DeltaINT-O itself flags.
  DeltaINT-E : DeltaINT-O + periodic FULL refresh every P windows: on a refresh
               window every packet re-reports all on-path port states (cost like
               Full-INT for that window), each surviving w.p. (1-q). Many packets
               cross a port per window, so refresh self-heals stale state unless
               ALL crossing reports are dropped. Trades bytes for loss-robustness.
  PoolINT    : per window, decode (COMP+DD) from that window's report packets;
               loss drops q-fraction of tests only (Prop 2), no state history.

Metrics per scheme per q: per-window F1 (vs S(w), scored on the d-pool),
detection rate, detection latency (windows), cumulative TRANSMITTED bytes.
Loss is stochastic -> averaged over LOSS_SEEDS.

REALISM CAVEAT (same as M3b-3): synthetic fault timing over REAL captured paths/
test_ids; not a capture of real dynamic injection or real loss.
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
import poolint_hash as H
from poolint_collector import comp_dd

RES = os.path.join(ROOT, "results")
BASEBOARD = "d2"
SEED = 31
W = 32
D = 3
N_PLACE = 30
QS = [0.0, 0.05, 0.10, 0.20]
LOSS_SEEDS = 20
REFRESH_PS = [8, 4, 2]      # DeltaINT-E refresh every P windows
BASE = 8
PERHOP = 16
POOL_BYTES = 9


def f1(pred, truth):
    pred, truth = set(pred), set(truth)
    if not pred and not truth:
        return 1.0
    tp = len(pred & truth)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(truth) if truth else 0.0
    return (2 * p * r / (p + r)) if (p + r) else 0.0


def main():
    pkts, cov_mem, npaths = FS.build_baseboard(BASEBOARD)
    obs = sorted(cov_mem)
    npk = len(pkts)
    win_of = [i * W // npk for i in range(npk)]
    win_pkts = [[] for _ in range(W)]
    for i in range(npk):
        win_pkts[win_of[i]].append(i)

    def schedule(pool, churn, rng):
        s = {}
        for e in pool:
            st = rng.random() < 0.5
            seq = []
            for w in range(W):
                if w > 0 and rng.random() < churn:
                    st = not st
                seq.append(st)
            s[e] = seq
        return s

    def truth_at(s, w):
        return {e for e, seq in s.items() if seq[w]}

    def on_events(s):
        ev = []
        for e, seq in s.items():
            for w in range(W):
                if seq[w] and (w == 0 or not seq[w - 1]):
                    ev.append((e, w))
        return ev

    def metrics(sched, est_per_w, pow_):
        f1s = [f1(est_per_w[w], truth_at(sched, w)) for w in range(W)]
        lat, miss = [], 0
        for (e, w0) in on_events(sched):
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
        return (statistics.mean(f1s),
                statistics.mean(lat) if lat else None,
                (len(lat) / (len(lat) + miss)) if (lat or miss) else 1.0)

    def run_delta(sched, q, lrng, refresh_P=None):
        """DeltaINT-O (refresh_P=None) or DeltaINT-E. Returns est_per_w, bytes,
        port_on_windows."""
        last_rep = {}        # switch-side last reported value
        known = {}           # collector knowledge (subject to loss)
        est_per_w = [set() for _ in range(W)]
        pow_ = {e: set() for e in sched}
        nbytes = 0
        for w in range(W):
            tw = truth_at(sched, w)
            is_refresh = (refresh_P is not None and w % refresh_P == 0)
            for i in win_pkts[w]:
                p = pkts[i]
                if is_refresh:
                    # full re-report of all on-path ports
                    changed = [e for e in p["path"] if e in sched]
                    if changed:
                        nbytes += BASE + PERHOP * len(changed)
                        for e in changed:
                            last_rep[e] = (e in tw)
                            if lrng.random() >= q:      # survives
                                known[e] = (e in tw)
                else:
                    changed = []
                    for e in p["path"]:
                        if e in sched:
                            cur = (e in tw)
                            if last_rep.get(e) != cur:
                                changed.append((e, cur))
                                last_rep[e] = cur
                    if changed:
                        nbytes += BASE + PERHOP * len(changed)
                        for e, cur in changed:
                            if lrng.random() >= q:
                                known[e] = cur
            est = {e for e in sched if known.get(e)}
            est_per_w[w] = est
            for e in est:
                pow_[e].add(w)
        return est_per_w, nbytes, pow_

    def run_pool(sched, q, lrng):
        est_per_w = [set() for _ in range(W)]
        pow_ = {e: set() for e in sched}
        nbytes = 0
        for w in range(W):
            tw = truth_at(sched, w)
            rows, ys = [], []
            for i in win_pkts[w]:
                p = pkts[i]
                if lrng.random() < q:        # whole report packet lost
                    continue
                nbytes += POOL_BYTES
                for r in range(H.R):
                    mem = p["rows"][r]
                    if mem:
                        rows.append(mem)
                        ys.append(1 if (mem & tw) else 0)
            definite = comp_dd(rows, ys)[0] if rows else set()
            est = set(definite) & set(sched)
            est_per_w[w] = est
            for e in est:
                pow_[e].add(w)
        return est_per_w, nbytes, pow_

    rng = random.Random(SEED)
    pools = []
    seen = set()
    while len(pools) < N_PLACE:
        S = frozenset(rng.sample(obs, D))
        if S not in seen:
            seen.add(S)
            pools.append(sorted(S))

    churn = 0.20   # fixed mid-high churn (where loss matters); documented
    out = {"baseboard": BASEBOARD, "npk": npk, "W": W, "D": D, "churn": churn,
           "n_placements": N_PLACE, "loss_seeds": LOSS_SEEDS, "qs": QS,
           "refresh_Ps": REFRESH_PS,
           "cost": {"base": BASE, "perhop": PERHOP, "pool_bytes": POOL_BYTES},
           "results": {}}

    schemes = ["delta_O"] + ["delta_E_P%d" % P for P in REFRESH_PS] + ["pool"]
    for q in QS:
        agg = {k: {"f1": [], "lat": [], "det": [], "bytes": []}
               for k in schemes}
        for pi, pool in enumerate(pools):
            sched = schedule(pool, churn, random.Random(
                SEED + (hash(tuple(pool)) % 100000)))
            for ls in range(LOSS_SEEDS):
                lr = random.Random(SEED * 7 + pi * 131 + ls * 17 + int(q * 1000))
                runs = {"delta_O": run_delta(sched, q, lr, None)}
                for P in REFRESH_PS:
                    lr2 = random.Random(SEED * 7 + pi * 131 + ls * 17
                                        + int(q * 1000) + P * 1000003)
                    runs["delta_E_P%d" % P] = run_delta(sched, q, lr2, P)
                lr3 = random.Random(SEED * 7 + pi * 131 + ls * 17
                                    + int(q * 1000) + 555555)
                runs["pool"] = run_pool(sched, q, lr3)
                for k, (est, by, pow_) in runs.items():
                    fm, lm, dr = metrics(sched, est, pow_)
                    agg[k]["f1"].append(fm)
                    if lm is not None:
                        agg[k]["lat"].append(lm)
                    agg[k]["det"].append(dr)
                    agg[k]["bytes"].append(by)
        res = {}
        for k in schemes:
            res[k] = {"f1_mean": statistics.mean(agg[k]["f1"]),
                      "f1_std": statistics.pstdev(agg[k]["f1"]),
                      "lat_mean": statistics.mean(agg[k]["lat"]) if agg[k]["lat"] else None,
                      "detect_rate": statistics.mean(agg[k]["det"]),
                      "bytes_mean": statistics.mean(agg[k]["bytes"])}
        out["results"]["%.2f" % q] = res
        print("q=%.2f deltaO_f1=%.3f poolf1=%.3f deltaO_b=%d pool_b=%d"
              % (q, res["delta_O"]["f1_mean"], res["pool"]["f1_mean"],
                 res["delta_O"]["bytes_mean"], res["pool"]["bytes_mean"]))

    json.dump(out, open(os.path.join(RES, "m3c1_loss.json"), "w"), indent=2)
    print("m3c1_loss written; churn=%.2f W=%d seeds=%d" % (churn, W, LOSS_SEEDS))


if __name__ == "__main__":
    main()
