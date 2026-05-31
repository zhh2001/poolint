#!/usr/bin/env python3
"""M3b-3 (offline): dynamic/churn faults; 5 schemes compared faithfully-by-
mechanism (NOT original-author code).

Time axis = capture order of the baseboard (file order = packet time). epoch_id
in the raw wraps (bmv2 counter), so we define W fixed windows over capture order
as the dynamic "epochs"; within a window the fault support is constant.

Dynamic fault model S(t): a pool of d ports, each with a random on/off schedule
over the W windows (flip prob = churn per window per port). The FAIL syndrome of
a packet in window w is the gate#0-verified synth with S = S(w):
    synth_r(p) = OR_{e in path(p)} [member(e,test_id_p,FAIL,r) AND e in S(w_p)]
For constant S this is exactly the bit-exact-verified static synth (offline_
faultsim gate), so the dynamic version inherits that correctness BY CONSTRUCTION.
REALISM CAVEAT (reported): this is synthesised dynamic faults over REAL captured
paths/test_ids, NOT a capture of real-time dynamic fault injection. The traffic
(which packet crosses which port when) is real; the fault on/off timing is
synthetic and assumed epoch-constant.

Schemes (collector keeps last-known state per port for the reveal-by-crossing
ones; PoolINT decodes each window independently):
  Full-INT   : every pkt reveals true state of all on-path ports. cost=BASE+16*hops/pkt.
  Sampling(s): only sampled pkts reveal (Bernoulli s). cost=s-fraction of Full.
  DeltaINT-O : boolean FAIL reported only when it flips vs collector's last-known;
               collector knowledge == Full (so same F1/latency) at fewer bytes.
               cost = BASE per pkt with >=1 changed on-path port + 16 per changed port.
  PINT-style : each pkt carries a small bounded digest = ONE hash-chosen on-path
               port's status. cost = PINT_BYTES/pkt. Slow learning (1 port/pkt).
  PoolINT    : flat 9 B/pkt; per-window COMP+DD over that window's tests.

Metrics per scheme per churn: per-epoch F1 (vs S(w)), detection latency in
windows (new on-event -> first window localised), cumulative bytes.
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
W = 32                      # windows (dynamic epochs)
D = 3                       # active fault-pool size
N_PLACE = 30
CHURNS = [("low", 0.05), ("mid", 0.20), ("high", 0.50)]
SAMP_S = 0.125
PINT_BYTES = 4
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

    # window of each packet (capture order)
    win_of = [i * W // npk for i in range(npk)]
    win_pkts = [[] for _ in range(W)]
    for i in range(npk):
        win_pkts[win_of[i]].append(i)

    # on-path coverage (for stratified reporting only)
    cov_op = {e: 0 for e in obs}
    for p in pkts:
        for e in p["path"]:
            if e in cov_op:
                cov_op[e] += 1

    # PINT hashed pick: one on-path port per packet, deterministic by test_id
    pint_pick = []
    for p in pkts:
        path = sorted(p["path"])
        pint_pick.append(path[hash(("pint", id(p))) % len(path)]
                         if False else path[0])   # placeholder, set below
    # deterministic by index (reproducible, no Date/random in module load)
    for i, p in enumerate(pkts):
        path = sorted(p["path"])
        pint_pick[i] = path[(i * 2654435761) % len(path)]

    full_bytes = sum(BASE + PERHOP * p["hops"] for p in pkts)

    def schedule(pool, churn, rng):
        """W x state per port: dict port-> [bool]*W ; flip prob=churn/window."""
        sched = {}
        for e in pool:
            st = rng.random() < 0.5
            seq = []
            for w in range(W):
                if w > 0 and rng.random() < churn:
                    st = not st
                seq.append(st)
            sched[e] = seq
        return sched

    def truth_at(sched, w):
        return {e for e, seq in sched.items() if seq[w]}

    def on_events(sched):
        """(port, w) where port goes off->on at window w (w=0 counts if on)."""
        ev = []
        for e, seq in sched.items():
            for w in range(W):
                if seq[w] and (w == 0 or not seq[w - 1]):
                    ev.append((e, w))
        return ev

    def run_reveal(sched, mode, srng=None, s=None):
        """Full/Sampling/DeltaINT/PINT via collector last-known. Returns
        (per_window_estimate list, bytes, est_includes(e,w) lookup)."""
        last = {}                      # collector last-known true state
        est_per_w = [set() for _ in range(W)]
        # for latency we need per-window membership of each port in estimate
        bytes_used = 0
        # we must process packets in capture order, advancing windows
        # estimate snapshot is taken at the END of each window
        # track, per port, the set of windows where estimate says "on"
        port_on_windows = {e: set() for e in sched}
        for w in range(W):
            tw = truth_at(sched, w)
            for i in win_pkts[w]:
                p = pkts[i]
                path = p["path"]
                if mode == "full":
                    for e in path:
                        if e in sched:
                            last[e] = (e in tw)
                    bytes_used += BASE + PERHOP * p["hops"]
                elif mode == "samp":
                    if srng.random() < s:
                        for e in path:
                            if e in sched:
                                last[e] = (e in tw)
                        bytes_used += BASE + PERHOP * p["hops"]
                elif mode == "delta":
                    changed = 0
                    for e in path:
                        if e in sched:
                            cur = (e in tw)
                            if last.get(e) != cur:
                                last[e] = cur
                                changed += 1
                    if changed:
                        bytes_used += BASE + PERHOP * changed
                elif mode == "pint":
                    e = pint_pick[i]
                    if e in sched:
                        last[e] = (e in tw)
                    bytes_used += PINT_BYTES
            est = {e for e in sched if last.get(e)}
            est_per_w[w] = est
            for e in est:
                port_on_windows[e].add(w)
        return est_per_w, bytes_used, port_on_windows

    def run_pool(sched):
        est_per_w = [set() for _ in range(W)]
        port_on_windows = {e: set() for e in sched}
        for w in range(W):
            tw = truth_at(sched, w)
            rows = []
            ys = []
            for i in win_pkts[w]:
                p = pkts[i]
                for r in range(H.R):
                    mem = p["rows"][r]
                    if mem:
                        rows.append(mem)
                        ys.append(1 if (mem & tw) else 0)
            definite, _s, _c = comp_dd(rows, ys) if rows else (set(), set(), set())
            est = set(definite) & set(sched)   # restrict to pool for fair F1
            # NOTE: DD may flag non-pool ports too; for F1 vs S(w) (subset of
            # pool) we score on pool membership. Report this restriction.
            est_per_w[w] = est
            for e in est:
                port_on_windows[e].add(w)
        return est_per_w, POOL_BYTES * npk, port_on_windows

    def metrics(sched, est_per_w, port_on_windows):
        # per-epoch F1 (mean over windows)
        f1s = []
        for w in range(W):
            f1s.append(f1(est_per_w[w], truth_at(sched, w)))
        # detection latency over on-events
        lat = []
        miss = 0
        for (e, w0) in on_events(sched):
            # port stays on for a run; find first window >=w0 (while still on)
            det = None
            w = w0
            while w < W and sched[e][w]:
                if w in port_on_windows[e]:
                    det = w - w0
                    break
                w += 1
            if det is None:
                miss += 1
            else:
                lat.append(det)
        return {"f1_mean": statistics.mean(f1s),
                "lat_mean": statistics.mean(lat) if lat else None,
                "n_events": len(on_events(sched)),
                "miss_events": miss,
                "detect_rate": (len(lat) / (len(lat) + miss)) if (lat or miss) else 1.0}

    rng = random.Random(SEED)
    pools = []
    seen = set()
    while len(pools) < N_PLACE:
        S = frozenset(rng.sample(obs, D))
        if S not in seen:
            seen.add(S)
            pools.append(sorted(S))

    out = {"baseboard": BASEBOARD, "npk": npk, "W": W, "D": D,
           "pkts_per_window": npk // W, "tests_per_window": 2 * npk // W,
           "n_placements": N_PLACE, "seed": SEED,
           "cost": {"base": BASE, "perhop": PERHOP, "pool_bytes": POOL_BYTES,
                    "pint_bytes": PINT_BYTES, "samp_s": SAMP_S,
                    "full_total_bytes": full_bytes},
           "churns": [c[0] for c in CHURNS],
           "results": {}}

    for cname, cp in CHURNS:
        agg = {k: {"f1": [], "lat": [], "bytes": [], "detect": []}
               for k in ("full", "samp", "delta", "pint", "pool")}
        srng = random.Random(SEED + 999)
        for pool in pools:
            sched = schedule(pool, cp, random.Random(
                SEED + hash(tuple(pool)) % 100000 + int(cp * 1000)))
            runs = {
                "full": run_reveal(sched, "full"),
                "samp": run_reveal(sched, "samp", srng, SAMP_S),
                "delta": run_reveal(sched, "delta"),
                "pint": run_reveal(sched, "pint"),
                "pool": run_pool(sched),
            }
            for k, (est, by, pow_) in runs.items():
                m = metrics(sched, est, pow_)
                agg[k]["f1"].append(m["f1_mean"])
                if m["lat_mean"] is not None:
                    agg[k]["lat"].append(m["lat_mean"])
                agg[k]["bytes"].append(by)
                agg[k]["detect"].append(m["detect_rate"])
        res = {}
        for k in agg:
            res[k] = {
                "f1_mean": statistics.mean(agg[k]["f1"]),
                "f1_std": statistics.pstdev(agg[k]["f1"]),
                "lat_mean": statistics.mean(agg[k]["lat"]) if agg[k]["lat"] else None,
                "bytes_mean": statistics.mean(agg[k]["bytes"]),
                "detect_rate": statistics.mean(agg[k]["detect"]),
            }
        out["results"][cname] = res
        print("churn=%s done full_b=%d delta_b=%d pool_b=%d"
              % (cname, res["full"]["bytes_mean"], res["delta"]["bytes_mean"],
                 res["pool"]["bytes_mean"]))

    json.dump(out, open(os.path.join(RES, "m3b3_dynamic.json"), "w"), indent=2)
    print("m3b3_dynamic written; W=%d pkts/win=%d tests/win=%d"
          % (W, npk // W, 2 * npk // W))


if __name__ == "__main__":
    main()
