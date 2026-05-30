#!/usr/bin/env python3
"""PoolINT collector / sparse-recovery decoder (Milestone 2).

Sniffs PoolINT report frames (EtherType 0x1213), and for each packet:
  * parses test_id / epoch_id / boolean+quant syndromes (+ debug fields),
  * reconstructs the port path from the 5-tuple via routing + a replay of
    the bmv2 crc16 ECMP (control/poolint_hash.ecmp_select),
  * recomputes per-(metric,round) membership (the row of matrix A) with the
    bit-exact membership hash, and reads the matching syndrome (y).

Then, per (metric, epoch) it stacks A (m x n) and y and decodes:
  * boolean metrics  -> COMP + DD group testing  -> anomalous port set,
  * quant   metrics  -> NNLS (min ||As-y||, s>=0) -> per-port severity.

Gate #0 is checked inline:
  (a) recompute the source-stamped debug hash and compare bit-exact,
  (b) compare the reconstructed on-path spine to the spine the packet
      actually traversed (poolint_dbg.dbg_spine).

Everything quantitative is written to --json-out (read back by the runner;
never trust raw stdout on this box -- see REPORT M1 E-7).
"""
import argparse
import json
import os
import struct
import sys

import numpy as np
from scipy.optimize import nnls
from scapy.all import sniff

THIS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(THIS)
sys.path.insert(0, os.path.join(ROOT, "topo"))
sys.path.insert(0, os.path.join(ROOT, "control"))

from leaf_spine import LeafSpine
from line_topo import LineTopo
import poolint_hash as H

TYPE_POOLINT = 0x1213
POOL_LEN = 9      # test_id(2) epoch(1) flags(1) bsynd(1) q0..q3(4)
DBG_LEN = 14      # dbg_hash(4) dbg_port_uid(2) dbg_path(8)  [M3a]


# ---------------------------------------------------------------- parse
def parse_pool(raw):
    if len(raw) < 14 + POOL_LEN + DBG_LEN:
        return None
    if struct.unpack(">H", raw[12:14])[0] != TYPE_POOLINT:
        return None
    off = 14
    test_id, epoch_id, flags, bsynd, q0, q1, q2, q3 = struct.unpack(
        ">HBBBBBBB", raw[off:off + POOL_LEN])
    off += POOL_LEN
    dbg_hash, dbg_port_uid, dbg_path = struct.unpack(
        ">IHQ", raw[off:off + DBG_LEN])
    off += DBG_LEN
    if off + 20 > len(raw):
        return None
    ihl = (raw[off] & 0x0f) * 4
    proto = raw[off + 9]
    src = ".".join(str(b) for b in raw[off + 12:off + 16])
    dst = ".".join(str(b) for b in raw[off + 16:off + 20])
    sport = dport = 0
    l4 = off + ihl
    if proto in (6, 17) and l4 + 4 <= len(raw):
        sport, dport = struct.unpack(">HH", raw[l4:l4 + 4])
    return {
        "test_id": test_id, "epoch_id": epoch_id, "flags": flags,
        "bsynd": bsynd, "q": [q0, q1, q2, q3],
        "dbg_hash": dbg_hash, "dbg_port_uid": dbg_port_uid,
        "dbg_path": dbg_path,
        "src": src, "dst": dst, "proto": proto, "sport": sport, "dport": dport,
    }


# --------------------------------------------------------- helpers
def pack_path(puids):
    """Pack a reconstructed port_uid path's switch-id sequence the same way the
    data plane builds poolint_dbg.dbg_path: dbg = (dbg<<8)|switch_id per hop,
    where switch_id = port_uid >> 8.  Returns the 64-bit packed value so the
    collector can compare its replayed path to the in-packet actual path."""
    v = 0
    for pu in puids:
        v = ((v << 8) | (pu >> 8)) & 0xFFFFFFFFFFFFFFFF
    return v


# --------------------------------------------------------- decoders
def comp_dd(rows, y):
    """COMP + DD group-test decode.
    rows: list of sets of port_uids (members of each test); y: 0/1 list.
    Returns (definite_defectives, comp_suspects, columns)."""
    cols = set()
    for r in rows:
        cols |= r
    suspects = set(cols)
    for r, yi in zip(rows, y):
        if yi == 0:
            suspects -= r            # everyone in a negative test is healthy
    definite = set()
    for r, yi in zip(rows, y):
        if yi == 1:
            s = r & suspects
            if len(s) == 1:
                definite |= s        # unique suspect in a positive test
    return definite, suspects, cols


def nnls_decode(rows, y, cols, drop_saturated=True):
    """Quant decode: min ||A s - y||, s>=0.  Saturated rows (y==255) are
    dropped from the equality system by default (they only lower-bound the
    sum) -- documented in REPORT D-#4."""
    col_list = sorted(cols)
    idx = {c: i for i, c in enumerate(col_list)}
    A_rows, y_rows, n_sat = [], [], 0
    for r, yi in zip(rows, y):
        if yi >= 255:
            n_sat += 1
            if drop_saturated:
                continue
        a = np.zeros(len(col_list))
        for p in r:
            a[idx[p]] = 1.0
        A_rows.append(a)
        y_rows.append(float(yi))
    if not A_rows:
        return {c: 0.0 for c in col_list}, 0, n_sat
    A = np.array(A_rows)
    yv = np.array(y_rows)
    s, _ = nnls(A, yv)
    return {col_list[i]: float(s[i]) for i in range(len(col_list))}, len(A_rows), n_sat


def prf1(decoded, truth):
    decoded, truth = set(decoded), set(truth)
    tp = len(decoded & truth)
    fp = len(decoded - truth)
    fn = len(truth - decoded)
    prec = tp / (tp + fp) if (tp + fp) else (1.0 if not truth else 0.0)
    rec = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": prec, "recall": rec, "f1": f1}


# --------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--count", type=int, default=2000)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--label", default="poolint")
    ap.add_argument("--json-out", default=None)
    ap.add_argument("--topo", default="leaf", choices=["leaf", "line"])
    ap.add_argument("--spines", type=int, default=2)
    ap.add_argument("--leaves", type=int, default=4)
    ap.add_argument("--hosts", type=int, default=2)
    ap.add_argument("--line-n", type=int, default=5)
    ap.add_argument("--crc-variant", default=None,
                    help="ECMP crc16 variant; default = fixed H.CRC16_CHOSEN")
    ap.add_argument("--gt", default=None, help="ground-truth JSON")
    ap.add_argument("--drop-frac", type=float, default=0.0,
                    help="randomly drop this fraction of report packets (#5)")
    ap.add_argument("--drop-seed", type=int, default=12345)
    args = ap.parse_args()

    if args.topo == "line":
        topo = LineTopo(n=args.line_n)
    else:
        topo = LeafSpine(spines=args.spines, leaves=args.leaves,
                         hosts_per_leaf=args.hosts)

    crc = args.crc_variant

    def recon(p):
        return topo.reconstruct_path(p["src"], p["dst"], p["proto"],
                                     p["sport"], p["dport"], crc)

    def spine_of(p):
        return topo.spine_swid_on_path(p["src"], p["dst"], p["proto"],
                                       p["sport"], p["dport"], crc)

    pkts = []

    def handle(p):
        r = parse_pool(bytes(p))
        if r:
            pkts.append(r)

    sys.stdout.write("[poolint:%s] sniffing %s count=%d timeout=%d\n"
                     % (args.label, args.iface, args.count, args.timeout))
    sys.stdout.flush()
    sniff(iface=args.iface, prn=handle, count=args.count, timeout=args.timeout,
          store=False, lfilter=lambda p: bytes(p)[12:14] == b"\x12\x13")

    summary = {"label": args.label, "packets": len(pkts),
               "crc16_ecmp_variant": args.crc_variant or H.CRC16_CHOSEN,
               "crc32_membership_variant": H.CRC32_CHOSEN}

    # optional packet loss for #5
    if args.drop_frac > 0 and pkts:
        rng = np.random.RandomState(args.drop_seed)
        keep = rng.rand(len(pkts)) >= args.drop_frac
        pkts = [p for p, k in zip(pkts, keep) if k]
        summary["packets_after_drop"] = len(pkts)
        summary["drop_frac"] = args.drop_frac

    if not pkts:
        sys.stdout.write("[poolint:%s] NO PoolINT packets\n" % args.label)
        if args.json_out:
            json.dump(summary, open(args.json_out, "w"), indent=2)
        return

    # ---- gate #0 ----------------------------------------------------
    a_ok = a_tot = 0
    b_ok = b_tot = 0
    paths = {}
    for p in pkts:
        if p["dbg_port_uid"]:
            # dbg_hash is the FULL crc32 value (not mod HASH_MOD) the source
            # stamped for key(test_id,epoch,own_port_uid,FAIL,0); compare to the
            # full crc32 over the same 7-byte key with the fixed CRC32 variant.
            key = H.membership_key(p["test_id"], p["epoch_id"],
                                   p["dbg_port_uid"], H.MID_FAIL, 0)
            exp = H._crc32(key)
            a_tot += 1
            if exp == p["dbg_hash"]:
                a_ok += 1
        sp = spine_of(p)
        if sp is not None and p["dbg_spine"]:
            b_tot += 1
            if sp == p["dbg_spine"]:
                b_ok += 1
        puids = recon(p)
        if puids:
            paths[(p["src"], p["dst"], p["sport"], p["dport"])] = puids
    summary["gate0a_hash"] = {"matched": a_ok, "total": a_tot,
                              "exact": (a_ok == a_tot and a_tot > 0)}
    # variant sweep (calibration evidence): for the captured dbg samples, score
    # EVERY candidate CRC variant so the report can show the chosen one matches
    # 100% and all others ~0 -- proving the choice is unique & reproducible.
    c32_sweep = {name: 0 for name in H.CRC32_VARIANTS}
    c16_sweep = {name: 0 for name in H.CRC16_VARIANTS}
    c32_n = c16_n = 0
    for p in pkts:
        if p["dbg_port_uid"]:
            c32_n += 1
            key = H.membership_key(p["test_id"], p["epoch_id"],
                                   p["dbg_port_uid"], H.MID_FAIL, 0)
            for name, fn in H.CRC32_VARIANTS.items():
                if fn(bytes(key)) == p["dbg_hash"]:
                    c32_sweep[name] += 1
        if p["dbg_spine"]:
            sp_t = topo.reconstruct_path
            c16_n += 1
            for name in H.CRC16_VARIANTS:
                pp = topo.reconstruct_path(p["src"], p["dst"], p["proto"],
                                           p["sport"], p["dport"], name)
                if pp and len(pp) >= 2 and (pp[1] >> 8) == p["dbg_spine"]:
                    c16_sweep[name] += 1
    summary["crc32_variant_sweep"] = {"n": c32_n,
        "matched": {k: v for k, v in c32_sweep.items()}}
    summary["crc16_variant_sweep"] = {"n": c16_n,
        "matched": {k: v for k, v in c16_sweep.items()}}
    summary["gate0b_path_spine"] = {"matched": b_ok, "total": b_tot,
                                    "exact": (b_ok == b_tot and b_tot > 0)}
    summary["distinct_paths"] = {"%s->%s:%d->%d" % k: v for k, v in
                                 list(paths.items())[:8]}

    # ---- build per-(metric,epoch) systems ---------------------------
    # boolean metrics: rows of sets + 0/1 y
    bool_rows = {}   # (metric_idx, epoch) -> ([sets], [y])
    quant_rows = {}  # (qmetric_idx, epoch) -> ([sets], [y])
    for p in pkts:
        puids = recon(p)
        if not puids:
            continue
        ep = p["epoch_id"]
        path = set(puids)
        for bi, mid in enumerate(H.BOOL_METRICS):
            for r in range(H.R):
                mem = {u for u in path
                       if H.member(p["test_id"], ep, u, mid, r)}
                if not mem:
                    continue
                yi = (p["bsynd"] >> (bi * H.R + r)) & 1
                bool_rows.setdefault((bi, ep), ([], []))
                bool_rows[(bi, ep)][0].append(mem)
                bool_rows[(bi, ep)][1].append(yi)
        for qi, mid in enumerate(H.QUANT_METRICS):
            for r in range(H.R):
                mem = {u for u in path
                       if H.member(p["test_id"], ep, u, mid, r)}
                if not mem:
                    continue
                yi = p["q"][qi * H.R + r]
                quant_rows.setdefault((qi, ep), ([], []))
                quant_rows[(qi, ep)][0].append(mem)
                quant_rows[(qi, ep)][1].append(yi)

    gt = json.load(open(args.gt)) if (args.gt and os.path.exists(args.gt)) else {}
    bmetric_names = {0: "FAIL", 1: "QHI"}
    qmetric_names = {0: "QDEPTH", 1: "UTIL"}

    # ---- boolean decode ---------------------------------------------
    bool_out = []
    for (bi, ep), (rows, y) in sorted(bool_rows.items()):
        definite, suspects, cols = comp_dd(rows, y)
        # per-port test coverage = number of tests whose member-set contains it
        coverage = {}
        for r in rows:
            for u in r:
                coverage[u] = coverage.get(u, 0) + 1
        rec = {"metric": bmetric_names[bi], "epoch": ep,
               "m_tests": len(rows), "n_cols": len(cols),
               "positive_tests": int(sum(y)),
               "dd_defective": sorted(definite),
               "comp_suspects": sorted(suspects),
               "coverage": {str(k): coverage[k] for k in sorted(coverage)}}
        truth = gt.get("%s_ports" % bmetric_names[bi].lower())
        if truth is not None:
            rec["truth"] = sorted(truth)
            rec["eval_dd"] = prf1(definite, truth)
            rec["eval_comp"] = prf1(suspects, truth)
        bool_out.append(rec)
    summary["boolean"] = bool_out

    # ---- quant decode -----------------------------------------------
    quant_out = []
    for (qi, ep), (rows, y) in sorted(quant_rows.items()):
        sev, m_used, n_sat = nnls_decode(rows, y, set().union(*rows) if rows else set())
        ranked = sorted(sev.items(), key=lambda kv: -kv[1])
        rec = {"metric": qmetric_names[qi], "epoch": ep,
               "m_tests": len(rows), "m_used": m_used, "n_saturated": n_sat,
               "top_severity": [{"port_uid": p, "severity": round(s, 2)}
                                for p, s in ranked[:6]]}
        truth = gt.get("%s_ports" % qmetric_names[qi].lower())
        if truth is not None:
            rec["truth_ports"] = sorted(truth)
            # singleton-derived ground-truth severity per truth port
            singdict = {}
            for tp in truth:
                vals = [yy for rr, yy in zip(rows, y) if rr == {tp}]
                if vals:
                    singdict[tp] = float(np.mean(vals))
            rec["truth_severity_singleton"] = singdict
            # correlation of estimate vs truth indicator
            cols = sorted(set().union(*rows)) if rows else []
            est = np.array([sev.get(c, 0.0) for c in cols])
            ind = np.array([1.0 if c in set(truth) else 0.0 for c in cols])
            if len(cols) > 1 and est.std() > 0 and ind.std() > 0:
                rec["corr_est_vs_truth_indicator"] = float(
                    np.corrcoef(est, ind)[0, 1])
            # relative error vs singleton ground truth
            relerrs = {}
            for tp, gtv in singdict.items():
                if gtv > 0:
                    relerrs[tp] = abs(sev.get(tp, 0.0) - gtv) / gtv
            rec["rel_error_vs_singleton"] = relerrs
            top_port = ranked[0][0] if ranked else None
            rec["top1_is_truth"] = bool(top_port in set(truth))
        quant_out.append(rec)
    summary["quant"] = quant_out

    # ---- per-packet overhead (#3): CONSTANT, hop-count independent ------
    # The PoolINT syndrome header is a fixed-size struct (POOL_LEN bytes),
    # parsed identically regardless of path length; observed_hop_counts comes
    # from the reconstructed paths to prove the captured flows really span the
    # claimed number of hops.  (M1 baseline INT, by contrast, = 8 + 18*hops B.)
    BSYND_BITS = 1 * (H.R * len(H.BOOL_METRICS))    # K_b*R boolean bits
    QSYND_BITS = 8 * (H.R * len(H.QUANT_METRICS))   # K_q*R*8 quant bits
    hop_counts = sorted({len(recon(p)) for p in pkts if recon(p)})
    summary["overhead"] = {
        "core_syndrome_bytes": POOL_LEN,
        "core_syndrome_bits": POOL_LEN * 8,
        "bsynd_bits_used": BSYND_BITS,
        "qsynd_bits_used": QSYND_BITS,
        "dbg_bytes_excluded": DBG_LEN,
        "observed_hop_counts": hop_counts,
        "bytes_per_hop": 0,
    }

    if args.json_out:
        json.dump(summary, open(args.json_out, "w"), indent=2)
    sys.stdout.write("[poolint:%s] pkts=%d gate0a=%s gate0b=%s\n"
                     % (args.label, len(pkts),
                        summary["gate0a_hash"], summary["gate0b_path"]))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
