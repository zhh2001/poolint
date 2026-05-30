#!/usr/bin/env python3
"""Atomic M3a diagnostic: everything in one process, write compact result.
Usage: m3a_diag.py <label>   e.g. m3a_diag.py pool_ft_d1
Answers, for the target fault port(s): PKTS_ONPATH_FAULT on the MEASURED raw,
whether target is in the observed-from-MEASURED coverage, and for the largest
FAIL epoch: is truth a column of A, in how many y=1 / y=0 tests, and DD verdict.
"""
import json
import os
import sys
import collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for s in ("topo", "control", "collector"):
    sys.path.insert(0, os.path.join(ROOT, s))
import poolint_hash as H
from fat_tree import FatTree
from poolint_collector import comp_dd, pack_path

label = sys.argv[1]
RES = os.path.join(ROOT, "results")
RAW = os.path.join(RES, "raw")
t = FatTree(k=4)
gt = json.load(open(os.path.join(RES, "%s_gt.json" % label)))
fault = set(gt["fail_ports"])
pkts = [json.loads(l) for l in open(os.path.join(RAW, "%s.jsonl" % label)) if l.strip()]

out = []
out.append("LABEL=%s  TARGETS=%s  d=%d" % (label, sorted(fault), len(fault)))

# reconstruct each measured packet's path; validate vs dbg_path
recon = {}
g0b_ok = 0
for i, p in enumerate(pkts):
    pp = t.reconstruct_path(p["src"], p["dst"], p["proto"], p["sport"], p["dport"])
    recon[i] = pp
    if pp and p.get("dbg_path") and pack_path(pp) == p["dbg_path"]:
        g0b_ok += 1
out.append("MEASURED_PKTS=%d  RECON_MATCHES_DBGPATH=%d" % (len(pkts), g0b_ok))

# observed coverage from MEASURED raw
cov = collections.Counter()
for i, p in enumerate(pkts):
    for u in (recon[i] or []):
        cov[u] += 1
out.append("OBSERVED_PORTS=%d" % len(cov))
for f in sorted(fault):
    out.append("TARGET %d : PKTS_ONPATH=%d  in_observed=%s  cov=%s"
               % (f, sum(1 for i in recon if recon[i] and f in recon[i]),
                  f in cov, cov.get(f)))

# per-FAIL-epoch A/y for the target; focus on the largest epoch
bi = H.BOOL_METRICS.index(H.MID_FAIL)
rows_by_ep = {}
for i, p in enumerate(pkts):
    pp = recon[i]
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

if rows_by_ep:
    ep = max(rows_by_ep, key=lambda e: len(rows_by_ep[e][0]))
    rows, y = rows_by_ep[ep]
    cols = set().union(*rows) if rows else set()
    definite, suspects, _ = comp_dd(rows, y)
    out.append("BIG_EPOCH=%d  m_tests=%d  positives=%d  n_cols=%d"
               % (ep, len(rows), sum(y), len(cols)))
    out.append("DD_definite=%s  COMP_suspects_n=%d" % (sorted(definite), len(suspects)))
    for f in sorted(fault):
        in_cols = f in cols
        y1 = sum(1 for r_, yy in zip(rows, y) if f in r_ and yy == 1)
        y0 = sum(1 for r_, yy in zip(rows, y) if f in r_ and yy == 0)
        # would DD ever isolate f? a positive test where f is the only suspect
        uniq = 0
        for r_, yy in zip(rows, y):
            if yy == 1 and f in r_ and len(r_ & suspects) == 1 and f in suspects:
                uniq += 1
        out.append("  TRUTH %d : in_A_cols=%s  in_y1_tests=%d  in_y0_tests=%d  "
                   "in_COMP_suspects=%s  DD_unique_positive_tests=%d"
                   % (f, in_cols, y1, y0, f in suspects, uniq))

open("/tmp/m3a_diag_%s.txt" % label, "w").write("\n".join(out) + "\n")
print("WROTE /tmp/m3a_diag_%s.txt (%d lines)" % (label, len(out)))
