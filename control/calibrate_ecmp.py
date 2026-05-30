#!/usr/bin/env python3
"""Record that bmv2's HashAlgorithm.crc16 ECMP is NOT replayable by a standard
CRC-16 (the finding that motivated PoolINT's Mersenne-hash ECMP, REPORT §E-1).

This is a diagnostic, not part of the acceptance path: PoolINT's data plane now
computes ECMP with the same Mersenne hash as membership (poolint.p4
PoolIngress.ecmp_group / poolint_hash.ecmp_select_pool), which the collector
replays exactly (gate #0b = 2160/2160).

To re-run the original brute force you need a bmv2 build that still uses
crc16 ECMP and a capture of (5-tuple -> traversed spine) ground truth; then for
each variant in poolint_hash.CRC16_VARIANTS x {fwd,rev byte order} count how
often `crc16(fields) % S` picks the spine actually traversed.  When this was run
the best match was ~0.5 (= chance on 2-way ECMP), i.e. no standard CRC-16
reproduces bmv2's internal field serialization.  Hence the switch to Mersenne.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import poolint_hash as H


def best_crc_match(samples, group_size):
    """samples: list of (src_ip,dst_ip,proto,l4src,l4dst, traversed_spine_index).
    Returns {variant/order: match_fraction} plus the best key."""
    results = {}
    for variant in H.CRC16_VARIANTS:
        for order in ("fwd", "rev"):
            ok = tot = 0
            for (s, d, p, ls, ld, truth_idx) in samples:
                data = H.ecmp_fields_bytes(s, d, p, ls, ld)
                if order == "rev":
                    data = data[::-1]
                sel = H._crc16(data, **H.CRC16_VARIANTS[variant]) % group_size
                tot += 1
                ok += (sel == truth_idx)
            results["%s/%s" % (variant, order)] = ok / tot if tot else 0.0
    best = max(results, key=results.get) if results else None
    return results, best


if __name__ == "__main__":
    print(__doc__)
    print("CRC16 variants available:", ", ".join(sorted(H.CRC16_VARIANTS)))
    print("PoolINT uses Mersenne ECMP instead; see poolint_hash.ecmp_select_pool.")
