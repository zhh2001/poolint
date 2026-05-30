#!/usr/bin/env python3
"""Bit-exact reimplementation of the PoolINT data-plane hashing (crc revision).

Two independent hashes, both via bmv2 HashAlgorithm externs over byte-aligned
field lists, both reproduced here over the SAME byte string:

  * membership gate  -> bmv2 crc32  (poolint.p4 PoolEgress.gate)
        hval = crc32(key7) mod HASH_MOD ; member = hval < RHO_PERMIL
  * ECMP             -> bmv2 crc16  (poolint.p4 PoolIngress.ecmp_group)
        sel  = crc16(key13) mod group_size

The exact CRC variants bmv2 uses are FIXED below (CRC32_CHOSEN / CRC16_CHOSEN)
after a one-time calibration against ground truth stamped in the packets
(poolint_dbg.dbg_hash for crc32, poolint_dbg.dbg_spine for crc16).  They are NOT
re-selected at run time -- reproducibility is a hard requirement.  pick_*()
remain only to (re)run that calibration on demand.

All constants here MUST match p4src/poolint/headers.p4.
"""
import zlib

# ---- structural constants (== headers.p4) ----------------------------
HASH_MOD = 1000
RHO_PERMIL = 500            # rho = 0.5
R = 2
MID_FAIL, MID_QHI, MID_QDEPTH, MID_UTIL = 0, 1, 2, 3
BOOL_METRICS = [MID_FAIL, MID_QHI]      # bsynd bit = idx*R + r
QUANT_METRICS = [MID_QDEPTH, MID_UTIL]  # quant slot = idx*R + r

# ---- FIXED CRC variants (locked after gate #0a calibration) ----------
# CRC32_CHOSEN: membership hash; CRC16_CHOSEN: ECMP.  See REPORT [M2-gate0].
CRC32_CHOSEN = "ZLIB"        # CRC-32/ISO-HDLC: poly 0x04C11DB7 init 0xFFFFFFFF
                             # refin=T refout=T xorout 0xFFFFFFFF (== zlib.crc32,
                             # == "IEEE" variant). Verified by the gate-#0a run
                             # itself: ZLIB matches dbg_hash 100% over ~6k pkts,
                             # BZIP2 0/6711. See REPORT [M2-gate0].
CRC16_CHOSEN = "ARC"          # CRC-16/ARC: poly 0x8005 init 0x0000 refin refout
                              # xorout 0x0000.  Locked by calibrate_crc.py
                              # (2145/2145 match vs dbg_spine). See REPORT [M2-gate0].


def port_uid(switch_id, egress_port):
    return ((switch_id << 8) | (egress_port & 0xff)) & 0xffff


# ---- parameterizable CRC-32 -----------------------------------------
def _crc_param(data, width, poly, init, refin, refout, xorout):
    def reflect(v, n):
        r = 0
        for i in range(n):
            if v & (1 << i):
                r |= 1 << (n - 1 - i)
        return r
    topbit = 1 << (width - 1)
    mask = (1 << width) - 1
    crc = init
    for byte in data:
        b = reflect(byte, 8) if refin else byte
        crc ^= (b << (width - 8)) & mask
        for _ in range(8):
            if crc & topbit:
                crc = ((crc << 1) ^ poly) & mask
            else:
                crc = (crc << 1) & mask
    if refout:
        crc = reflect(crc, width)
    return (crc ^ xorout) & mask


CRC32_VARIANTS = {
    "ZLIB":   lambda d: zlib.crc32(d) & 0xFFFFFFFF,
    "IEEE":   lambda d: _crc_param(d, 32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
    "BZIP2":  lambda d: _crc_param(d, 32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0xFFFFFFFF),
    "MPEG2":  lambda d: _crc_param(d, 32, 0x04C11DB7, 0xFFFFFFFF, False, False, 0x00000000),
    "POSIX":  lambda d: _crc_param(d, 32, 0x04C11DB7, 0x00000000, False, False, 0xFFFFFFFF),
    "CRC32C": lambda d: _crc_param(d, 32, 0x1EDC6F41, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
    "JAMCRC": lambda d: _crc_param(d, 32, 0x04C11DB7, 0xFFFFFFFF, True, True, 0x00000000),
}

# ---- parameterizable CRC-16 -----------------------------------------
CRC16_VARIANTS = {
    "ARC":         lambda d: _crc_param(d, 16, 0x8005, 0x0000, True, True, 0x0000),
    "CCITT_FALSE": lambda d: _crc_param(d, 16, 0x1021, 0xFFFF, False, False, 0x0000),
    "XMODEM":      lambda d: _crc_param(d, 16, 0x1021, 0x0000, False, False, 0x0000),
    "KERMIT":      lambda d: _crc_param(d, 16, 0x1021, 0x0000, True, True, 0x0000),
    "MODBUS":      lambda d: _crc_param(d, 16, 0x8005, 0xFFFF, True, True, 0x0000),
    "USB":         lambda d: _crc_param(d, 16, 0x8005, 0xFFFF, True, True, 0xFFFF),
    "GENIBUS":     lambda d: _crc_param(d, 16, 0x1021, 0xFFFF, False, False, 0xFFFF),
    "DDS110":      lambda d: _crc_param(d, 16, 0x8005, 0x800D, False, False, 0x0000),
    "MAXIM":       lambda d: _crc_param(d, 16, 0x8005, 0x0000, True, True, 0xFFFF),
}

# explicit parameter records for documentation / REPORT
CRC32_PARAMS = {
    "ZLIB": dict(poly=0x04C11DB7, init=0xFFFFFFFF, refin=True, refout=True, xorout=0xFFFFFFFF),
}
CRC16_PARAMS = {
    "ARC":         dict(poly=0x8005, init=0x0000, refin=True,  refout=True,  xorout=0x0000),
    "CCITT_FALSE": dict(poly=0x1021, init=0xFFFF, refin=False, refout=False, xorout=0x0000),
    "XMODEM":      dict(poly=0x1021, init=0x0000, refin=False, refout=False, xorout=0x0000),
    "KERMIT":      dict(poly=0x1021, init=0x0000, refin=True,  refout=True,  xorout=0x0000),
    "MODBUS":      dict(poly=0x8005, init=0xFFFF, refin=True,  refout=True,  xorout=0x0000),
    "USB":         dict(poly=0x8005, init=0xFFFF, refin=True,  refout=True,  xorout=0xFFFF),
    "GENIBUS":     dict(poly=0x1021, init=0xFFFF, refin=False, refout=False, xorout=0xFFFF),
    "DDS110":      dict(poly=0x8005, init=0x800D, refin=False, refout=False, xorout=0x0000),
    "MAXIM":       dict(poly=0x8005, init=0x0000, refin=True,  refout=True,  xorout=0xFFFF),
}


def _crc32(data, variant=None):
    return CRC32_VARIANTS[variant or CRC32_CHOSEN](bytes(data))


def _crc16(data, variant=None):
    return CRC16_VARIANTS[variant or CRC16_CHOSEN](bytes(data))


# ---- membership key (== headers.p4 hashkey_t, 7 bytes big-endian) ----
def membership_key(test_id, epoch_id, puid, metric_id, round_r):
    return bytes([
        (test_id >> 8) & 0xff, test_id & 0xff,
        epoch_id & 0xff,
        (puid >> 8) & 0xff, puid & 0xff,
        metric_id & 0xff, round_r & 0xff,
    ])


def hash_h(test_id, epoch_id, puid, metric_id, round_r, variant=None):
    """crc32(key) mod HASH_MOD -- the value the data plane compares to RHO."""
    return _crc32(membership_key(test_id, epoch_id, puid, metric_id, round_r),
                  variant) % HASH_MOD


def member(test_id, epoch_id, puid, metric_id, round_r, variant=None):
    return hash_h(test_id, epoch_id, puid, metric_id, round_r, variant) < RHO_PERMIL


# ---- ECMP key (crc16 over the 13-byte 5-tuple) -----------------------
def ecmp_fields_bytes(src_ip, dst_ip, proto, l4src, l4dst, swid=None):
    def ip2b(ip):
        return bytes(int(o) & 0xff for o in ip.split("."))
    b = (ip2b(src_ip) + ip2b(dst_ip) + bytes([proto & 0xff]) +
         bytes([(l4src >> 8) & 0xff, l4src & 0xff]) +
         bytes([(l4dst >> 8) & 0xff, l4dst & 0xff]))
    if swid is not None:                       # M3a fat-tree: per-hop swid in key
        b += bytes([(swid >> 8) & 0xff, swid & 0xff])
    return b


def ecmp_select(src_ip, dst_ip, proto, l4src, l4dst, group_size, variant=None,
                swid=None):
    data = ecmp_fields_bytes(src_ip, dst_ip, proto, l4src, l4dst, swid=swid)
    return _crc16(data, variant) % group_size


# ---- calibration helpers (run once; result is FIXED above) -----------
def pick_crc32(samples):
    """samples: [(test_id,epoch_id,puid,dbg_hash)]. Return (best,frac,scores)
    matching crc32(membership_key(...,FAIL,0)) mod HASH_MOD == dbg_hash."""
    scores = {}
    for name in CRC32_VARIANTS:
        ok = tot = 0
        for (tid, ep, puid, dh) in samples:
            tot += 1
            if hash_h(tid, ep, puid, MID_FAIL, 0, name) == dh:
                ok += 1
        scores[name] = ok / tot if tot else 0.0
    best = max(scores, key=scores.get) if scores else None
    return best, (scores.get(best, 0.0) if best else 0.0), scores


def pick_crc16(samples, topo):
    """samples: [(src,dst,proto,sport,dport,dbg_spine_swid)]. Return
    (best,frac,scores) matching the replayed spine to dbg_spine."""
    i2h = {topo.host_ip(n): n for n in topo.hosts}
    scores = {}
    for name in CRC16_VARIANTS:
        ok = tot = 0
        for (s, d, pr, sp, dp, truth) in samples:
            if s not in i2h:
                continue
            sel = ecmp_select(s, d, pr, sp, dp, topo.S, name)
            src_leaf = topo.hosts[i2h[s]]["leaf"]
            ups = topo.uplink_ports(src_leaf)
            up = ups[sel % len(ups)]
            spine = topo.ports[src_leaf][up][1]
            tot += 1
            if topo.swid[spine] == truth:
                ok += 1
        scores[name] = ok / tot if tot else 0.0
    best = max(scores, key=scores.get) if scores else None
    return best, (scores.get(best, 0.0) if best else 0.0), scores


if __name__ == "__main__":
    k = membership_key(5, 7, port_uid(1, 1), MID_FAIL, 0)
    print("memb_key=", k.hex(), "crc32_mod=", hash_h(5, 7, port_uid(1, 1), 0, 0))
    e = ecmp_fields_bytes("10.0.1.1", "10.0.4.254", 17, 40001, 5001)
    print("ecmp_key=", e.hex(), "sel=", ecmp_select("10.0.1.1", "10.0.4.254", 17, 40001, 5001, 2))
