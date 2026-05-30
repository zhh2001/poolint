#!/usr/bin/env python3
"""One-shot CRC calibration for PoolINT.

Brings up the leaf-spine net with the PoolINT data plane (poolint=True so
tb_port_idx is installed and test_id increments), sends iperf flows from
several leaves, sniffs PoolINT report frames at the collector, and:
  * crc32 (membership): finds the CRC-32 variant whose
    crc32(membership_key(test_id,epoch,dbg_port_uid,FAIL,0)) == dbg_hash for
    100% of samples.
  * crc16 (ECMP): finds the CRC-16 variant whose replayed spine == dbg_spine
    for 100% of samples.
Writes results/crc_calib.json (per-variant match fractions + sample counts +
a few raw samples for the audit trail).  Does NOT mutate poolint_hash.py; the
winners are locked there by hand after reading this.
"""
import json
import os
import struct
import sys
import time

THIS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(THIS)
for sub in ("topo", "control", "scripts"):
    sys.path.insert(0, os.path.join(ROOT, sub))

from mininet.log import setLogLevel
from scapy.all import sniff

import poolint_runner as RUN
import poolint_hash as H
from leaf_spine import LeafSpine

POOL_LEN, DBG_LEN = 9, 7


def main():
    setLogLevel("warning")
    topo = LeafSpine()
    net, thrift = RUN.build_net(topo, RUN.POOL_JSON, "/tmp", False)
    net.start(); time.sleep(1)
    # poolint=True so tb_port_idx + test_id counters are active
    RUN.populate(topo, thrift, "/tmp/poolcmds_cal", False)
    import gen_commands
    paths = gen_commands.write_files(topo, "/tmp/poolcmds_cal", poolint=True)
    for sw in sorted(paths):
        with open(paths[sw]) as fh:
            __import__("subprocess").run(
                "simple_switch_CLI --thrift-port %d" % thrift[sw],
                shell=True, stdin=fh,
                stdout=__import__("subprocess").DEVNULL,
                stderr=__import__("subprocess").DEVNULL)
    RUN.static_arp(net, topo); time.sleep(1)

    col = topo.collector_name()
    colip = topo.host_ip(col)
    caps = []

    def handle(p):
        b = bytes(p)
        if b[12:14] != b"\x12\x13":
            return
        off = 14
        test_id, epoch_id = struct.unpack(">HB", b[off:off + 3])
        off += POOL_LEN
        dbg_hash, dbg_port_uid, dbg_spine = struct.unpack(">IHB", b[off:off + DBG_LEN])
        off += DBG_LEN
        ihl = (b[off] & 0x0f) * 4
        proto = b[off + 9]
        src = ".".join(str(x) for x in b[off + 12:off + 16])
        dst = ".".join(str(x) for x in b[off + 16:off + 20])
        sp, dp = struct.unpack(">HH", b[off + ihl:off + ihl + 4])
        caps.append((test_id, epoch_id, dbg_hash, dbg_port_uid, dbg_spine,
                     src, dst, proto, sp, dp))

    import threading
    th = threading.Thread(target=lambda: sniff(
        iface="%s-eth0" % col, prn=handle, count=4000, timeout=14, store=False,
        lfilter=lambda p: bytes(p)[12:14] == b"\x12\x13"))
    th.start(); time.sleep(2.0)
    for sh in ["h1_1", "h2_1", "h3_1", "h1_2", "h2_2"]:
        net.get(sh).cmd("iperf -c %s -u -b 3M -t 8 -l 200 -p 5001 -B %s "
                        ">/tmp/ip_%s.log 2>&1 &"
                        % (colip, topo.host_ip(sh), sh))
    th.join()
    net.stop()

    crc32_samples = [(t, e, pu, dh) for (t, e, dh, pu, ds, s, d, pr, sp, dp)
                     in caps if pu]
    crc16_samples = [(s, d, pr, sp, dp, ds) for (t, e, dh, pu, ds, s, d, pr, sp, dp)
                     in caps if ds >= 100]

    out = {"captured": len(caps),
           "crc32_samples": len(crc32_samples),
           "crc16_samples": len(crc16_samples)}
    b32, f32, s32 = H.pick_crc32(crc32_samples)
    out["crc32"] = {"best": b32, "frac": f32, "scores": s32}
    b16, f16, s16 = H.pick_crc16(crc16_samples, topo)
    out["crc16"] = {"best": b16, "frac": f16, "scores": s16}
    # a few raw samples for the audit trail
    out["sample_crc32"] = [{"test_id": t, "epoch": e, "port_uid": pu,
                            "dbg_hash": dh} for (t, e, pu, dh) in crc32_samples[:5]]
    json.dump(out, open(os.path.join(ROOT, "results/crc_calib.json"), "w"),
              indent=2)
    print("CAPTURED=%d crc32_samples=%d crc16_samples=%d"
          % (len(caps), len(crc32_samples), len(crc16_samples)))
    print("crc32 best=%s frac=%.4f ; crc16 best=%s frac=%.4f"
          % (b32, f32, b16, f16))


if __name__ == "__main__":
    main()
