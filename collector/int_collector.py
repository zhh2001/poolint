#!/usr/bin/env python3
"""Baseline INT collector.

Sniffs INT frames (EtherType 0x1212), parses the shim + per-hop metadata
stack, prints a per-flow / per-hop table plus the per-packet INT byte
overhead, and emits a machine-readable JSON summary (--json-out) that
net_runner.py consumes for before/after comparisons.

Wire layout parsed (see p4src/baseline_int/headers.p4):
  ethernet(14)  int_shim(8)  int_metadata(18)*hopCount  ipv4(20) ...
  int_shim     : ver(1) hopCount(1) maxHops(1) instr(1) origEtherType(2) rsvd(2)
  int_metadata : switch_id(2) ingress_port(2) egress_port(2) queue_depth(2)
                 hop_latency(4)  ingress_ts(6)        [newest hop first]
"""
import argparse
import json
import struct
import sys

from scapy.all import sniff

TYPE_INT = 0x1212
SHIM_LEN = 8
META_LEN = 18
CORE_META_LEN = 12   # the 5 spec-mandated fields (excl. ingress_ts extension)


def parse_int(raw):
    """Return a dict for an INT frame, or None if not INT / malformed."""
    if len(raw) < 14 + SHIM_LEN:
        return None
    if struct.unpack(">H", raw[12:14])[0] != TYPE_INT:
        return None
    ver, hop_count, max_hops, instr, orig_etype, _rsvd = struct.unpack(
        ">BBBBHH", raw[14:14 + SHIM_LEN])
    off = 14 + SHIM_LEN
    hops = []
    for _ in range(hop_count):
        if off + META_LEN > len(raw):
            return None
        swid, in_p, eg_p, qd = struct.unpack(">HHHH", raw[off:off + 8])
        hop_lat = struct.unpack(">I", raw[off + 8:off + 12])[0]
        ing_ts = int.from_bytes(raw[off + 12:off + 18], "big")
        hops.append({"switch_id": swid, "ingress_port": in_p,
                     "egress_port": eg_p, "queue_depth": qd,
                     "hop_latency": hop_lat, "ingress_ts": ing_ts})
        off += META_LEN
    hops.reverse()  # stack is newest-first; present source -> dest

    flow = None
    if off + 20 <= len(raw):
        ihl = (raw[off] & 0x0f) * 4
        proto = raw[off + 9]
        src = ".".join(str(b) for b in raw[off + 12:off + 16])
        dst = ".".join(str(b) for b in raw[off + 16:off + 20])
        sport = dport = 0
        l4 = off + ihl
        if proto in (6, 17) and l4 + 4 <= len(raw):
            sport, dport = struct.unpack(">HH", raw[l4:l4 + 4])
        flow = {"src": src, "dst": dst, "proto": proto,
                "sport": sport, "dport": dport}

    return {"hop_count": hop_count, "max_hops": max_hops, "instr": instr,
            "orig_etype": orig_etype, "hops": hops, "flow": flow,
            "int_bytes": SHIM_LEN + hop_count * META_LEN,
            "core_int_bytes": SHIM_LEN + hop_count * CORE_META_LEN}


def fmt_flow(f):
    if not f:
        return "?"
    return "%s:%d -> %s:%d (proto %d)" % (f["src"], f["sport"], f["dst"],
                                          f["dport"], f["proto"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--label", default="capture")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args()

    parsed = []

    def handle(pkt):
        r = parse_int(bytes(pkt))
        if r:
            parsed.append(r)

    sys.stdout.write("[collector:%s] sniffing on %s (count=%d timeout=%ds)\n"
                     % (args.label, args.iface, args.count, args.timeout))
    sys.stdout.flush()
    sniff(iface=args.iface, prn=handle, count=args.count,
          timeout=args.timeout, store=False,
          lfilter=lambda p: bytes(p)[12:14] == b"\x12\x12")

    summary = {"label": args.label, "packets": len(parsed)}
    if not parsed:
        sys.stdout.write("[collector:%s] NO INT packets captured\n" % args.label)
        if args.json_out:
            json.dump(summary, open(args.json_out, "w"), indent=2)
        return

    first = parsed[0]
    sys.stdout.write("\n=== INT trace (%s)  flow=%s ===\n"
                     % (args.label, fmt_flow(first["flow"])))
    sys.stdout.write("hops=%d  INT overhead=%d B (core %d B)  "
                     "[shim %d + %d B/hop x %d]\n"
                     % (first["hop_count"], first["int_bytes"],
                        first["core_int_bytes"], SHIM_LEN, META_LEN,
                        first["hop_count"]))
    sys.stdout.write("%-4s %-8s %-7s %-7s %-11s %-14s\n"
                     % ("idx", "swid", "in", "out", "qdepth", "hop_lat(us)"))
    for i, h in enumerate(first["hops"]):
        sys.stdout.write("%-4d %-8d %-7d %-7d %-11d %-14d\n"
                         % (i, h["switch_id"], h["ingress_port"],
                            h["egress_port"], h["queue_depth"], h["hop_latency"]))

    nhops = first["hop_count"]
    path = [h["switch_id"] for h in first["hops"]]
    same = [p for p in parsed if len(p["hops"]) == nhops]

    per_hop = []
    for i in range(nhops):
        qds = [p["hops"][i]["queue_depth"] for p in same]
        lats = [p["hops"][i]["hop_latency"] for p in same]
        per_hop.append({"switch_id": path[i],
                        "avg_queue_depth": sum(qds) / len(qds),
                        "max_queue_depth": max(qds),
                        "avg_hop_latency_us": sum(lats) / len(lats),
                        "max_hop_latency_us": max(lats)})

    # inter-hop link latency: clocks are per-switch (unsynced) so the
    # absolute value carries a constant offset -- only before/after deltas
    # are meaningful (see REPORT.md D-2 / F).
    links = []
    for i in range(nhops - 1):
        dvals = []
        for p in same:
            up, dn = p["hops"][i], p["hops"][i + 1]
            dvals.append(dn["ingress_ts"] - (up["ingress_ts"] + up["hop_latency"]))
        links.append({"from_swid": path[i], "to_swid": path[i + 1],
                      "avg_link_latency_us": sum(dvals) / len(dvals)})

    sys.stdout.write("\nper-hop averages (n=%d packets):\n" % len(same))
    for h in per_hop:
        sys.stdout.write("  swid %-5d avg_qdepth=%.1f max_qdepth=%d "
                         "avg_hoplat=%.1fus max_hoplat=%dus\n"
                         % (h["switch_id"], h["avg_queue_depth"],
                            h["max_queue_depth"], h["avg_hop_latency_us"],
                            h["max_hop_latency_us"]))
    sys.stdout.write("inter-hop link latency (raw, unsynced clocks):\n")
    for l in links:
        sys.stdout.write("  %d -> %d : %.1f us\n"
                         % (l["from_swid"], l["to_swid"], l["avg_link_latency_us"]))

    summary.update({"hop_count": nhops, "path_swids": path,
                    "int_bytes_per_pkt": first["int_bytes"],
                    "core_int_bytes_per_pkt": first["core_int_bytes"],
                    "shim_bytes": SHIM_LEN, "perhop_bytes": META_LEN,
                    "core_perhop_bytes": CORE_META_LEN,
                    "per_hop": per_hop, "links": links})
    if args.json_out:
        json.dump(summary, open(args.json_out, "w"), indent=2)
    sys.stdout.flush()


if __name__ == "__main__":
    main()
