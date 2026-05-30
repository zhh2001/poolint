#!/usr/bin/env python3
"""k-ary fat-tree topology *description* for PoolINT M3a (default k=4).

Pure-data description (switches, hosts, links, port maps, addressing, swids)
duck-typed to the same interface as leaf_spine.py / line_topo.py so the M3a
runner / collector / command generator reuse the M2 machinery unchanged.

k=4 fat-tree:
  - k pods; each pod has k/2 edge + k/2 agg switches
  - (k/2)^2 core switches
  - each edge has k/2 hosts
  totals (k=4): 8 edge + 8 agg + 4 core = 20 switches, 16 hosts.

Addressing: host = 10.<pod>.<edge>.<host+1>;  /16 = pod, /24 = pod.edge.

Per-switch port numbering (deterministic; bmv2 -i and table entries line up):
  edge_{p}_{e} : ports 1..k/2   -> uplink to agg_{p}_{0..k/2-1}  (port a+1 -> agg a)
                 ports k/2+1..k -> hosts (port k/2+h+1 -> host h)
  agg_{p}_{a}  : ports 1..k/2   -> uplink to core group a (port c+1 -> core_{a}_{c})
                 ports k/2+1..k -> downlink to edge_{p}_{e} (port k/2+e+1)
  core_{a}_{c} : ports 1..k     -> downlink to pod p (port p+1 -> agg_{p}_{a})

swids (<=255, needed for the in-packet dbg_path byte-packing):
  edges 1..(k*k/2), aggs 11.., cores 41..   (gaps for readability; all <=255)

Routing / ECMP (must be replayable bit-exact by the collector):
  edge: /32 local hosts -> down;  default -> ECMP up over the k/2 aggs
  agg : /24 per local-pod edge -> down;  default -> ECMP up over the k/2 cores
  core: /16 per pod -> down to that pod's agg a
  ECMP index = crc16(srcip,dstip,proto,l4src,l4dst, switch_id) mod (k/2);
  index i -> uplink port i+1.  Including switch_id makes the edge- and agg-
  level decisions independent (k/2 * k/2 distinct up-paths between pods) and
  lets gate #0b's variant sweep disambiguate CRC-16 variants (M2 left ARC/USB
  degenerate under a single 2-way hop).
"""


class FatTree(object):
    def __init__(self, k=4, bw=10, delay="1ms"):
        assert k % 2 == 0, "k must be even"
        self.k = k
        self.h = k // 2                      # k/2
        self.bw = bw
        self.delay = delay
        self.S = self.h                      # ECMP group size per up-hop

        self.edges, self.aggs, self.cores = [], [], []
        self.swid = {}
        self.role = {}
        self.pod_of = {}                     # switch -> pod (edges/aggs)
        self.pos_of = {}                     # switch -> position index within its tier
        self._name_switches()
        self.all_switches = self.edges + self.aggs + self.cores

        self.ports = {sw: {} for sw in self.all_switches}
        self.hosts = {}
        self.links = []
        self._build()

    # ---- naming / ids ---------------------------------------------------
    def _name_switches(self):
        k, h = self.k, self.h
        sid = 1
        for p in range(k):
            for e in range(h):
                nm = "e%d_%d" % (p, e)
                self.edges.append(nm); self.swid[nm] = sid; sid += 1
                self.role[nm] = "edge"; self.pod_of[nm] = p; self.pos_of[nm] = e
        sid = 11
        for p in range(k):
            for a in range(h):
                nm = "a%d_%d" % (p, a)
                self.aggs.append(nm); self.swid[nm] = sid; sid += 1
                self.role[nm] = "agg"; self.pod_of[nm] = p; self.pos_of[nm] = a
        sid = 41
        for a in range(h):
            for c in range(h):
                nm = "c%d_%d" % (a, c)
                self.cores.append(nm); self.swid[nm] = sid; sid += 1
                self.role[nm] = "core"; self.pos_of[nm] = (a, c)

    def edge(self, p, e):
        return "e%d_%d" % (p, e)

    def agg(self, p, a):
        return "a%d_%d" % (p, a)

    def core(self, a, c):
        return "c%d_%d" % (a, c)

    def _add_link(self, a, ap, b, bp, host_link=False):
        self.links.append({"a": a, "ap": ap, "b": b, "bp": bp,
                           "host_link": host_link, "bw": self.bw,
                           "delay": self.delay})

    # ---- build ----------------------------------------------------------
    def _build(self):
        k, h = self.k, self.h
        col_done = False
        for p in range(k):
            for e in range(h):
                ed = self.edge(p, e)
                # uplinks: port a+1 -> agg_{p}_{a}
                for a in range(h):
                    ag = self.agg(p, a)
                    eport = a + 1
                    aport = h + e + 1          # agg downlink port to edge e
                    self.ports[ed][eport] = ("agg", ag)
                    self.ports[ag][aport] = ("edge", ed)
                    self._add_link(ed, eport, ag, aport)
                # hosts: port h+hh+1 -> host
                for hh in range(h):
                    hp = h + hh + 1
                    nm = "h%d_%d_%d" % (p, e, hh)
                    ip = "10.%d.%d.%d/16" % (p, e, hh + 1)
                    mac = "00:00:00:%02x:%02x:%02x" % (p, e, hh + 1)
                    self.hosts[nm] = {"ip": ip, "mac": mac, "leaf": ed,
                                      "leaf_port": hp, "pod": p, "edge": e}
                    self.ports[ed][hp] = ("host", nm)
                    self._add_link(ed, hp, nm, 0, host_link=True)
        # agg <-> core
        for p in range(k):
            for a in range(h):
                ag = self.agg(p, a)
                for c in range(h):
                    cr = self.core(a, c)
                    aport = c + 1               # agg uplink port -> core c
                    cport = p + 1               # core downlink port -> pod p
                    self.ports[ag][aport] = ("core", cr)
                    self.ports[cr][cport] = ("agg", ag)
                    self._add_link(ag, aport, cr, cport)
        # collector: a dedicated host on the LAST edge of the LAST pod, on the
        # next free host port (so it doesn't displace a regular host)
        led = self.edge(k - 1, h - 1)
        hp = max(self.ports[led]) + 1
        nm = "hcol"
        ip = "10.%d.%d.254/16" % (k - 1, h - 1)
        self.hosts[nm] = {"ip": ip, "mac": "00:00:00:ff:ff:fe", "leaf": led,
                          "leaf_port": hp, "pod": k - 1, "edge": h - 1,
                          "collector": True}
        self.ports[led][hp] = ("host", nm)
        self._add_link(led, hp, nm, 0, host_link=True)

    # ---- helpers (shared interface) ------------------------------------
    def host_ip(self, name):
        return self.hosts[name]["ip"].split("/")[0]

    def ip2host(self):
        return {self.host_ip(n): n for n in self.hosts}

    def collector_name(self):
        for n, hh in self.hosts.items():
            if hh.get("collector"):
                return n
        return None

    def uplink_ports(self, sw):
        """Ports going 'up' (edge->agg or agg->core), ordered by index."""
        up = "agg" if self.role[sw] == "edge" else "core"
        return [pt for pt, (t, _) in sorted(self.ports[sw].items()) if t == up]

    def n_monitored_ports(self):
        """Total directed switch egress ports (= n, the monitored-unit count)."""
        return sum(len(self.ports[sw]) for sw in self.all_switches)

    # ---- ECMP replay (bit-exact mirror of poolint.p4 ecmp_group) -------
    def reconstruct_path(self, src_ip, dst_ip, proto, sport, dport,
                         crc_variant=None):
        import poolint_hash as _H
        i2h = self.ip2host()
        sh, dh = i2h.get(src_ip), i2h.get(dst_ip)
        if sh is None or dh is None:
            return None
        sp, se = self.hosts[sh]["pod"], self.hosts[sh]["edge"]
        dp, de = self.hosts[dh]["pod"], self.hosts[dh]["edge"]
        path = []

        def ecmp(sw, gsize):
            return _H.ecmp_select(src_ip, dst_ip, proto, sport, dport, gsize,
                                  crc_variant, swid=self.swid[sw])

        if sp == dp and se == de:
            ed = self.edge(dp, de)
            return [_H.port_uid(self.swid[ed], self.hosts[dh]["leaf_port"])]

        # 1) source edge -> up to an agg (ECMP)
        ed = self.edge(sp, se)
        a = ecmp(ed, self.h)
        path.append(_H.port_uid(self.swid[ed], a + 1))        # edge uplink port a+1
        ag = self.agg(sp, a)

        if sp == dp:
            # same pod: agg -> down to dst edge
            dport_p = self.h + de + 1
            path.append(_H.port_uid(self.swid[ag], dport_p))
        else:
            # 2) agg -> up to a core in group a (ECMP)
            c = ecmp(ag, self.h)
            path.append(_H.port_uid(self.swid[ag], c + 1))    # agg uplink port c+1
            cr = self.core(a, c)
            # 3) core -> down to pod dp (port dp+1) -> agg_{dp}_{a}
            path.append(_H.port_uid(self.swid[cr], dp + 1))
            ag2 = self.agg(dp, a)
            # 4) agg_{dp}_{a} -> down to dst edge
            dport_p = self.h + de + 1
            path.append(_H.port_uid(self.swid[ag2], dport_p))
        # final: dst edge -> down to host
        ded = self.edge(dp, de)
        path.append(_H.port_uid(self.swid[ded], self.hosts[dh]["leaf_port"]))
        return path

    def spine_swid_on_path(self, src_ip, dst_ip, proto, sport, dport,
                           crc_variant=None):
        p = self.reconstruct_path(src_ip, dst_ip, proto, sport, dport, crc_variant)
        return (p[1] >> 8) if (p and len(p) >= 2) else None

    def summary(self):
        lines = ["fat-tree k=%d: %d edge + %d agg + %d core = %d switches, "
                 "%d hosts; n(monitored egress ports)=%d"
                 % (self.k, len(self.edges), len(self.aggs), len(self.cores),
                    len(self.all_switches), len([h for h in self.hosts]),
                    self.n_monitored_ports())]
        return "\n".join(lines)


if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "control"))
    t = FatTree(k=4)
    print(t.summary())
