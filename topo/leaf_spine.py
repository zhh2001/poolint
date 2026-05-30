#!/usr/bin/env python3
"""Parametrizable leaf-spine topology *description* for PoolINT.

This module only builds a pure-data description (switches, hosts, links,
port maps, addressing, switch ids).  net_runner.py turns it into a live
Mininet network and control/gen_commands.py turns it into per-switch
bmv2 CLI command lists.  Keeping it data-only avoids hard-coding ports or
roles anywhere, so the same code scales to other leaf/spine counts.

Defaults: 2 spines, 4 leaves, 2 hosts/leaf, full leaf-spine mesh (ECMP),
plus one collector host attached to the last leaf.

Port numbering (deterministic, so table entries line up with bmv2 ports):
  leaf  li : ports 1..S   -> spine sj (port == j)
             ports S+1..  -> local hosts, then the collector (last leaf)
  spine sj : ports 1..L   -> leaf li (port == i)
"""


def _mac(leaf, host):
    return "00:00:00:00:%02x:%02x" % (leaf, host)


class LeafSpine(object):
    def __init__(self, spines=2, leaves=4, hosts_per_leaf=2,
                 bw=10, delay="1ms", collector_leaf=None):
        self.S = spines
        self.L = leaves
        self.H = hosts_per_leaf
        self.bw = bw
        self.delay = delay
        self.collector_leaf = collector_leaf or leaves

        self.spines = ["s%d" % j for j in range(1, self.S + 1)]
        self.leaves = ["l%d" % i for i in range(1, self.L + 1)]

        self.swid = {}
        for i, sw in enumerate(self.leaves, start=1):
            self.swid[sw] = i                # leaves: 1..L
        for j, sw in enumerate(self.spines, start=1):
            self.swid[sw] = 100 + j          # spines: 101..

        self.role = {sw: "leaf" for sw in self.leaves}
        self.role.update({sw: "spine" for sw in self.spines})

        # ports[sw][port] = ("spine"/"leaf"/"host", neighbor_name)
        self.ports = {sw: {} for sw in self.leaves + self.spines}
        # hosts[name] = dict(ip, mac, leaf, leaf_port[, collector])
        self.hosts = {}
        # links = list of dicts describing each link for Mininet
        self.links = []

        self._build()

    def _add_link(self, a, ap, b, bp, host_link=False):
        self.links.append({
            "a": a, "ap": ap, "b": b, "bp": bp,
            "host_link": host_link,
            "bw": self.bw, "delay": self.delay,
        })

    def _build(self):
        # leaf <-> spine full mesh
        for li, leaf in enumerate(self.leaves, start=1):
            for sj, spine in enumerate(self.spines, start=1):
                leaf_port = sj           # leaf uplink port == spine index
                spine_port = li          # spine downlink port == leaf index
                self.ports[leaf][leaf_port] = ("spine", spine)
                self.ports[spine][spine_port] = ("leaf", leaf)
                self._add_link(leaf, leaf_port, spine, spine_port)

        # hosts on each leaf; host ports start after the uplinks
        for li, leaf in enumerate(self.leaves, start=1):
            next_port = self.S + 1
            for hi in range(1, self.H + 1):
                name = "h%d_%d" % (li, hi)
                self.hosts[name] = {
                    "ip": "10.0.%d.%d/16" % (li, hi), "mac": _mac(li, hi),
                    "leaf": leaf, "leaf_port": next_port,
                }
                self.ports[leaf][next_port] = ("host", name)
                self._add_link(leaf, next_port, name, 0, host_link=True)
                next_port += 1

            if li == self.collector_leaf:
                name = "hcol"
                self.hosts[name] = {
                    "ip": "10.0.%d.254/16" % li, "mac": _mac(li, 0xfe),
                    "leaf": leaf, "leaf_port": next_port, "collector": True,
                }
                self.ports[leaf][next_port] = ("host", name)
                self._add_link(leaf, next_port, name, 0, host_link=True)
                next_port += 1

    # ---- helpers used by the runner / command generator ----------------
    def host_ip(self, name):
        return self.hosts[name]["ip"].split("/")[0]

    def ip2host(self):
        return {self.host_ip(n): n for n in self.hosts}

    def reconstruct_path(self, src_ip, dst_ip, proto, sport, dport,
                         crc_variant=None):
        """Replay routing + crc16 ECMP to get the egress port_uid sequence a
        packet of this 5-tuple traverses.  Used by the PoolINT collector to
        build matrix A.  Returns a list of port_uids or None."""
        import poolint_hash as _H
        i2h = self.ip2host()
        sh, dh = i2h.get(src_ip), i2h.get(dst_ip)
        if sh is None or dh is None:
            return None
        sl, dl = self.hosts[sh]["leaf"], self.hosts[dh]["leaf"]
        if sl == dl:                       # same leaf: 1 hop to dst host
            return [_H.port_uid(self.swid[dl], self.hosts[dh]["leaf_port"])]
        sel = _H.ecmp_select(src_ip, dst_ip, proto, sport, dport, self.S,
                             crc_variant)
        ups = self.uplink_ports(sl)
        up = ups[sel % len(ups)]
        spine = self.ports[sl][up][1]
        downp = next((p for p, (t, nb) in self.ports[spine].items()
                      if t == "leaf" and nb == dl), None)
        if downp is None:
            return None
        return [_H.port_uid(self.swid[sl], up),
                _H.port_uid(self.swid[spine], downp),
                _H.port_uid(self.swid[dl], self.hosts[dh]["leaf_port"])]

    def spine_swid_on_path(self, src_ip, dst_ip, proto, sport, dport,
                           crc_variant=None):
        p = self.reconstruct_path(src_ip, dst_ip, proto, sport, dport,
                                  crc_variant)
        return (p[1] >> 8) if (p and len(p) >= 2) else None

    def collector_name(self):
        for n, h in self.hosts.items():
            if h.get("collector"):
                return n
        return None

    def uplink_ports(self, leaf):
        return [p for p, (t, _) in sorted(self.ports[leaf].items())
                if t == "spine"]

    def summary(self):
        lines = ["leaf-spine: S=%d L=%d H=%d  bw=%sMbit delay=%s"
                 % (self.S, self.L, self.H, self.bw, self.delay)]
        lines.append("switch ids: " + ", ".join(
            "%s=%d" % (sw, self.swid[sw])
            for sw in self.leaves + self.spines))
        for h, hi in sorted(self.hosts.items()):
            lines.append("  host %-6s ip=%-14s mac=%s on %s(port %d)%s"
                         % (h, hi["ip"], hi["mac"], hi["leaf"],
                            hi["leaf_port"],
                            "  [COLLECTOR]" if hi.get("collector") else ""))
        return "\n".join(lines)


if __name__ == "__main__":
    import sys
    sys.stdout.write(LeafSpine().summary() + "\n")
