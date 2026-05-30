#!/usr/bin/env python3
"""Linear chain topology: c1 - c2 - ... - cN, host hA on c1, collector hB on
cN.  A packet hA->hB traverses all N switches, so this gives the >3-hop path
PoolINT acceptance #3 needs (default N=5 => 5 hops) without ECMP.

Duck-typed to the same interface the runner / collector use: .all_switches,
.swid, .role, .ports, .hosts, .links, collector_name(), reconstruct_path().
Path reconstruction is deterministic (no ECMP) -- the full chain.

Port convention per switch ci:
  port 1 -> c(i-1)   (toward c1)         [absent on c1]
  port 2 -> c(i+1)   (toward cN)         [absent on cN]
  port 3 -> local host                   [c1: hA, cN: hB]
"""


class LineTopo(object):
    def __init__(self, n=5, bw=10, delay="1ms"):
        self.N = n
        self.bw = bw
        self.delay = delay
        self.switches = ["c%d" % i for i in range(1, n + 1)]
        self.all_switches = list(self.switches)
        self.swid = {sw: i for i, sw in enumerate(self.switches, start=1)}
        self.role = {sw: "line" for sw in self.switches}
        self.S = 0   # no spines / no ECMP

        self.ports = {sw: {} for sw in self.switches}
        self.hosts = {}
        self.links = []
        self._build()

    def _add_link(self, a, ap, b, bp, host_link=False):
        self.links.append({"a": a, "ap": ap, "b": b, "bp": bp,
                           "host_link": host_link, "bw": self.bw,
                           "delay": self.delay})

    def _build(self):
        for i in range(1, self.N):
            ci, cj = "c%d" % i, "c%d" % (i + 1)
            self.ports[ci][2] = ("switch", cj)     # ci -> c(i+1)
            self.ports[cj][1] = ("switch", ci)     # c(i+1) -> ci
            self._add_link(ci, 2, cj, 1)
        # hosts: hA on c1 port3, hB(collector) on cN port3
        self.hosts["hA"] = {"ip": "10.0.1.1/16", "mac": "00:00:00:00:0a:01",
                            "leaf": "c1", "leaf_port": 3}
        self.ports["c1"][3] = ("host", "hA")
        self._add_link("c1", 3, "hA", 0, host_link=True)
        self.hosts["hcol"] = {"ip": "10.0.%d.254/16" % self.N,
                              "mac": "00:00:00:00:0a:fe",
                              "leaf": "c%d" % self.N, "leaf_port": 3,
                              "collector": True}
        self.ports["c%d" % self.N][3] = ("host", "hcol")
        self._add_link("c%d" % self.N, 3, "hcol", 0, host_link=True)

    def host_ip(self, name):
        return self.hosts[name]["ip"].split("/")[0]

    def ip2host(self):
        return {self.host_ip(n): n for n in self.hosts}

    def collector_name(self):
        for n, h in self.hosts.items():
            if h.get("collector"):
                return n
        return None

    def reconstruct_path(self, src_ip, dst_ip, proto, sport, dport,
                         crc_variant=None):
        import poolint_hash as _H
        i2h = self.ip2host()
        sh, dh = i2h.get(src_ip), i2h.get(dst_ip)
        if sh is None or dh is None:
            return None
        si = self.swid[self.hosts[sh]["leaf"]]
        di = self.swid[self.hosts[dh]["leaf"]]
        puids = []
        if si == di:
            return [_H.port_uid(si, self.hosts[dh]["leaf_port"])]
        step = 1 if di > si else -1
        i = si
        while i != di:
            sw = "c%d" % i
            eg = 2 if step > 0 else 1          # toward higher / lower index
            puids.append(_H.port_uid(i, eg))
            i += step
        # final switch (cD): egress to the local host
        puids.append(_H.port_uid(di, self.hosts[dh]["leaf_port"]))
        return puids

    def spine_swid_on_path(self, *a, **k):
        return None   # no spine in a line

    def summary(self):
        lines = ["line: N=%d  bw=%sMbit delay=%s" % (self.N, self.bw, self.delay)]
        lines.append("swids: " + ", ".join("%s=%d" % (s, self.swid[s])
                                            for s in self.switches))
        for h, hi in sorted(self.hosts.items()):
            lines.append("  host %-5s ip=%-14s on %s(port %d)%s"
                         % (h, hi["ip"], hi["leaf"], hi["leaf_port"],
                            "  [COLLECTOR]" if hi.get("collector") else ""))
        return "\n".join(lines)


def gen_commands_line(topo):
    """Per-switch simple_switch_CLI command lists for the line topology
    (dst /32 routing, no ECMP)."""
    out = {}
    for sw in topo.switches:
        i = topo.swid[sw]
        cmds = ["table_set_default tb_swid set_swid %d" % i]
        for port, (ntype, _) in sorted(topo.ports[sw].items()):
            if ntype == "host":
                cmds.append("table_add tb_int_source set_int_source %d =>" % port)
        for hname, hinfo in sorted(topo.hosts.items()):
            di = topo.swid[hinfo["leaf"]]
            ip = topo.host_ip(hname)
            if di == i:
                port = hinfo["leaf_port"]
            elif di > i:
                port = 2
            else:
                port = 1
            cmds.append("table_add tb_ipv4_lpm set_nhop %s/32 => %d" % (ip, port))
        # PoolINT tb_port_idx: compact per-switch local_idx
        import port_index
        cmds.extend(port_index.tb_port_idx_cmds(topo, sw))
        out[sw] = cmds
    return out


def write_files_line(topo, out_dir):
    import os
    os.makedirs(out_dir, exist_ok=True)
    paths = {}
    for sw, cmds in gen_commands_line(topo).items():
        p = os.path.join(out_dir, "%s-commands.txt" % sw)
        open(p, "w").write("\n".join(cmds) + "\n")
        paths[sw] = p
    return paths


if __name__ == "__main__":
    import sys
    t = LineTopo()
    sys.stdout.write(t.summary() + "\n")
    sys.path.insert(0, __file__.rsplit("/", 2)[0] + "/control")
    sys.stdout.write("path hA->hcol: %s\n" %
                     [hex(x) for x in t.reconstruct_path(
                         "10.0.1.1", t.host_ip("hcol"), 17, 1, 2)])
