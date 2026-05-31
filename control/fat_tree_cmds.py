#!/usr/bin/env python3
"""Per-switch simple_switch_CLI command lists for the k-ary fat-tree (M3a).

Routing (mirrors topo/fat_tree.py.reconstruct_path so the collector's replay is
bit-exact):
  edge e_{p}_{e} : /32 local hosts -> down;  0/0 -> ecmp_group(k/2) up to aggs
  agg  a_{p}_{a} : /24 per local-pod edge -> down; 0/0 -> ecmp_group(k/2) up to cores
  core c_{a}_{c} : /16 per pod -> down to that pod's agg a
tb_ecmp_nhop maps ECMP index i -> uplink port i+1 (uplink i goes to agg/core i).
tb_port_idx (compact per-switch local_idx) appended via control.port_index.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import port_index


def gen_for_switch(topo, sw):
    h = topo.h
    cmds = ["table_set_default tb_swid set_swid %d" % topo.swid[sw]]
    role = topo.role[sw]

    if role == "edge":
        p = topo.pod_of[sw]
        # mark INT source on host-facing ports
        for port, (ntype, _) in sorted(topo.ports[sw].items()):
            if ntype == "host":
                cmds.append("table_add tb_int_source set_int_source %d =>" % port)
        # /32 local hosts -> down
        for port, (ntype, nb) in sorted(topo.ports[sw].items()):
            if ntype == "host":
                cmds.append("table_add tb_ipv4_lpm set_nhop %s/32 => %d"
                            % (topo.host_ip(nb), port))
        # default -> ECMP up to the h aggs
        cmds.append("table_set_default tb_ipv4_lpm ecmp_group %d" % h)
        for i in range(h):
            cmds.append("table_add tb_ecmp_nhop set_nhop %d => %d" % (i, i + 1))

    elif role == "agg":
        p = topo.pod_of[sw]
        # /24 per edge in this pod -> down
        for port, (ntype, nb) in sorted(topo.ports[sw].items()):
            if ntype == "edge":
                e = topo.pos_of[nb]
                cmds.append("table_add tb_ipv4_lpm set_nhop 10.%d.%d.0/24 => %d"
                            % (p, e, port))
        # default -> ECMP up to the h cores
        cmds.append("table_set_default tb_ipv4_lpm ecmp_group %d" % h)
        for i in range(h):
            cmds.append("table_add tb_ecmp_nhop set_nhop %d => %d" % (i, i + 1))

    else:  # core
        # /16 per pod -> down (port p+1 -> agg in pod p)
        for port, (ntype, nb) in sorted(topo.ports[sw].items()):
            if ntype == "agg":
                pod = topo.pod_of[nb]
                cmds.append("table_add tb_ipv4_lpm set_nhop 10.%d.0.0/16 => %d"
                            % (pod, port))

    cmds.extend(port_index.tb_port_idx_cmds(topo, sw))
    return cmds


def write_files(topo, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    paths = {}
    for sw in topo.all_switches:
        p = os.path.join(out_dir, "%s-commands.txt" % sw)
        open(p, "w").write("\n".join(gen_for_switch(topo, sw)) + "\n")
        paths[sw] = p
    return paths


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "topo"))
    from fat_tree import FatTree
    t = FatTree(k=4)
    for sw in ["e0_0", "a0_0", "c0_0"]:
        print("=== %s (swid %d, %s) ===" % (sw, t.swid[sw], t.role[sw]))
        print("\n".join(gen_for_switch(t, sw)))
