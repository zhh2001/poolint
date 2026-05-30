#!/usr/bin/env python3
"""Generate per-switch bmv2 (simple_switch_CLI) command lists from a
LeafSpine topology description.

Everything is derived from the topology's port maps and addressing, so
there are no hard-coded ports or roles -- changing spine/leaf/host counts
in leaf_spine.py regenerates correct tables automatically.

Tables (see p4src/baseline_int/baseline_int.p4):
  tb_swid       keyless, default set_swid(<id>)
  tb_int_source per host-facing ingress port -> set_int_source
  tb_ipv4_lpm   /32 local hosts -> set_nhop(port); 0/0 -> ecmp_group(S)  (leaf)
                /24 per leaf    -> set_nhop(port)                        (spine)
  tb_ecmp_nhop  ecmp member k   -> set_nhop(uplink port)                 (leaf)
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "topo"))
from leaf_spine import LeafSpine


def gen_for_switch(topo, sw):
    cmds = ["table_set_default tb_swid set_swid %d" % topo.swid[sw]]

    if topo.role[sw] == "leaf":
        # mark INT source on every host-facing ingress port
        for port, (ntype, _) in sorted(topo.ports[sw].items()):
            if ntype == "host":
                cmds.append("table_add tb_int_source set_int_source %d =>" % port)

        # local hosts -> direct /32 routes
        for hname, hinfo in sorted(topo.hosts.items()):
            if hinfo["leaf"] == sw:
                cmds.append("table_add tb_ipv4_lpm set_nhop %s/32 => %d"
                            % (topo.host_ip(hname), hinfo["leaf_port"]))

        # everything else -> ECMP across the spine uplinks
        cmds.append("table_add tb_ipv4_lpm ecmp_group 0.0.0.0/0 => %d" % topo.S)
        for k, uplink in enumerate(topo.uplink_ports(sw)):
            cmds.append("table_add tb_ecmp_nhop set_nhop %d => %d" % (k, uplink))

    else:  # spine
        for port, (ntype, leaf) in sorted(topo.ports[sw].items()):
            if ntype == "leaf":
                li = topo.swid[leaf]   # leaf id == its /24 third octet
                cmds.append("table_add tb_ipv4_lpm set_nhop 10.0.%d.0/24 => %d"
                            % (li, port))

    return cmds


def generate(topo, poolint=False):
    cmds = {sw: gen_for_switch(topo, sw)
            for sw in topo.leaves + topo.spines}
    if poolint:
        # PoolINT data plane: install tb_port_idx (compact per-switch local_idx)
        import port_index
        for sw in cmds:
            cmds[sw].extend(port_index.tb_port_idx_cmds(topo, sw))
    return cmds


def write_files(topo, out_dir, poolint=False):
    os.makedirs(out_dir, exist_ok=True)
    paths = {}
    for sw, cmds in generate(topo, poolint=poolint).items():
        p = os.path.join(out_dir, "%s-commands.txt" % sw)
        with open(p, "w") as f:
            f.write("\n".join(cmds) + "\n")
        paths[sw] = p
    return paths


if __name__ == "__main__":
    topo = LeafSpine()
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/poolint-cmds"
    paths = write_files(topo, out)
    for sw in sorted(paths):
        sys.stdout.write("=== %s (%s) ===\n" % (sw, paths[sw]))
        with open(paths[sw]) as f:
            sys.stdout.write(f.read())
