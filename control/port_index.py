#!/usr/bin/env python3
"""Single source of truth for the compact per-switch local_idx used by the
PoolINT data plane's tb_port_idx table and its per-port registers.

local_idx(sw, egress_port) = position of egress_port in the sorted list of
that switch's port numbers.  It is unique WITHIN a switch (registers are
per-switch), in [0, NUM_PORTS_REAL=32).  The command generators install the
matching tb_port_idx entries and the injector writes r_fault at the same idx,
so all three agree by construction.
"""

NUM_PORTS_REAL = 32


def switch_ports(topo, sw):
    """Sorted egress-port numbers for switch sw (works for LeafSpine/LineTopo
    which both expose .ports[sw] = {port: (...)})."""
    return sorted(topo.ports[sw].keys())


def local_idx(topo, sw, egress_port):
    ports = switch_ports(topo, sw)
    if egress_port not in ports:
        return None
    idx = ports.index(egress_port)
    if idx >= NUM_PORTS_REAL:
        raise ValueError("switch %s has >%d ports; bump NUM_PORTS_REAL"
                         % (sw, NUM_PORTS_REAL))
    return idx


def tb_port_idx_cmds(topo, sw):
    """simple_switch_CLI lines installing tb_port_idx for switch sw."""
    swid = topo.swid[sw]
    out = []
    for port in switch_ports(topo, sw):
        out.append("table_add tb_port_idx set_local_idx %d %d => %d"
                   % (swid, port, local_idx(topo, sw, port)))
    return out
