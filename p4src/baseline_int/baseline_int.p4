/* -*- P4_16 -*- */
/*
 * PoolINT project - Milestone 1
 * baseline_int.p4 : baseline full-stack INT-MD data plane (v1model/bmv2).
 *
 * One program runs on every switch (leaf and spine); role is decided
 * entirely by the table entries installed by the control plane, so the
 * topology can grow without touching the data plane (modularity req.).
 *
 *   - L3 forwarding by destination IPv4 (static ARP on hosts, no MAC
 *     rewrite, no TTL decrement -> IPv4 checksum stays valid).
 *   - ECMP across spine uplinks at the leaves (hash over the 5-tuple).
 *   - INT-MD: source leaf pushes a shim; every switch on the path
 *     appends one int_metadata record in egress (where queue stats are
 *     known); the destination host (= collector) parses the stack.
 *
 * See headers.p4 for the exact wire layout and field widths.
 */
#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "parser.p4"

/* ===================== INGRESS ===================== */
control BaselineIngress(inout headers hdr,
                        inout metadata meta,
                        inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_swid(bit<16> id) {
        meta.switch_id = id;
    }

    action set_int_source() {
        meta.int_source = 1;
    }

    action set_nhop(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    /* Pick an ECMP member by hashing the 5-tuple into [0, group_size). */
    action ecmp_group(bit<8> group_size) {
        meta.ecmp_group_size = group_size;
        hash(meta.ecmp_select,
             HashAlgorithm.crc16,
             (bit<16>)0,
             { hdr.ipv4.srcAddr,
               hdr.ipv4.dstAddr,
               hdr.ipv4.protocol,
               meta.ecmp_l4_src,
               meta.ecmp_l4_dst },
             (bit<16>)group_size);
    }

    /* Per-switch id (keyless: control plane sets the default action). */
    table tb_swid {
        actions = { set_swid; NoAction; }
        default_action = NoAction();
        size = 1;
    }

    /* Mark INT source on host-facing ingress ports of an edge leaf. */
    table tb_int_source {
        key = { standard_metadata.ingress_port : exact; }
        actions = { set_int_source; NoAction; }
        default_action = NoAction();
        size = 16;
    }

    /* Destination-based L3 forwarding. */
    table tb_ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { set_nhop; ecmp_group; drop; }
        default_action = drop();
        size = 1024;
    }

    /* Resolve an ECMP member id to a concrete spine uplink port. */
    table tb_ecmp_nhop {
        key = { meta.ecmp_select : exact; }
        actions = { set_nhop; drop; }
        default_action = drop();
        size = 64;
    }

    apply {
        tb_swid.apply();

        /* Snapshot L4 ports for the ECMP hash regardless of L4 type. */
        if (hdr.udp.isValid()) {
            meta.ecmp_l4_src = hdr.udp.srcPort;
            meta.ecmp_l4_dst = hdr.udp.dstPort;
        } else if (hdr.tcp.isValid()) {
            meta.ecmp_l4_src = hdr.tcp.srcPort;
            meta.ecmp_l4_dst = hdr.tcp.dstPort;
        }

        tb_int_source.apply();

        if (hdr.ipv4.isValid()) {
            switch (tb_ipv4_lpm.apply().action_run) {
                ecmp_group: { tb_ecmp_nhop.apply(); }
            }
        }

        /* Decide whether this packet carries INT downstream. */
        if (hdr.int_shim.isValid() || meta.int_source == 1) {
            meta.do_int = 1;
        }
    }
}

/* ===================== EGRESS ===================== */
control BaselineEgress(inout headers hdr,
                       inout metadata meta,
                       inout standard_metadata_t standard_metadata) {

    /* Append this switch's metadata record to the front of the stack. */
    action int_append_hop() {
        hdr.int_metadata.push_front(1);
        hdr.int_metadata[0].setValid();
        hdr.int_metadata[0].switch_id    = meta.switch_id;
        hdr.int_metadata[0].ingress_port = (bit<16>)standard_metadata.ingress_port;
        hdr.int_metadata[0].egress_port  = (bit<16>)standard_metadata.egress_port;
        hdr.int_metadata[0].queue_depth  = (bit<16>)standard_metadata.deq_qdepth;
        hdr.int_metadata[0].hop_latency  = standard_metadata.deq_timedelta;
        hdr.int_metadata[0].ingress_ts   = standard_metadata.ingress_global_timestamp;
        hdr.int_shim.hopCount = hdr.int_shim.hopCount + 1;
    }

    apply {
        if (meta.do_int == 1) {
            /* Source leaf: create the shim before the first append. */
            if (!hdr.int_shim.isValid()) {
                hdr.int_shim.setValid();
                hdr.int_shim.ver           = 1;
                hdr.int_shim.hopCount      = 0;
                hdr.int_shim.maxHops       = INT_MAX_HOPS;
                hdr.int_shim.instrBitmap   = INT_INSTR_FULL;
                hdr.int_shim.origEtherType = hdr.ethernet.etherType;
                hdr.int_shim.rsvd          = 0;
                hdr.ethernet.etherType     = TYPE_INT;
            }
            int_append_hop();
        }
    }
}

/* ===================== SWITCH ===================== */
V1Switch(
    BaselineParser(),
    BaselineVerifyChecksum(),
    BaselineIngress(),
    BaselineEgress(),
    BaselineComputeChecksum(),
    BaselineDeparser()
) main;
