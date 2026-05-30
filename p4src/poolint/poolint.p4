/* -*- P4_16 -*- */
/*
 * PoolINT project - Milestone 2  (compile-fix revision)
 * p4src/poolint/poolint.p4 : PoolINT pooled-measurement data plane (v1model).
 *
 * Forwarding: dst-IPv4 L3 + crc32 5-tuple ECMP at the source leaf (collector
 * replays it).  Telemetry: source leaf stamps test_id+epoch_id and creates the
 * syndrome header; every hop, per metric per round, a crc32 hash gate decides
 * membership and merges the local anomaly value (boolean OR / quant saturating
 * add) into the constant-size in-packet syndrome.
 *
 * Compile-fix: all hashing uses bmv2's crc32 extern (no P4 wide multiply); per
 * port/epoch state is indexed by a compact local_idx from tb_port_idx, never by
 * the 16-bit port_uid.  See REPORT [M2-compile-fix].
 */
#include <core.p4>
#include <v1model.p4>

#include "headers.p4"
#include "parser.p4"

/* ===================== INGRESS ===================== */
control PoolIngress(inout headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata) {

    action drop() { mark_to_drop(standard_metadata); }
    action set_swid(bit<16> id) { meta.switch_id = id; }
    action set_int_source() { meta.int_source = 1; }
    action set_nhop(egressSpec_t port) { standard_metadata.egress_spec = port; }

    /* crc16 5-tuple ECMP (byte-aligned fields -> standard CRC-16 reproducible;
     * variant fixed in control/poolint_hash.py after gate-#0a calibration). */
    action ecmp_group(bit<8> group_size) {
        meta.ecmp_group_size = group_size;
        hash(meta.ecmp_select, HashAlgorithm.crc16, (bit<16>)0,
             { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol,
               meta.ecmp_l4_src, meta.ecmp_l4_dst, meta.switch_id },
             (bit<16>)group_size);
    }

    table tb_swid {
        actions = { set_swid; NoAction; }
        default_action = NoAction();
        size = 1;
    }
    table tb_int_source {
        key = { standard_metadata.ingress_port : exact; }
        actions = { set_int_source; NoAction; }
        default_action = NoAction();
        size = 16;
    }
    table tb_ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { set_nhop; ecmp_group; drop; }
        default_action = drop();
        size = 1024;
    }
    table tb_ecmp_nhop {
        key = { meta.ecmp_select : exact; }
        actions = { set_nhop; drop; }
        default_action = drop();
        size = 64;
    }

    apply {
        tb_swid.apply();
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
        if (hdr.poolint.isValid() || meta.int_source == 1) {
            meta.pool_active = 1;
        }
    }
}

/* ===================== EGRESS ===================== */
control PoolEgress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {

    /* compact per-port / per-epoch state (indexed by local_idx) */
    register<bit<8>>(NUM_PORTS_REAL)  r_fault;
    register<bit<8>>(REG_SLOTS)       r_util_epoch;
    register<bit<32>>(REG_SLOTS)      r_util_bytes;
    register<bit<32>>(NUM_PORTS_REAL) r_testctr;

    /* (switch_id, egress_port) -> compact local_idx in [0, NUM_PORTS_REAL) */
    action set_local_idx(bit<8> idx) {
        meta.local_idx = idx;
        meta.idx_valid = 1;
    }
    table tb_port_idx {
        key = {
            meta.switch_id                  : exact;
            standard_metadata.egress_port   : exact;
        }
        actions = { set_local_idx; NoAction; }
        default_action = NoAction();
        size = NUM_PORTS_REAL;
    }

    /* crc32 membership gate: meta.hval = crc32(key) mod HASH_MOD */
    action gate(bit<8> mid, bit<8> rr) {
        meta.hk.metric_id = mid;
        meta.hk.round_r   = rr;
        hash(meta.hval, HashAlgorithm.crc32, (bit<32>)0,
             { meta.hk.test_id, meta.hk.epoch_id, meta.hk.port_uid,
               meta.hk.metric_id, meta.hk.round_r },
             (bit<32>)HASH_MOD);
    }

    /* full crc32 of the same key for the gate-#0a bit-exact check (modulus
     * 2^32 -> no reduction, so dbg_hash carries the raw 32-bit crc). */
    action gate_full(bit<8> mid, bit<8> rr) {
        meta.hk.metric_id = mid;
        meta.hk.round_r   = rr;
        hash(meta.hval_full, HashAlgorithm.crc32, (bit<64>)0,
             { meta.hk.test_id, meta.hk.epoch_id, meta.hk.port_uid,
               meta.hk.metric_id, meta.hk.round_r },
             (bit<64>)0x100000000);
    }

    action sat_add_q0(bit<8> v) { bit<16> t = (bit<16>)hdr.poolint.q0 + (bit<16>)v; hdr.poolint.q0 = (t > 255) ? 8w255 : (bit<8>)t; }
    action sat_add_q1(bit<8> v) { bit<16> t = (bit<16>)hdr.poolint.q1 + (bit<16>)v; hdr.poolint.q1 = (t > 255) ? 8w255 : (bit<8>)t; }
    action sat_add_q2(bit<8> v) { bit<16> t = (bit<16>)hdr.poolint.q2 + (bit<16>)v; hdr.poolint.q2 = (t > 255) ? 8w255 : (bit<8>)t; }
    action sat_add_q3(bit<8> v) { bit<16> t = (bit<16>)hdr.poolint.q3 + (bit<16>)v; hdr.poolint.q3 = (t > 255) ? 8w255 : (bit<8>)t; }

    apply {
        if (meta.pool_active == 1) {

            meta.port_uid = (meta.switch_id << 8) | (bit<16>)standard_metadata.egress_port;
            tb_port_idx.apply();

            /* source leaf: create the syndrome header + stamp test_id */
            if (!hdr.poolint.isValid()) {
                bit<32> c = 0;
                if (meta.idx_valid == 1) {
                    r_testctr.read(c, (bit<32>)meta.local_idx);
                    r_testctr.write((bit<32>)meta.local_idx, c + 1);
                }
                hdr.poolint.setValid();
                hdr.poolint.test_id  = (bit<16>)c;
                hdr.poolint.epoch_id =
                    (bit<8>)((standard_metadata.ingress_global_timestamp >> EPOCH_SHIFT) & 0xff);
                hdr.poolint.flags = 0x01;
                hdr.poolint.bsynd = 0;
                hdr.poolint.q0 = 0; hdr.poolint.q1 = 0;
                hdr.poolint.q2 = 0; hdr.poolint.q3 = 0;

                hdr.poolint_dbg.setValid();
                hdr.poolint_dbg.dbg_hash = 0;
                hdr.poolint_dbg.dbg_port_uid = 0;
                hdr.poolint_dbg.dbg_path = 0;

                hdr.ethernet.etherType = TYPE_POOLINT;
            }
            meta.epoch_id = hdr.poolint.epoch_id;
            meta.eslot = meta.epoch_id & (NUM_EPOCH_SLOTS - 1);

            /* local metric values for this hop's egress port */
            bit<8> fault = 0;
            if (meta.idx_valid == 1) {
                r_fault.read(fault, (bit<32>)meta.local_idx);
            }
            meta.v_fail = (fault != 0) ? 1w1 : 1w0;
            meta.v_qhi  = (standard_metadata.deq_qdepth > TAU_Q) ? 1w1 : 1w0;
            meta.v_qdepth = (standard_metadata.deq_qdepth > 255) ? 8w255
                            : (bit<8>)standard_metadata.deq_qdepth;

            /* M_UTIL: per-(port,epoch) byte accumulator, lazy reset */
            bit<8> v_util = 0;
            if (meta.idx_valid == 1) {
                bit<32> ridx = (bit<32>)meta.local_idx * NUM_EPOCH_SLOTS + (bit<32>)meta.eslot;
                bit<8>  ue; bit<32> ub;
                r_util_epoch.read(ue, ridx);
                r_util_bytes.read(ub, ridx);
                if (ue != meta.epoch_id) {
                    ub = 0;
                    r_util_epoch.write(ridx, meta.epoch_id);
                }
                ub = ub + standard_metadata.packet_length;
                r_util_bytes.write(ridx, ub);
                bit<32> uq = ub >> UTIL_SHIFT;
                v_util = (uq > 255) ? 8w255 : (bit<8>)uq;
            }
            meta.v_util = v_util;

            /* byte-aligned crc32 key (shared across all gates this hop) */
            meta.hk.test_id  = hdr.poolint.test_id;
            meta.hk.epoch_id = meta.epoch_id;
            meta.hk.port_uid = meta.port_uid;

            /* boolean FAIL -> bsynd bits 0,1 */
            gate(MID_FAIL, 0);
            if (meta.hval < RHO_PERMIL && meta.v_fail == 1) { hdr.poolint.bsynd = hdr.poolint.bsynd | 0x01; }
            gate(MID_FAIL, 1);
            if (meta.hval < RHO_PERMIL && meta.v_fail == 1) { hdr.poolint.bsynd = hdr.poolint.bsynd | 0x02; }
            /* boolean QHI -> bsynd bits 2,3 */
            gate(MID_QHI, 0);
            if (meta.hval < RHO_PERMIL && meta.v_qhi == 1) { hdr.poolint.bsynd = hdr.poolint.bsynd | 0x04; }
            gate(MID_QHI, 1);
            if (meta.hval < RHO_PERMIL && meta.v_qhi == 1) { hdr.poolint.bsynd = hdr.poolint.bsynd | 0x08; }

            /* quant QDEPTH -> q0(r0) q1(r1) */
            gate(MID_QDEPTH, 0);
            if (meta.hval < RHO_PERMIL) { sat_add_q0(meta.v_qdepth); }
            gate(MID_QDEPTH, 1);
            if (meta.hval < RHO_PERMIL) { sat_add_q1(meta.v_qdepth); }
            /* quant UTIL -> q2(r0) q3(r1) */
            gate(MID_UTIL, 0);
            if (meta.hval < RHO_PERMIL) { sat_add_q2(meta.v_util); }
            gate(MID_UTIL, 1);
            if (meta.hval < RHO_PERMIL) { sat_add_q3(meta.v_util); }

            /* gate #0a debug: source stamps H(FAIL,0) for its own port_uid */
            if (hdr.poolint_dbg.dbg_port_uid == 0) {
                gate_full(MID_FAIL, 0);
                hdr.poolint_dbg.dbg_hash = meta.hval_full;
                hdr.poolint_dbg.dbg_port_uid = meta.port_uid;
            }
            /* gate #0b debug: every hop appends its swid to the actual path
             * (collector packs its reconstructed swid sequence the same way) */
            hdr.poolint_dbg.dbg_path =
                (hdr.poolint_dbg.dbg_path << 8) | (bit<64>)meta.switch_id;
        }
    }
}

/* ===================== SWITCH ===================== */
V1Switch(
    PoolParser(),
    PoolVerifyChecksum(),
    PoolIngress(),
    PoolEgress(),
    PoolComputeChecksum(),
    PoolDeparser()
) main;
