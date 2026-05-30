/* -*- P4_16 -*- */
/*
 * PoolINT project - Milestone 2  (compile-fix revision: crc32 hash)
 * p4src/poolint/headers.p4 : headers / metadata / constants.
 *
 * Each packet is ONE pooled test.  Every switch, per metric per hash round,
 * decides via a hash gate whether its egress port is a member of this test;
 * if so it merges its local anomaly value into a tiny in-packet syndrome.
 * The per-packet syndrome size is constant, INDEPENDENT of hop count.
 *
 * Hashing uses bmv2's crc32 extern (NOT a P4-level wide multiply): the old
 * multiplicative Mersenne hash inlined a bit<64> multiply + a ~14-step fold
 * chain at ~10 call sites, which made the bmv2 backend blow up (OOM / hang
 * with no diagnostic).  See REPORT [M2-compile-fix].
 */
#ifndef __POOLINT_HEADERS_P4__
#define __POOLINT_HEADERS_P4__

/* ---- EtherTypes / protocols ------------------------------------------ */
const bit<16> TYPE_IPV4    = 0x0800;
const bit<16> TYPE_POOLINT = 0x1213;
const bit<8>  IP_PROTO_UDP = 0x11;
const bit<8>  IP_PROTO_TCP = 0x06;

/* ---- metric ids (used in the hash key, 1 byte) ----------------------- */
const bit<8> MID_FAIL   = 0;   /* per-port fault/high-loss flag (register) */
const bit<8> MID_QHI    = 1;   /* deq_qdepth > TAU_Q                       */
const bit<8> MID_QDEPTH = 2;   /* deq_qdepth quantized to 8 bit           */
const bit<8> MID_UTIL   = 3;   /* egress byte-rate proxy quantized 0..255 */

/* ---- PoolINT structural constants ------------------------------------ */
#define K_B 2          /* boolean metrics  (FAIL, QHI)                    */
#define K_Q 2          /* quant metrics    (QDEPTH, UTIL)                 */
#define R   2          /* hash rounds per metric per packet               */

/* ---- compact register sizing (root-cause fix for scaling) ------------ *
 * port_uid = (switch_id<<8)|egress_port is a 16-bit GLOBAL LABEL only
 * (written into poolint_t for the collector); it is NEVER a register
 * index.  A control-plane table tb_port_idx maps each real (switch_id,
 * egress_port) to a compact local_idx in [0, NUM_PORTS_REAL).  Per-port /
 * per-epoch registers are sized NUM_PORTS_REAL * NUM_EPOCH_SLOTS.         */
#define NUM_PORTS_REAL   32
#define NUM_EPOCH_SLOTS  4
#define REG_SLOTS        128   /* = NUM_PORTS_REAL * NUM_EPOCH_SLOTS       */

/* ---- epoch ----------------------------------------------------------- */
/* epoch_id = (ingress_global_timestamp >> EPOCH_SHIFT) & 0xff (~32ms).   */
#define EPOCH_SHIFT 15

/* ---- local-metric thresholds / quantization -------------------------- */
#define TAU_Q       8
#define UTIL_SHIFT  6

/* ---- hash gate (crc32 via bmv2 hash() extern) ------------------------ *
 * membership(r) = ( crc32(key_bytes) mod HASH_MOD ) < RHO_PERMIL         *
 * key_bytes (7, fixed big-endian, all byte-aligned so zlib.crc32 of the  *
 * same bytes reproduces it):                                             *
 *   [ test_id(2) epoch_id(1) port_uid(2) metric_id(1) round_r(1) ]       *
 * The per-round "seed" is the round_r byte itself (different round ->     *
 * different crc), so no separate seed constant is needed.                */
#define HASH_MOD    1000
#define RHO_PERMIL  500    /* rho = 0.5 */

/* ---- L2 / L3 / L4 ----------------------------------------------------- */
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  egressSpec_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/* ---- PoolINT syndrome header (one per packet, constant size) ---------
 * CORE (the per-packet overhead figure):
 *   test_id 16 | epoch_id 8 | flags 8 | bsynd 8 | q0..q3 4x8  = 9 bytes
 * DEBUG add-on (gate #0 only, excluded from overhead, removable):
 *   dbg_hash 32 | dbg_port_uid 16 | dbg_spine 8              = 7 bytes
 */
header poolint_t {
    bit<16> test_id;
    bit<8>  epoch_id;
    bit<8>  flags;
    bit<8>  bsynd;
    bit<8>  q0;
    bit<8>  q1;
    bit<8>  q2;
    bit<8>  q3;
}

header poolint_dbg_t {
    bit<32> dbg_hash;
    bit<16> dbg_port_uid;
    bit<64> dbg_path;     /* M3a: packed swid sequence of the ACTUAL path     */
                          /* (each hop: dbg_path = (dbg_path<<8)|switch_id).  */
                          /* >=3 swids fit; up to 8 hops. gate#0b ground truth*/
}

/* ---- byte-aligned hash key header (kept in metadata, not emitted) ----
 * Used as the bmv2 hash() field list so the serialized buffer is exactly
 * these 7 bytes big-endian -> reproducible with zlib.crc32 in Python.    */
struct hashkey_t {
    bit<16> test_id;
    bit<8>  epoch_id;
    bit<16> port_uid;
    bit<8>  metric_id;
    bit<8>  round_r;
}

/* ---- header & metadata structs --------------------------------------- */
struct headers {
    ethernet_t    ethernet;
    poolint_t     poolint;
    poolint_dbg_t poolint_dbg;
    ipv4_t        ipv4;
    udp_t         udp;
    tcp_t         tcp;
}

struct metadata {
    bit<16>   switch_id;
    bit<1>    int_source;
    bit<1>    pool_active;
    bit<16>   ecmp_select;
    bit<8>    ecmp_group_size;
    bit<16>   ecmp_l4_src;
    bit<16>   ecmp_l4_dst;

    bit<16>   port_uid;     /* global label (switch_id<<8)|egress_port     */
    bit<8>    local_idx;    /* compact register index from tb_port_idx     */
    bit<1>    idx_valid;    /* tb_port_idx hit                             */
    bit<8>    epoch_id;
    bit<8>    eslot;        /* epoch_id % NUM_EPOCH_SLOTS                  */

    bit<1>    v_fail;
    bit<1>    v_qhi;
    bit<8>    v_qdepth;
    bit<8>    v_util;

    hashkey_t hk;           /* byte-aligned crc32 key                      */
    bit<32>   hval;         /* crc32(key) mod HASH_MOD  (membership gate)  */
    bit<32>   hval_full;    /* full crc32(key)  (gate #0a bit-exact dbg)   */
}

#endif /* __POOLINT_HEADERS_P4__ */
