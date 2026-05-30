/* -*- P4_16 -*- */
/*
 * PoolINT project - Milestone 1
 * headers.p4 : common type / header / metadata definitions for the
 *              baseline full-stack INT-MD data plane (v1model / bmv2).
 *
 * Kept in a standalone include so that later milestones (PoolINT data
 * plane, other baselines) can reuse the same L2/L3/INT header layout.
 */
#ifndef __HEADERS_P4__
#define __HEADERS_P4__

/* ---- constants -------------------------------------------------------- */
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_INT  = 0x1212;   /* custom EtherType marking an INT frame */
const bit<8>  IP_PROTO_UDP = 0x11;
const bit<8>  IP_PROTO_TCP = 0x06;

/* Maximum number of INT metadata entries the stack can hold.            */
/* leaf-spine demo path is 3 hops; 10 gives generous head-room.          */
#define INT_MAX_HOPS 10

/* INT instruction bitmap (which metadata each hop records).             */
/* Baseline records the full fixed set, so the bitmap is informational.  */
const bit<8> INT_INSTR_FULL = 0x1f;   /* swid|in_port|eg_port|qdepth|hoplat */

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

/* ---- INT-MD headers --------------------------------------------------- */
/*
 * Wire layout of an INT frame produced by the baseline:
 *
 *   ethernet (etherType = TYPE_INT)
 *   int_shim_t                       (8 bytes, present once)
 *   int_metadata_t [hopCount]        (18 bytes each, newest first)
 *   ipv4 / udp|tcp / payload         (the original packet, untouched)
 *
 * The shim carries origEtherType so a sink can restore the frame to a
 * plain IPv4 packet (sink-strip is a documented M1 extension point).
 */
header int_shim_t {
    bit<8>  ver;            /* INT version (=1)                           */
    bit<8>  hopCount;       /* number of int_metadata_t currently stacked */
    bit<8>  maxHops;        /* INT_MAX_HOPS, for collector sanity checks  */
    bit<8>  instrBitmap;    /* which fields each hop recorded             */
    bit<16> origEtherType;  /* EtherType to restore at the sink (0x0800)  */
    bit<16> rsvd;
}

/*
 * Per-hop metadata.  The five fields mandated by the spec
 * (switch_id, ingress_port, egress_port, queue_depth, hop_latency) make
 * up the canonical 12-byte record.  ingress_ts (6 bytes) is an M1
 * hardening extension: it lets the collector compute INTER-hop / link
 * latency (egress_ts(prev) -> ingress_ts(next)), which is the only way
 * to surface a tc-netem LINK delay -- an in-switch deq_timedelta cannot
 * see wire delay.  See REPORT.md sections D/F.
 */
header int_metadata_t {
    bit<16> switch_id;
    bit<16> ingress_port;
    bit<16> egress_port;
    bit<16> queue_depth;   /* standard_metadata.deq_qdepth               */
    bit<32> hop_latency;   /* standard_metadata.deq_timedelta (us)       */
    bit<48> ingress_ts;    /* standard_metadata.ingress_global_timestamp */
}

/* ---- header & metadata structs --------------------------------------- */
struct headers {
    ethernet_t                       ethernet;
    int_shim_t                       int_shim;
    int_metadata_t[INT_MAX_HOPS]     int_metadata;
    ipv4_t                           ipv4;
    udp_t                            udp;
    tcp_t                            tcp;
}

struct metadata {
    bit<16> switch_id;       /* this switch's id, set by tb_swid          */
    bit<1>  int_source;      /* this switch must push the INT shim        */
    bit<1>  do_int;          /* this packet should carry/append INT       */
    bit<16> ecmp_select;     /* ECMP group member chosen by hash          */
    bit<8>  ecmp_group_size; /* number of spine uplinks for this leaf     */
    bit<16> ecmp_l4_src;     /* L4 src port snapshot for ECMP hashing     */
    bit<16> ecmp_l4_dst;     /* L4 dst port snapshot for ECMP hashing     */
}

#endif /* __HEADERS_P4__ */
