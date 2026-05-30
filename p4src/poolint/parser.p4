/* -*- P4_16 -*- */
/*
 * p4src/poolint/parser.p4 : parser / checksum / deparser for PoolINT.
 *
 * A plain IPv4 frame (0x0800) enters at the source leaf; the source leaf's
 * egress pushes a poolint_t (+ poolint_dbg_t) and rewrites etherType to
 * TYPE_POOLINT (0x1213).  Every downstream switch and the collector parse
 * 0x1213 -> poolint_t -> poolint_dbg_t -> ipv4.
 */
#ifndef __POOLINT_PARSER_P4__
#define __POOLINT_PARSER_P4__

parser PoolParser(packet_in packet,
                  out headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_POOLINT: parse_poolint;
            TYPE_IPV4   : parse_ipv4;
            default     : accept;
        }
    }

    state parse_poolint {
        packet.extract(hdr.poolint);
        packet.extract(hdr.poolint_dbg);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_TCP: parse_tcp;
            default     : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/* IPv4 header is never modified (static ARP, no TTL decrement), so its
 * checksum stays valid; PoolINT headers carry no checksum. */
control PoolVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}
control PoolComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control PoolDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.poolint);
        packet.emit(hdr.poolint_dbg);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

#endif /* __POOLINT_PARSER_P4__ */
