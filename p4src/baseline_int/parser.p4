/* -*- P4_16 -*- */
/*
 * parser.p4 : parser, checksum and deparser for the baseline INT-MD
 *             data plane.  Included by baseline_int.p4.
 *
 * The parser handles both plain IPv4 frames (EtherType 0x0800) and INT
 * frames (EtherType TYPE_INT).  For an INT frame it extracts the shim
 * and then loops extracting `hopCount` metadata records using a parser
 * counter, before falling through to the original IPv4 header.
 */
#ifndef __PARSER_P4__
#define __PARSER_P4__

parser BaselineParser(packet_in packet,
                      out headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {

    /* number of INT metadata records still to extract */
    bit<8> int_left = 0;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_INT : parse_int_shim;
            TYPE_IPV4: parse_ipv4;
            default  : accept;
        }
    }

    state parse_int_shim {
        packet.extract(hdr.int_shim);
        int_left = hdr.int_shim.hopCount;
        transition select(int_left) {
            0      : parse_ipv4;          /* empty stack (shouldn't happen) */
            default: parse_int_metadata;
        }
    }

    state parse_int_metadata {
        packet.extract(hdr.int_metadata.next);
        int_left = int_left - 1;
        transition select(int_left) {
            0      : parse_ipv4;
            default: parse_int_metadata;
        }
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

/* ---- checksum verification (no-op: IPv4 left intact) ----------------- */
control BaselineVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*
 * The baseline does NOT modify the IPv4 header (no TTL decrement, no MAC
 * rewrite -- forwarding relies on static ARP), so the IPv4 checksum stays
 * valid and is left untouched.  INT headers sit between L2 and L3 and
 * carry no checksum.
 */
control BaselineComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/* ---- deparser -------------------------------------------------------- */
control BaselineDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_metadata);   /* emits all valid stack entries */
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

#endif /* __PARSER_P4__ */
