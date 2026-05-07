#pragma once

#include "IGenerator.h"

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

struct IPv4Tag {
    rte_be32_t ip_src;
    rte_be32_t ip_dst;
};

struct IPv6Tag {
    uint8_t ip_src[16];
    uint8_t ip_dst[16];
};

struct TcpTag {
    rte_be16_t port_src;
    rte_be16_t port_dst;
};

struct UdpTag {
    rte_be16_t port_src;
    rte_be16_t port_dst;
};

template<typename NetworkTag, typename TransportTag>
class ManualGenerator : public IGenerator {
public:
    ManualGenerator(rte_mbuf *packet, uint16_t info_size, const NetworkTag& network_info, const TransportTag& transport_info)
     : packet_(packet), info_size_(info_size), network_info_(network_info), transport_info_(transport_info) {}

    rte_mbuf* 
    Generate() override {
        if (rte_pktmbuf_append(packet_, sizeof(rte_ether_hdr)) == nullptr) {
            rte_pktmbuf_free(packet_);

            return nullptr;
        }

        if (!Generate(NetworkTag{}, TransportTag{})) {
            rte_pktmbuf_free(packet_);

            return nullptr;
        }

        if (rte_pktmbuf_append(packet_, info_size_) == nullptr) {
            rte_pktmbuf_free(packet_);

            return nullptr;
        }

        return packet_;
    }

private:
    rte_mbuf *packet_;
    uint16_t info_size_;
    NetworkTag network_info_;
    TransportTag transport_info_;


    bool 
    Generate(IPv4Tag, TcpTag) {
        if (rte_pktmbuf_append(packet_, sizeof(rte_ipv4_hdr)) == nullptr) {
            rte_pktmbuf_free(packet_);

            return false;
        }

        rte_pktmbuf_mtod(packet_, rte_ether_hdr *)->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        rte_ipv4_hdr* cur_ipv4_hdr = rte_pktmbuf_mtod_offset(packet_, rte_ipv4_hdr *, sizeof(rte_ether_hdr));

        cur_ipv4_hdr->version_ihl = (4 << 4) | (sizeof(rte_ipv4_hdr) / 4);
        cur_ipv4_hdr->src_addr = network_info_.ip_src;
        cur_ipv4_hdr->dst_addr = network_info_.ip_dst;
        cur_ipv4_hdr->time_to_live = 63;

        cur_ipv4_hdr->next_proto_id = IPPROTO_TCP;
        cur_ipv4_hdr->total_length = rte_cpu_to_be_16(info_size_ + sizeof(rte_ipv4_hdr) + sizeof(rte_tcp_hdr));

        if (rte_pktmbuf_append(packet_, sizeof(rte_tcp_hdr)) == nullptr) {
            rte_pktmbuf_free(packet_);

            return false;
        }

        rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(packet_, rte_tcp_hdr *, sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr));
        tcp_hdr->src_port = transport_info_.port_src;
        tcp_hdr->dst_port = transport_info_.port_dst;
        tcp_hdr->data_off = (sizeof(rte_tcp_hdr) / 4) << 4;

        return true;
    }

    bool 
    Generate(IPv4Tag, UdpTag) {
        if (rte_pktmbuf_append(packet_, sizeof(rte_ipv4_hdr)) == nullptr) {
            rte_pktmbuf_free(packet_);

            return false;
        }

        rte_pktmbuf_mtod(packet_, rte_ether_hdr *)->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

        rte_ipv4_hdr* cur_ipv4_hdr = rte_pktmbuf_mtod_offset(packet_, rte_ipv4_hdr *, sizeof(rte_ether_hdr));

        cur_ipv4_hdr->version_ihl = (4 << 4) | (sizeof(rte_ipv4_hdr) / 4);
        cur_ipv4_hdr->src_addr = network_info_.ip_src;
        cur_ipv4_hdr->dst_addr = network_info_.ip_dst;
        cur_ipv4_hdr->time_to_live = 63;

        cur_ipv4_hdr->total_length = rte_cpu_to_be_16(info_size_ + sizeof(rte_ipv4_hdr) + sizeof(rte_udp_hdr));
        cur_ipv4_hdr->next_proto_id = IPPROTO_UDP;

        if (rte_pktmbuf_append(packet_, sizeof(rte_udp_hdr)) == nullptr) {
            rte_pktmbuf_free(packet_);

            return false;
        }

        rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(packet_, rte_udp_hdr *, sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr));
        udp_hdr->src_port = transport_info_.port_src;
        udp_hdr->dst_port = transport_info_.port_dst;
        udp_hdr->dgram_len = rte_cpu_to_be_16(info_size_ + sizeof(rte_udp_hdr));

        return true;
    }

    bool 
    Generate(IPv6Tag, TcpTag) {
        if (rte_pktmbuf_append(packet_, sizeof(rte_ipv6_hdr)) == nullptr) {
            rte_pktmbuf_free(packet_);

            return false;
        }

        rte_pktmbuf_mtod(packet_, rte_ether_hdr *)->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

        rte_ipv6_hdr* cur_ipv6_hdr = rte_pktmbuf_mtod_offset(packet_, rte_ipv6_hdr *, sizeof(rte_ether_hdr));

        cur_ipv6_hdr->payload_len = rte_cpu_to_be_16(info_size_ + sizeof(rte_tcp_hdr));
        cur_ipv6_hdr->proto = IPPROTO_TCP;
        cur_ipv6_hdr->flow_label = rte_cpu_to_be_32(0x60000000);
        cur_ipv6_hdr->hop_limits = 63;

        rte_memcpy(&cur_ipv6_hdr->src_addr, network_info_.ip_src, 16);
        rte_memcpy(&cur_ipv6_hdr->dst_addr, network_info_.ip_dst, 16);

        if (rte_pktmbuf_append(packet_, sizeof(rte_tcp_hdr)) == nullptr) {
            rte_pktmbuf_free(packet_);

            return false;
        }

        rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(packet_, rte_tcp_hdr *, sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr));
        tcp_hdr->src_port = transport_info_.port_src;
        tcp_hdr->dst_port = transport_info_.port_dst;
        tcp_hdr->data_off = (sizeof(rte_tcp_hdr) / 4) << 4;

        return true;
    }

    bool 
    Generate(IPv6Tag, UdpTag) {
        if (rte_pktmbuf_append(packet_, sizeof(rte_ipv6_hdr)) == nullptr) {
            rte_pktmbuf_free(packet_);

            return false;
        }

        rte_pktmbuf_mtod(packet_, rte_ether_hdr *)->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);

        rte_ipv6_hdr* cur_ipv6_hdr = rte_pktmbuf_mtod_offset(packet_, rte_ipv6_hdr *, sizeof(rte_ether_hdr));

        rte_memcpy(&cur_ipv6_hdr->src_addr, network_info_.ip_src, 16);
        rte_memcpy(&cur_ipv6_hdr->dst_addr, network_info_.ip_dst, 16);

        cur_ipv6_hdr->payload_len = rte_cpu_to_be_16(info_size_ + sizeof(rte_udp_hdr));
        cur_ipv6_hdr->proto = IPPROTO_UDP;
        cur_ipv6_hdr->flow_label = rte_cpu_to_be_32(0x60000000);
        cur_ipv6_hdr->hop_limits = 63;

        if (rte_pktmbuf_append(packet_, sizeof(rte_udp_hdr)) == nullptr) {
            rte_pktmbuf_free(packet_);

            return false;
        }

        rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(packet_, rte_udp_hdr *, sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr));
        udp_hdr->src_port = transport_info_.port_src;
        udp_hdr->dst_port = transport_info_.port_dst;
        udp_hdr->dgram_len = rte_cpu_to_be_16(info_size_ + sizeof(rte_udp_hdr));

        return true;
    }
};