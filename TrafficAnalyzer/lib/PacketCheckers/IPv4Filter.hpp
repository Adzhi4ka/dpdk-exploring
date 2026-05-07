#pragma once

#include <memory>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

struct ipv4_filter_args {
    rte_be32_t ip_src;
    rte_be32_t ip_dist;
    rte_be16_t port_src;
    rte_be16_t port_dist;

    bool is_any_ip_src = 0;
    bool is_any_ip_dist = 0;
    bool is_any_port_src = 0;
    bool is_any_port_dist = 0;
};

class IPv4Filter {
public:
    using args = ipv4_filter_args;

    IPv4Filter(const args& masks) : masks_(masks) {}

    inline bool 
    check_packet(args& readed_args) const noexcept 
    {
        return ((masks_.is_any_ip_src) || (masks_.ip_src == readed_args.ip_src))         &&
               ((masks_.is_any_ip_dist) || (masks_.ip_dist == readed_args.ip_dist))      &&
               ((masks_.is_any_port_src) || (masks_.port_src == readed_args.port_src))   &&
               ((masks_.is_any_port_dist) || (masks_.port_dist == readed_args.port_dist));
    }

    static inline bool 
    check_packet_type(const rte_mbuf *packet, args& readed_args) 
    {
        if (rte_pktmbuf_mtod(packet, rte_ether_hdr *)->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {

            return false;
        }

        const rte_ipv4_hdr* ipv4_hdr = rte_pktmbuf_mtod_offset(packet, rte_ipv4_hdr *, sizeof(rte_ether_hdr));

        if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
            const rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(packet, rte_tcp_hdr *, sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr));
            readed_args.ip_dist = ipv4_hdr->dst_addr;
            readed_args.ip_src = ipv4_hdr->src_addr;
            readed_args.port_dist = tcp_hdr->dst_port;
            readed_args.port_src = tcp_hdr->src_port;

            return true;
        }

        if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
            const rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(packet, rte_udp_hdr *, sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr));
            readed_args.ip_dist = ipv4_hdr->dst_addr;
            readed_args.ip_src = ipv4_hdr->src_addr;
            readed_args.port_dist = udp_hdr->dst_port;
            readed_args.port_src = udp_hdr->src_port;

            return true;
        }

        return false;
    }

    inline void 
    print_discription() const noexcept 
    {
        std::cout << dscr_;
    }

private:
    args masks_;
    const char* dscr_;
};