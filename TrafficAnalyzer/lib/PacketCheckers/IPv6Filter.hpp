#pragma once

#include <memory>

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

struct ipv6_filter_args {
    uint8_t ip_src[16];
    uint8_t ip_dist[16];
    rte_be16_t port_src;
    rte_be16_t port_dist;

    bool is_any_ip_src = 0;
    bool is_any_ip_dist = 0;
    bool is_any_port_src = 0;
    bool is_any_port_dist = 0;
};

class IPv6Filter {
public:
    using args = ipv6_filter_args;

    IPv6Filter(const args& masks) :
        masks_(masks) {}


    inline bool 
    check_packet(const args& readed_args) const noexcept 
    {
        return check_dist_ip(readed_args.ip_dist)                                              &&
               check_src_ip(readed_args.ip_src)                                                &&
               ((masks_.is_any_port_src == 0) || (masks_.port_src == readed_args.port_src))    &&
               ((masks_.is_any_port_dist == 0) || (masks_.port_dist == readed_args.port_dist));
    }

    inline void 
    print_discription() const noexcept 
    {
        std::cout << dscr_;
    }

    static inline bool 
    check_packet_type(const rte_mbuf *packet, args& readed_args) 
    {
        if (rte_pktmbuf_mtod(packet, struct rte_ether_hdr *)->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {

            return false;
        }

        const rte_ipv6_hdr* ipv6_hdr = rte_pktmbuf_mtod_offset(packet, rte_ipv6_hdr *, sizeof(rte_ether_hdr));

        if (ipv6_hdr->proto == IPPROTO_TCP) {
            const rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(packet, rte_tcp_hdr *, sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr));
            memcpy(readed_args.ip_dist, ipv6_hdr->dst_addr, 16);
            memcpy(readed_args.ip_src, ipv6_hdr->src_addr, 16);
            readed_args.port_dist = tcp_hdr->dst_port;
            readed_args.port_src = tcp_hdr->src_port;

            return true;
        }

        if (ipv6_hdr->proto == IPPROTO_UDP) {
            const rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(packet, rte_udp_hdr *, sizeof(rte_ether_hdr) + sizeof(rte_ipv6_hdr));
            memcpy(readed_args.ip_dist, ipv6_hdr->dst_addr, 16);
            memcpy(readed_args.ip_src, ipv6_hdr->src_addr, 16);
            readed_args.port_dist = udp_hdr->dst_port;
            readed_args.port_src = udp_hdr->src_port;

            return true;
        }

        return false;
    }

private:
    args masks_;
    const char* dscr_;

    inline bool 
    check_src_ip(const uint8_t* ip_src) const noexcept 
    {
        if (masks_.is_any_ip_src == 0) {
            return true;
        }

        for (int i = 0; i < 16; ++i) {
            if (masks_.ip_src[i] != ip_src[i]) {

                return false;
            }
        }

        return true;
    }

    inline bool 
    check_dist_ip(const uint8_t* ip_dist) const noexcept 
    {
        if (masks_.is_any_ip_dist == 0) {
            return true;
        }

        for (int i = 0; i < 16; ++i) {
            if (masks_.ip_dist[i] != ip_dist[i]) {

                return false;
            }
        }

        return true;
    }
};