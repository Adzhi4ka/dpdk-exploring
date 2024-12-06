#pragma once

#include <iostream>

#include <rte_mempool.h>

#include "PacketCheckers/IPv4Filter.hpp"
#include "PacketCheckers/IPv6Filter.hpp"
#include "FilterContainer.hpp"

class TrafficAnalyzer {
public:
    void
    add_ipv4_filter(const IPv4Filter& filter) noexcept {
        ipv4_filters_.add_filter(filter);
    }

    void
    add_ipv6_filter(const IPv6Filter& filter) noexcept {
        ipv6_filters_.add_filter(filter);
    }

    void 
    analyze(rte_mbuf *packet) {
        if(ipv4_filters_.check_packet(packet)) {

            return;
        }

        if(ipv6_filters_.check_packet(packet)) {

            return;
        }

        ++unaccepted_packet_count;
    }

    void 
    print_stats() const {
        ipv4_filters_.print_statistic();
        ipv6_filters_.print_statistic();
        printf("Count of unaccepted packet: %ld", unaccepted_packet_count);
    }

private:
    FilterContainer<IPv4Filter> ipv4_filters_;
    FilterContainer<IPv6Filter> ipv6_filters_;
    uint64_t unaccepted_packet_count = 0;
};