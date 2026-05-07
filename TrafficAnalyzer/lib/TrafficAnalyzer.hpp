#pragma once

#include <iostream>
#include <chrono>

#include <rte_mempool.h>

#include "PacketCheckers/IPv4Filter.hpp"
#include "PacketCheckers/IPv6Filter.hpp"
#include "FilterContainer.hpp"

class TrafficAnalyzer {
public:
    void
    add_ipv4_filter(IPv4Filter&& filter) noexcept 
    {
        ipv4_filters_.add_filter(std::move(filter));
    }

    void
    add_ipv6_filter(IPv6Filter&& filter) noexcept 
    {
        ipv6_filters_.add_filter(std::move(filter));
    }

    void 
    analyze(rte_mbuf *packet) noexcept
    {
        if(ipv4_filters_.check_packet(packet)) {

            return;
        }

        if(ipv6_filters_.check_packet(packet)) {

            return;
        }

        ++unaccepted_packet_count;
    }

    void 
    print_stats(const std::chrono::duration<double>& duration) const noexcept
    {
        ipv4_filters_.print_statistic(duration);
        ipv6_filters_.print_statistic(duration);
        printf("Count of unaccepted packet: %ld", unaccepted_packet_count);
    }

private:
    FilterContainer<IPv4Filter> ipv4_filters_;
    FilterContainer<IPv6Filter> ipv6_filters_;
    uint64_t unaccepted_packet_count = 0;
};