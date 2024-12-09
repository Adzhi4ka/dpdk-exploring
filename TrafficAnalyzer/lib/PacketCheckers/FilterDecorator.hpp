#pragma once

#include <memory>
#include <cstdint>
#include <utility>
#include <vector>

#include <rte_mbuf.h>

template <typename T>
class FilterDecorator {
public:
    FilterDecorator(T&& filter) : filters_(std::move(filter)) {}

    static inline bool 
    check_hdr(const rte_mbuf* packet, typename T::args& readed_hdr) 
    {
        return T::check_packet_type(packet, readed_hdr);
    }

    bool 
    check_packet(const rte_mbuf* packet, typename T::args& readed_hdr) 
    {
        if (filters_.check_packet(readed_hdr)) {
            ++get_packet_count_;
            get_byte_count_ += packet->pkt_len;

            return true;
        }

        return false;
    }

    void 
    reset() noexcept 
    {
        get_packet_count_ = 0;
        get_byte_count_ = 0;
    }

    void 
    print_statistic() const noexcept 
    {
        printf("Packed count: %ld", get_packet_count_);
        printf("Byte count:   %ld", get_byte_count_);
    }

private:
    T filters_;

    uint64_t get_packet_count_ = 0;
    uint64_t get_byte_count_ = 0;
};