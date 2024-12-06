#pragma once

#include "PacketCheckers/FilterDecorator.hpp"

template <typename T>
class FilterContainer {
public:
    void 
    add_filter(const FilterDecorator<T>& filter) noexcept {
        filters_.push_back(filter);
    }

    bool 
    check_packet(const rte_mbuf* packet) {
        FilterDecorator<T>::check_hdr(packet);

        for (auto i : filters_) {
            if (i.check_packet(packet)) {

                return true;
            }
        }

        return false;
    }

    void 
    reset() noexcept {
        for (auto i : filters_) {
            i.reset();
        }
    }

    void 
    print_statistic() const noexcept {
        for (auto i : filters_) {
            i.print_statistic();
        }
    }

private:
    std::vector<FilterDecorator<T>> filters_ = std::vector<FilterDecorator<T>>();

    uint64_t get_packet_count_ = 0;
    uint64_t get_byte_count_ = 0;
};