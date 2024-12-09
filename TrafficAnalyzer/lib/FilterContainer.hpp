#pragma once

#include <deque>

#include "PacketCheckers/FilterDecorator.hpp"

template <typename T>
class FilterContainer {
public:
    void 
    add_filter(FilterDecorator<T>&& filter) noexcept 
    {
        filters_.emplace_back(std::move(filter));
    }

    bool 
    check_packet(const rte_mbuf* packet) noexcept
    {
        FilterDecorator<T>::check_hdr(packet, readed_hdr);

        for (FilterDecorator<T>& i : filters_) {
            if (i.check_packet(packet, readed_hdr)) {

                return true;
            }
        }

        return false;
    }

    void 
    reset() noexcept 
    {
        for (auto i : filters_) {
            i.reset();
        }
    }

    void 
    print_statistic() const noexcept 
    {
        for (const FilterDecorator<T>& i : filters_) {
            i.print_statistic();
        }
    }

private:
    std::vector<FilterDecorator<T>> filters_;
    typename T::args readed_hdr;

    uint64_t get_packet_count_ = 0;
    uint64_t get_byte_count_ = 0;
};