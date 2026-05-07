#pragma once

#include "IGenerator.h"

class TrashGenerator : public IGenerator {
public:
    TrashGenerator(rte_mbuf *packet, uint16_t info_size) : packet_(packet), info_size_(info_size) {}

    rte_mbuf* 
    Generate() override {
        char *data = rte_pktmbuf_append(packet_, sizeof(rte_ether_hdr) + info_size_);

        if (!data) {
            rte_pktmbuf_free(packet_);

            return nullptr;
        }

        return packet_;
    }

private:
    rte_mbuf *packet_;
    uint16_t info_size_;
};
