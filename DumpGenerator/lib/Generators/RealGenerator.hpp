#pragma once

#include "IGenerator.h"

class RealGenerator : public IGenerator {
public:
    RealGenerator(rte_mbuf *packet, uint16_t port_id) : packet_(packet), port_id_(port_id) {}

    rte_mbuf* 
    Generate() override {
        uint16_t nb_rx = rte_eth_rx_burst(port_id_, 0, &packet_, 1);

        if (nb_rx == 0) {
            return nullptr;
        }

        return packet_;
    }

private:
    rte_mbuf *packet_;
    uint16_t port_id_;
};