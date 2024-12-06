#pragma once

#include <iostream>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_lcore.h>

#include "TrafficAnalyzer.hpp"

#define PKT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define MAGIC_NUMBER        8192

rte_eth_conf port_conf = {};


class TrafficReader {
public:
    TrafficReader(const TrafficAnalyzer& analyzer) noexcept : analyzer_(analyzer) {
        mbuf_pool_ = rte_pktmbuf_pool_create("packet_pool", MAGIC_NUMBER, 32,
                    0, PKT_MBUF_DATA_SIZE, rte_socket_id());

        if (mbuf_pool_ == nullptr) {

            rte_exit(EXIT_FAILURE, "ERROR!\nrte_pktmbuf_pool_create failed\n");
        }
    }
    inline void 
    setup() const {
        /*
        uint16_t port_ids[RTE_MAX_ETHPORTS] = {0};
        int16_t id = 0;
        int16_t total_port_count = 0;

        RTE_ETH_FOREACH_DEV(id) {
            port_ids[total_port_count] = id;
            total_port_count++;
            if (total_port_count >= RTE_MAX_ETHPORTS)
            {
                std::cerr << "Total number of detected ports exceeds RTE_MAX_ETHPORTS. " << std::endl;
                rte_eal_cleanup();
                exit(1);
            }
        }

        const int16_t portSocketId = rte_eth_dev_socket_id(port_ids[0]);
        const int16_t coreSocketId = rte_socket_id();

        if (rte_eth_dev_configure(port_ids[0], 1, 0, &port_conf) < 0) {

            rte_exit(EXIT_FAILURE, "ERROR!\n rte_eth_dev_configure failed\n");
        }

        if (rte_eth_rx_queue_setup(port_ids[0], 0, 1024, ((portSocketId >= 0) ? portSocketId : coreSocketId), nullptr, mbuf_pool_) < 0) {

            rte_exit(EXIT_FAILURE, "ERROR!\n rte_eth_rx_queue_setup failed\n");
        }


        if (rte_eth_promiscuous_enable(port_ids[0]) < 0) {

            rte_exit(EXIT_FAILURE, "ERROR!\n rte_eth_promiscuous_enable failed\n");         
        }

        if (rte_eth_dev_start(port_ids[0]) < 0) {

            rte_exit(EXIT_FAILURE, "ERROR!\n rte_eth_dev_start failed\n");
        }
        */
    }

    void 
    read_traffic() {
        rte_mbuf* packets[32];
        uint32_t nb_rx;

        while (true) {
            char choice;

            std::cout << "Analyze packets\n";
            nb_rx = rte_eth_rx_burst(0, 0, packets, 32);
            for (int i = 0; i < nb_rx; ++i) {
                rte_pktmbuf_refcnt_update(packets[i], 1);
                analyzer_.analyze(packets[i]);
                rte_pktmbuf_refcnt_update(packets[i], -1);
            }

            std::cout << "Continue: [y/n]";
            std::cin >> choice;

            if (choice == 'n') {
                analyzer_.print_stats();

                break;
            }
        }
    }

private:
    TrafficAnalyzer analyzer_;
    rte_mempool *mbuf_pool_;
};