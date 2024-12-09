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
#define MAGIC_NUMBER        128

rte_eth_conf port_conf = {};


class TrafficReader {
public:
    TrafficReader(const TrafficAnalyzer& analyzer) noexcept : analyzer_(analyzer) 
    {}

    static inline int
    port_init(uint16_t port, struct rte_mempool *mbuf_pool)
    {
        struct rte_eth_conf port_conf;
        const uint16_t rx_rings = 1, tx_rings = 0;
        uint16_t nb_rxd = 1024;
        uint16_t nb_txd = 0;
        int retval;
        uint16_t q;
        struct rte_eth_dev_info dev_info;

        if (!rte_eth_dev_is_valid_port(port))
            return -1;

        memset(&port_conf, 0, sizeof(struct rte_eth_conf));

        retval = rte_eth_dev_info_get(port, &dev_info);
        if (retval != 0) {
            printf("Error during getting device (port %u) info: %s\n",
                    port, strerror(-retval));
            return retval;
        }

        /* Configure the Ethernet device. */
        retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
        if (retval != 0)
            return retval;

        retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
        if (retval != 0)
            return retval;

        /* Allocate and set up 1 RX queue per Ethernet port. */
        for (q = 0; q < rx_rings; q++) {
            retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                    rte_eth_dev_socket_id(port), NULL, mbuf_pool);
            if (retval < 0)
                return retval;
        }

        /* Starting Ethernet port. 8< */
        retval = rte_eth_dev_start(port);
        /* >8 End of starting of ethernet port. */
        if (retval < 0)
            return retval;

        /* Enable RX in promiscuous mode for the Ethernet device. */
        retval = rte_eth_promiscuous_enable(port);
        /* End of setting RX port in promiscuous mode. */
        if (retval != 0)
            return retval;

        return 0;
    }

    inline void 
    setup() const noexcept
    {
        uint16_t portid;
        rte_mempool *mbuf_pool;
        uint32_t nb_ports;
        nb_ports = rte_eth_dev_count_avail();

        std::cout << nb_ports << "ASDASDASDASASDASD";

        mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", 512 * nb_ports, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());


        if (mbuf_pool == NULL)
            rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

        RTE_ETH_FOREACH_DEV(portid)
            if (port_init(portid, mbuf_pool) != 0)
                rte_exit(EXIT_FAILURE, "Cannot init port %u \n", portid);

        if (rte_lcore_count() > 1)
            printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
    }

    inline void 
    read_traffic() noexcept 
    {
        rte_mbuf* packets[32];
        uint32_t nb_rx;

        while (true) {
            char choice;

            nb_rx = rte_eth_rx_burst(0, 0, packets, 32);
            std::cout << "Analyze packets" << nb_rx << '\n';
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