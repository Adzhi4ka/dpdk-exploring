#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_ip.h>
#include <rte_pcapng.h>
#include <pcap.h>
#include <stdio.h>

#include <iostream>
#include <chrono>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	rte_eth_conf port_conf = {0};
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	rte_eth_dev_info dev_info;
	rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;


	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));

		return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;

	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	return 0;
}

int main(int argc, char **argv) {
	char errbuf[PCAP_ERRBUF_SIZE];
	std::string file_name;
	rte_mempool *mbuf_pool;
	uint32_t nb_ports;
	pcap_t *handle;
	pcap_pkthdr header;
    const u_char *packet_data;
	uint16_t portid = 0;

	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	nb_ports = rte_eth_dev_count_avail();

	std::cerr << nb_ports;

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    port_init(portid, mbuf_pool);

	std::cout << "Input file name\n";
	std::cin >> file_name;

    handle = pcap_open_offline(file_name.c_str(), errbuf);
    if (handle == NULL) {
        rte_exit(EXIT_FAILURE, "Error during open file: %s\n", errbuf);
    }

	auto start = std::chrono::high_resolution_clock::now();

	uint64_t packet_cnt = 0;
	uint64_t byte_cnt = 0;

    while ((packet_data = pcap_next(handle, &header)) != NULL) {
        rte_mbuf *pkt = rte_pktmbuf_alloc(mbuf_pool);
        if (pkt == nullptr) {
            rte_exit(EXIT_FAILURE, "Error packet alloc\n");
        }

        rte_memcpy(rte_pktmbuf_mtod(pkt, void *), packet_data, header.len);
        pkt->data_len = header.len;
        pkt->pkt_len = header.len;

		++packet_cnt;
		byte_cnt += header.len;

        if (rte_eth_tx_burst(portid, 0, &pkt, 1) < 0) {
            rte_exit(EXIT_FAILURE, "Error during send packet\n");
        }
    }

	std::chrono::duration<double> duration = std::chrono::high_resolution_clock::now() - start;

	std::cout << "Total packet: " << packet_cnt << '\n';
	std::cout << "Packet per second: " << ((double) packet_cnt / duration.count()) * 1000000000 << '\n';

	std::cout << "Total byte: " << byte_cnt << '\n';
	std::cout << "byte per second: " << ((double) byte_cnt / duration.count()) * 1000000000 << '\n';

    pcap_close(handle);

	std::cin >> file_name;

    return 0;
}
