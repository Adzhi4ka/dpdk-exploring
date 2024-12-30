#include "lib/GeneratorContainer.hpp"
#include "lib/Generators/IGenerator.h"
#include "lib/Generators/ManualGenerator.hpp"
#include "lib/Generators/RealGenerator.hpp"
#include "lib/Generators/TrashGenerator.hpp"

#include <memory>
#include <iostream>
#include <cstring>

int port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf;
    const uint16_t rx_rings = 1, tx_rings = 0;
    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 0;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval < 0) {
        return retval;
    }

    memset(&port_conf, 0, sizeof(struct rte_eth_conf));

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        std::cout << rte_strerror(-retval);

        return retval;
    }

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) {
        std::cout << rte_strerror(-retval);

        return retval;
    }


    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) {
        std::cout << rte_strerror(-retval);

        return retval;
    }

    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);

        if (retval < 0) {
            std::cout << rte_strerror(-retval);

            return retval;
        }
    }

    return 0;
}

int parse_custom_args(int argc, char *argv[]) {
    if (argc == 0) {
        return 0;
    }

    if (argc > 1) {
        return -1;
    }

    if (!std::strcmp(argv[0], "--real")) {
        return -1;
    }

    std::cout << "Available " << rte_eth_dev_count_avail() << "ports\n";

    return 1;
}

void parse_user_args(GeneratorContainer& gen_cont, bool is_real_supported) {
    int generators_count;
    std::cout << "Input count of generators: ";
    std::cin >> generators_count;

    gen_cont = GeneratorContainer(generators_count);
    rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                                     generators_count,
                                                     0, 
                                                     RTE_MBUF_DEFAULT_BUF_SIZE,
                                                     UINT16_MAX, 
                                                     rte_socket_id());

    std::cout << "SUPPORTED GENERATORS\n t - trash dumper\n r - real traffic dumper\n m - manual dumper\n";

    if (is_real_supported) {
        uint32_t portid = 0;
        RTE_ETH_FOREACH_DEV(portid)
        if (int ret = port_init(portid, mbuf_pool) != 0)
            std::cout << rte_strerror(-ret);
    }

    for (int i = 0; i < generators_count; ++i) {
        char type_of_generator;
        uint64_t use_count;

        std::cout << "Type of generator\n";
        std::cin >> type_of_generator;

        std::cout << "Use count\n";
        std::cin >> use_count;

        switch (type_of_generator) {
        case 't':
        {
            uint16_t info_size;
            std::cout << "Input count of data\n";
            std::cin >> info_size;
            gen_cont.AddGenerator(
                std::make_unique<TrashGenerator>(
                    TrashGenerator(rte_pktmbuf_alloc(mbuf_pool), info_size)),
                use_count);

            continue;
        }
        case 'r':
        {
            uint16_t port_id;
            std::cout << "Input port id";
            std::cin >> port_id;
            gen_cont.AddGenerator(std::make_unique<RealGenerator>(
                RealGenerator(rte_pktmbuf_alloc(mbuf_pool), port_id)),
                use_count);

            continue;
        }
        case 'm':
        {
            uint16_t info_size;
            std::cout << "Input count of data\n";
            std::cin >> info_size;

            std::cout << "IPv4 - 1   or   IPv6 - 2\n";
            char type_of_network;
            std::cin >> type_of_network;

            if (type_of_network == '1') {
                IPv4Tag ipv4;

                std::cout << "Source ip: \n";
                std::cin >> ipv4.ip_src;
                ipv4.ip_src = rte_cpu_to_be_32(ipv4.ip_src);

                std::cout << "Dist ip: \n";
                std::cin >> ipv4.ip_dst;
                ipv4.ip_dst = rte_cpu_to_be_32(ipv4.ip_dst);

                std::cout << "TCP - 1   or   UDP - 2\n";
                char type_of_transport;
                std::cin >> type_of_transport;

                if (type_of_transport == '1') {
                    TcpTag tcp;

                    std::cout << "Source port: \n";
                    std::cin >> tcp.port_src;
                    tcp.port_src = rte_cpu_to_be_16(tcp.port_src);

                    std::cout << "Dist port: \n";
                    std::cin >> tcp.port_dst;
                    tcp.port_dst = rte_cpu_to_be_16(tcp.port_dst);

                    gen_cont.AddGenerator(
                        std::make_unique<ManualGenerator<IPv4Tag, TcpTag>>(
                            ManualGenerator<IPv4Tag, TcpTag>(rte_pktmbuf_alloc(mbuf_pool), info_size, ipv4, tcp)),
                        use_count);
                
                    continue;
                }

                if (type_of_transport == '2') {
                    UdpTag udp;

                    std::cout << "Source port: \n";
                    std::cin >> udp.port_src;
                    udp.port_src = rte_cpu_to_be_16(udp.port_src);

                    std::cout << "Dist port: \n";
                    std::cin >> udp.port_dst;
                    udp.port_dst = rte_cpu_to_be_16(udp.port_dst);

                    gen_cont.AddGenerator(
                        std::make_unique<ManualGenerator<IPv4Tag, UdpTag>>(
                            ManualGenerator<IPv4Tag, UdpTag>(rte_pktmbuf_alloc(mbuf_pool), info_size, ipv4, udp)),
                        use_count);
                
                    continue;
                }

                continue;
            }

            IPv6Tag ipv6;

            std::cout << "Source ip: \n";
            for (int j = 0; j < 16; ++j) {
                std::cin >> ipv6.ip_src[j];
            }

            std::cout << "Dist ip: \n";
            for (int j = 0; j < 16; ++j) {
                std::cin >> ipv6.ip_dst[j];
            }

            std::cout << "TCP - 1   or   UDP - 2\n";
            char type_of_transport;
            std::cin >> type_of_transport;

            if (type_of_transport == '1') {
                TcpTag tcp;

                std::cout << "Source port: \n";
                std::cin >> tcp.port_src;
                tcp.port_src = rte_cpu_to_be_16(tcp.port_src);

                std::cout << "Dist port: \n";
                std::cin >> tcp.port_dst;
                tcp.port_dst = rte_cpu_to_be_16(tcp.port_dst);

                gen_cont.AddGenerator(
                    std::make_unique<ManualGenerator<IPv6Tag, TcpTag>>(
                        ManualGenerator<IPv6Tag, TcpTag>(rte_pktmbuf_alloc(mbuf_pool), info_size, ipv6, tcp)),
                    use_count);
            
                continue;
            }

            if (type_of_transport == '2') {
                UdpTag udp;

                std::cout << "Source port: \n";
                std::cin >> udp.port_src;
                udp.port_src = rte_cpu_to_be_16(udp.port_src);

                std::cout << "Dist port: \n";
                std::cin >> udp.port_dst;
                udp.port_dst = rte_cpu_to_be_16(udp.port_dst);

                gen_cont.AddGenerator(
                    std::make_unique<ManualGenerator<IPv6Tag, UdpTag>>(
                        ManualGenerator<IPv6Tag, UdpTag>(rte_pktmbuf_alloc(mbuf_pool), info_size, ipv6, udp)),
                    use_count);
            
                continue;
            }
        }
            continue;
        default:
            rte_exit(EXIT_FAILURE, "ERROR.\nUncorrect input\n");
        }
    }
}

int main(int argc, char *argv[]) {
    int ret = rte_eal_init(argc, argv);

    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "ERROR.\nrte_eal_init failed\n");
    }

    argc -= ret;
    argv += ret;

    ret = parse_custom_args(argc, argv);

    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "ERROR.\nParse custom args failed\n");
    }

    GeneratorContainer gen_cont(0);
    parse_user_args(gen_cont, ret == 0);

    std::cout << "Direct or Random";
    char type_of_write;
    std::cin >> type_of_write;

    std::cout << "File name";
    std::string file_name;
    std::cin >> file_name;

    if (type_of_write == '1') {
        gen_cont.WriteDirect(file_name);

        return 0;
    }

    gen_cont.WriteRandom(file_name);

    return 0;
}