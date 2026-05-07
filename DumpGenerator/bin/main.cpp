#include "lib/GeneratorContainer.hpp"
#include "lib/Generators/IGenerator.h"
#include "lib/Generators/ManualGenerator.hpp"
#include "lib/Generators/RealGenerator.hpp"
#include "lib/Generators/TrashGenerator.hpp"

#include <memory>
#include <fstream>
#include <cstring>

int port_init(uint16_t port, rte_mempool *mbuf_pool)
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
        std::cout << rte_strerror(-retval) << '\n';

        return retval;
    }

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) {
        std::cout << rte_strerror(-retval) << '\n';

        return retval;
    }


    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) {
        std::cout << rte_strerror(-retval) << '\n';

        return retval;
    }

    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);

        if (retval < 0) {
            std::cout << rte_strerror(-retval) << '\n';

            return retval;
        }
    }

    return 0;
}

void parse_user_args(GeneratorContainer& gen_cont) {
    char type_of_generator;
    rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
                                                     255,
                                                     0, 
                                                     RTE_MBUF_DEFAULT_BUF_SIZE,
                                                     UINT16_MAX, 
                                                     SOCKET_ID_ANY);

    if (mbuf_pool == nullptr) {

        rte_exit(EXIT_FAILURE, "%s", rte_strerror(rte_errno));
    }

    std::cout << "SUPPORTED GENERATORS\n";
    std::cout << "f - from file\n";
    std::cout << "r - real traffic dumper\n";
    std::cout << "q - stop\n";

    std::cout << "Type of generator: ";
    std::cin >> type_of_generator;

    while (type_of_generator != 'q') {
        switch (type_of_generator) {
        case 'r':
        {
            uint64_t use_count;
            uint16_t port_id;

            std::cout << "Use count\n";
            std::cin >> use_count;

            std::cout << "Input port id\n";
            std::cin >> port_id;

            if (int ret = port_init(port_id, mbuf_pool) != 0) {
                std::cout << rte_strerror(-ret) << '\n';

                break;
            }

            gen_cont.AddGenerator(
                std::make_unique<RealGenerator>(rte_pktmbuf_alloc(mbuf_pool), port_id),
                use_count);

            break;
        }

        case 'f':
        {
            std::string file_name;
            std::ifstream fin;

            std::cout << "File name: ";
            std::cin >> file_name;

            fin.open(file_name);

            if (!fin) {
                std::cout << "File dont find\n";

                continue;
            }

            while (!fin.eof()) {
                char file_type_generator;

                fin >> file_type_generator;

                switch (file_type_generator) {
                case 'm':
                {
                    std::string type_of_network;
                    fin >> type_of_network;

                    if (type_of_network == "ipv4") {
                        IPv4Tag ipv4;
                        std::string type_of_transport;

                        fin >> ipv4.ip_src;
                        fin >> ipv4.ip_dst;

                        ipv4.ip_src = rte_cpu_to_be_32(ipv4.ip_src);
                        ipv4.ip_dst = rte_cpu_to_be_32(ipv4.ip_dst);

                        fin >> type_of_transport;

                        if (type_of_transport == "tcp") {
                            TcpTag tcp;
                            uint16_t info_size;
                            uint64_t use_count;

                            fin >> tcp.port_src;
                            fin >> tcp.port_dst;

                            tcp.port_src = rte_cpu_to_be_16(tcp.port_src);
                            tcp.port_dst = rte_cpu_to_be_16(tcp.port_dst);

                            fin >> info_size;
                            fin >> use_count;

                            gen_cont.AddGenerator(
                                std::make_unique<ManualGenerator<IPv4Tag, TcpTag>>(rte_pktmbuf_alloc(mbuf_pool), info_size, ipv4, tcp),
                                use_count);
                        
                            continue;
                        }

                        if (type_of_transport == "udp") {
                            UdpTag udp;
                            uint16_t info_size;
                            uint64_t use_count;

                            fin >> udp.port_src;
                            fin >> udp.port_dst;

                            udp.port_src = rte_cpu_to_be_16(udp.port_src);
                            udp.port_dst = rte_cpu_to_be_16(udp.port_dst);

                            fin >> info_size;
                            fin >> use_count;

                            gen_cont.AddGenerator(
                                std::make_unique<ManualGenerator<IPv4Tag, UdpTag>>(rte_pktmbuf_alloc(mbuf_pool), info_size, ipv4, udp),
                                use_count);
                        
                            continue;
                        }

                        continue;
                    }

                    if (type_of_network == "ipv6") {
                        IPv6Tag ipv6;
                        std::string adr_buf;
                        std::string type_of_transport;

                        fin >> adr_buf;
                        for (int j = 0; j < 16; ++j) {
                            ipv6.ip_src[j] = adr_buf[j];
                        }

                        fin >> adr_buf;
                        for (int j = 0; j < 16; ++j) {
                            ipv6.ip_dst[j] = adr_buf[j];
                        }

                        fin >> type_of_transport;
                        if (type_of_transport == "tcp") {
                            TcpTag tcp;
                            uint16_t info_size;
                            uint64_t use_count;

                            fin >> tcp.port_src;
                            fin >> tcp.port_dst;

                            tcp.port_src = rte_cpu_to_be_16(tcp.port_src);
                            tcp.port_dst = rte_cpu_to_be_16(tcp.port_dst);

                            fin >> info_size;
                            fin >> use_count;

                            gen_cont.AddGenerator(
                                std::make_unique<ManualGenerator<IPv6Tag, TcpTag>>(rte_pktmbuf_alloc(mbuf_pool), info_size, ipv6, tcp),
                                use_count);
                        
                            continue;
                        }

                        if (type_of_transport == "udp") {
                            UdpTag udp;
                            uint16_t info_size;
                            uint64_t use_count;

                            fin >> udp.port_src;
                            fin >> udp.port_dst;

                            udp.port_src = rte_cpu_to_be_16(udp.port_src);
                            udp.port_dst = rte_cpu_to_be_16(udp.port_dst);

                            fin >> info_size;
                            fin >> use_count;

                            gen_cont.AddGenerator(
                                std::make_unique<ManualGenerator<IPv6Tag, UdpTag>>(rte_pktmbuf_alloc(mbuf_pool), info_size, ipv6, udp),
                                use_count);
                        
                            continue;
                        }

                        continue;
                    }

                    continue;
                }
                
                case 't':
                {
                    uint16_t info_size;
                    uint64_t use_count;

                    fin >> info_size;
                    fin >> use_count;

                    gen_cont.AddGenerator(
                        std::make_unique<TrashGenerator>(
                            TrashGenerator(rte_pktmbuf_alloc(mbuf_pool), info_size)),
                        use_count);

                    break;
                }

                default:

                    break;
                }
            }

            break;
        }

        default:
            rte_exit(EXIT_FAILURE, "%s", "ERROR.\nUncorrect input\n");
        }

        std::cout << "Type of generator: ";
        std::cin >> type_of_generator;
    }
}

int main(int argc, char *argv[]) {
    int ret;
    char type_of_write;
    std::string file_name;


    ret = rte_eal_init(argc, argv);

    if (ret < rte_eal_init(argc, argv)) {
        rte_exit(EXIT_FAILURE, "%s", rte_strerror(rte_errno));
    }

    GeneratorContainer gen_cont;
    parse_user_args(gen_cont);

    std::cout << "Direct or Random [1/2]: ";
    std::cin >> type_of_write;

    std::cout << "File name: ";
    std::cin >> file_name;

    if (type_of_write == '1') {
        gen_cont.WriteDirect(file_name);
        std::cout << "End\n";

        return 0;
    }

    gen_cont.WriteRandom(file_name);
    std::cout << "End\n";

    return 0;
}