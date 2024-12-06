#include <cstdlib>
#include <iostream>

#include <rte_eal.h>
#include <rte_common.h>

#include "lib/TrafficAnalyzer.hpp"
#include "lib/TrafficReader.hpp"

/*Ужасное решение, нужно придумать получше*/
ipv6_filter_args IPv6Filter::readed_args = ipv6_filter_args{{0}, {0}, 0, 0, 0, 0, 0, 0};
/*Ужасное решение, нужно придумать получше*/
ipv4_filter_args IPv4Filter::readed_args = ipv4_filter_args{0, 0, 0, 0, 0, 0, 0, 0};

void InitDPDK(int argc, char **argv) {
    int ret = rte_eal_init(argc, argv);
    
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "ERROR.\nrte_eal_init failed\n");
    }
}

void parse(TrafficAnalyzer& filters) {
    
    std::cout << "Input count of filters: ";
    int filter_count;
    std::cin >> filter_count;
    
    std::string buff;

    if (filter_count <= 0) {
        filter_count = 10;
    }

    for (int i = 0; i < filter_count; ++i) {
        char filter_type;

        std::cout << "Type of filter: ";
        std::cin >> filter_type;

        while (true) {
            switch (filter_type)
            {
                case 'a':
                {
                    ipv4_filter_args args;

                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_ip_dist = true;
                    } else {
                        args.ip_dist = rte_cpu_to_be_32(std::stoi(buff));
                    }

                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_ip_src = true;
                    } else {
                        args.ip_src = rte_cpu_to_be_32(std::stoi(buff));
                    }

                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_port_dist = true;
                    } else {
                        args.port_dist = rte_cpu_to_be_16(std::stoi(buff));
                    }

                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_port_src = true;
                    } else {
                        args.port_src = rte_cpu_to_be_16(std::stoi(buff));
                    }

                    filters.add_ipv4_filter(IPv4Filter(args));

                    break;
                }
                case 'b':
                {
                    ipv6_filter_args args;

                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_ip_dist = true;
                    } else {
                        for (int i = 0; i < 16; ++i) {
                            args.ip_dist[i] = buff[i];
                        }
                    }

                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_ip_src = true;
                    } else {
                        for (int i = 0; i < 16; ++i) {
                            args.ip_src[i] = buff[i];
                        }
                    }

                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_port_dist = true;
                    } else {
                        args.port_dist = rte_cpu_to_be_16(std::stoi(buff));
                    }

                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_port_src = true;
                    } else {
                        args.port_src = rte_cpu_to_be_16(std::stoi(buff));
                    }

                    filters.add_ipv6_filter(IPv6Filter(args));

                    break;
                }

                case 'q':
                    rte_exit(EXIT_SUCCESS, "");

                default:
                    std::cout << "Uncorrect command";
                    std::cout << "Type of filter: ";
                    std::cin >> filter_type;
                    continue;
            }

            break;
        }
    }
}

int main(int argc, char **argv) {
    InitDPDK(argc, argv);

    TrafficAnalyzer analyzer;

    parse(analyzer);

    TrafficReader reader(analyzer);

    reader.setup();

    reader.read_traffic();

    rte_eal_cleanup();
    return 0;
}