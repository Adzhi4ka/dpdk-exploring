#include "lib/TrafficAnalyzer.hpp"
#include "lib/TrafficReader.hpp"

#include <rte_eal.h>
#include <rte_common.h>

#include <cstdlib>
#include <iostream>
#include <memory>

void InitDPDK(int argc, char **argv) 
{
    int ret = rte_eal_init(argc, argv);
    
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "ERROR.\nrte_eal_init failed\n");
    }
}

void parse(TrafficAnalyzer& filters) 
{
    int filter_count;
    std::string buff;
    
    std::cout << "Input count of filters: ";
    std::cin >> filter_count;

    for (int i = 0; i < filter_count; ++i) {
        char filter_type;

        std::cout << "Type of filter: ";
        std::cout << "a - ipv4\n";
        std::cout << "b - ipv6\n";
        std::cin >> filter_type;

        while (true) {
            switch (filter_type)
            {
                case 'a':
                {
                    ipv4_filter_args args;

                    std::cout << "Ip dist [any/number]: ";
                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_ip_dist = true;
                    } else {
                        args.ip_dist = rte_cpu_to_be_32(std::stoi(buff));
                    }

                    std::cout << "Ip src [any/number]: ";
                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_ip_src = true;
                    } else {
                        args.ip_src = rte_cpu_to_be_32(std::stoi(buff));
                    }

                    std::cout << "Port dst [any/number]: ";
                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_port_dist = true;
                    } else {
                        args.port_dist = rte_cpu_to_be_16(std::stoi(buff));
                    }

                    std::cout << "Port src [any/number]: ";
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

                    std::cout << "Ip dist [any/number]: ";
                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_ip_dist = true;
                    } else {
                        for (int i = 0; i < 16; ++i) {
                            args.ip_dist[i] = buff[i];
                        }
                    }

                    std::cout << "Ip src [any/number]: ";
                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_ip_src = true;
                    } else {
                        for (int i = 0; i < 16; ++i) {
                            args.ip_src[i] = buff[i];
                        }
                    }

                    std::cout << "Port dist [any/number]: ";
                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_port_dist = true;
                    } else {
                        args.port_dist = rte_cpu_to_be_16(std::stoi(buff));
                    }

                    std::cout << "Port src [any/number]: ";
                    std::cin >> buff;

                    if (buff == "any") {
                        args.is_any_port_src = true;
                    } else {
                        args.port_src = rte_cpu_to_be_16(std::stoi(buff));
                    }

                    filters.add_ipv6_filter(args);

                    break;
                }

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

int main(int argc, char **argv) 
{
    int ret = rte_eal_init(argc, argv);
    
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "ERROR.\nrte_eal_init failed\n");
    }

    TrafficAnalyzer analyzer;

    parse(analyzer);

    TrafficReader reader(analyzer);

    reader.setup();

    reader.read_traffic();

    rte_eal_cleanup();
    return 0;
}