#pragma once

#include "Generators/IGenerator.h"

#include <memory>
#include <pcap.h>
#include <random>
#include <vector>

#include <iostream>

struct UsingGenerator {
    std::unique_ptr<IGenerator> generator_;
    uint64_t use_count;
};

class GeneratorContainer {
public:
    GeneratorContainer() : use_count_(0) {}

    void 
    AddGenerator(std::unique_ptr<IGenerator> generator, uint64_t use_count) {
        generators_.push_back({std::move(generator), use_count});
        use_count_ += use_count;
    }

    void 
    WriteRandom(const std::string& file_name) {
        pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
        pcap_dumper = pcap_dump_open(pcap_handle, file_name.c_str());

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<std::size_t> dis(0, generators_.size());

        for (std::size_t i = 0; i < use_count_; ++i) {
            std::size_t cur_gen =  dis(gen);
            if (generators_[cur_gen].use_count == 0) {

                continue;
            }

            Write(generators_[cur_gen].generator_->Generate());
            generators_[cur_gen].use_count -= 1;
        }
    }

    void 
    WriteDirect(const std::string& file_name) {
        pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
        pcap_dumper = pcap_dump_open(pcap_handle, file_name.c_str());

        for (std::size_t i = 0; i < generators_.size(); ++i) {
            while (generators_[i].use_count != 0) {
                Write(generators_[i].generator_->Generate());
                generators_[i].use_count -= 1;
            }
        }
    }


private:
    void 
    Write(rte_mbuf* packet_dump) {
        pcap_pkthdr pcap_hdr = {0};

        if (packet_dump == nullptr) {

            return;
        }

        pcap_hdr.caplen = packet_dump->pkt_len;
        pcap_hdr.len = packet_dump->pkt_len;
        pcap_dump((u_char *)pcap_dumper, &pcap_hdr, rte_pktmbuf_mtod(packet_dump, u_char *));

        rte_pktmbuf_free(packet_dump);
    }

    std::vector<UsingGenerator> generators_;

    uint64_t use_count_;

    pcap_t *pcap_handle;
    pcap_dumper_t *pcap_dumper;
};