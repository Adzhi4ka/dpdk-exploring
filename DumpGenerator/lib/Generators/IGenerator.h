#pragma once

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

class IGenerator {
public:
    virtual ~IGenerator() = default;

    virtual rte_mbuf* Generate() = 0;
};