// SPDX-License-Identifier: MIT
//
#pragma once

#include <memory>
#include "dns_protocol.hpp"

class Resolver {
public:
    virtual ~Resolver() = default;
    virtual void init() {}
    virtual void maintain() {}
    virtual void reload() {}
    virtual DnsMessagePtr query(const DnsMessage& req, bool allowFanOut = true) = 0;
    virtual int countConnected() const { return 0; }
};
