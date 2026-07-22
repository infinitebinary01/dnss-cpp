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
    virtual DnsMessagePtr peekCache(const DnsMessage& req) { return nullptr; }
    virtual DnsMessagePtr peekCacheRaw(const uint8_t* data, size_t len) { return nullptr; }
};
