// SPDX-License-Identifier: MIT
//
#pragma once

#include "resolver.hpp"
#include <string>
#include <vector>
#include <atomic>
#include <thread>

class SystemResolver : public Resolver {
public:
    SystemResolver();
    ~SystemResolver() override;

    void init() override;
    DnsMessagePtr query(const DnsMessage& req, bool allowFanOut = true) override;

private:
    struct DnsServer {
        std::string ip;
        uint16_t port = 53;
    };

    std::vector<DnsServer> servers_;
    std::atomic<bool> detected_{false};

    // Network state
    std::atomic<bool> udpWorks_{false};
    std::atomic<bool> getaddrinfoWorks_{false};
    std::atomic<bool> getaddrinfoTested_{false};
    std::atomic<bool> running_{false};
    std::thread probeThread_;

    // DoH upstreams
    std::vector<std::string> dohUrls_;

    void detectSystemDns();
    void detectDohUpstreams();
    bool probeUdp();
    void probeLoop();
    DnsMessagePtr queryGetaddrinfo(const DnsMessage& req);
    DnsMessagePtr queryUdp(const DnsMessage& req);
    DnsMessagePtr queryDoh(const DnsMessage& req);
};
