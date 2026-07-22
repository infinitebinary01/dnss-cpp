// SPDX-License-Identifier: MIT
//
// SystemResolver: works on any network by auto-detecting the best DNS path.
//
// Strategy (in priority order):
//   1. getaddrinfo() for A/AAAA — leverages system nsswitch/D-Bus
//      (timed; if it hangs, we detect circular dependency and skip future calls)
//   2. Raw UDP to system nameservers — works on networks with direct DNS
//   3. DoH via libcurl — works through HTTP proxies, captive portals
//   4. Network re-probe every 60s to detect connectivity changes
//
#include "system_resolver.hpp"
#include "dns_protocol.hpp"
#include "logger.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <future>
#include <curl/curl.h>

static size_t curlWriteCb(void* contents, size_t size, size_t nmemb, void* userp) {
    auto* vec = static_cast<std::vector<uint8_t>*>(userp);
    size_t total = size * nmemb;
    auto* p = static_cast<const uint8_t*>(contents);
    vec->insert(vec->end(), p, p + total);
    return total;
}

SystemResolver::SystemResolver() {
    detectSystemDns();
    detectDohUpstreams();
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

SystemResolver::~SystemResolver() {
    running_ = false;
    if (probeThread_.joinable()) probeThread_.join();
    curl_global_cleanup();
}

void SystemResolver::detectSystemDns() {
    servers_.clear();

    std::ifstream resolv("/etc/resolv.conf");
    if (resolv.is_open()) {
        std::string line;
        while (std::getline(resolv, line)) {
            if (line.empty() || line[0] == '#') continue;
            std::istringstream iss(line);
            std::string directive;
            iss >> directive;
            if (directive != "nameserver") continue;
            std::string ip;
            iss >> ip;
            if (ip.empty() || ip.find(':') != std::string::npos) continue;
            // Collect ALL nameservers including loopback — we'll try them for UDP
            bool isLoopback = (ip.substr(0, 4) == "127.");
            if (!isLoopback) {
                servers_.push_back({ip, 53});
            }
        }
    }

    // Well-known public DNS as fallback
    bool has1111 = false, has8888 = false;
    for (auto& s : servers_) {
        if (s.ip == "1.1.1.1") has1111 = true;
        if (s.ip == "8.8.8.8") has8888 = true;
    }
    if (!has1111) servers_.push_back({"1.1.1.1", 53});
    if (!has8888) servers_.push_back({"8.8.8.8", 53});

    for (auto& s : servers_)
        LOG_INFO("SystemResolver: nameserver " + s.ip + ":" + std::to_string(s.port));

    detected_ = true;
}

void SystemResolver::detectDohUpstreams() {
    dohUrls_.push_back("https://dns.google/dns-query");
    dohUrls_.push_back("https://cloudflare-dns.com/dns-query");
    dohUrls_.push_back("https://dns.quad9.net/dns-query");
}

bool SystemResolver::probeUdp() {
    if (servers_.empty()) return false;

    auto probeQuery = DnsMessage::createQuery("google.com", DnsType::A);
    if (!probeQuery) return false;
    auto wire = probeQuery->pack();

    for (auto& server : servers_) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;

        struct timeval tv{};
        tv.tv_sec = 2;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server.port);
        if (inet_pton(AF_INET, server.ip.c_str(), &addr.sin_addr) != 1) {
            close(sock);
            continue;
        }

        ssize_t sent = sendto(sock, wire.data(), wire.size(), 0,
                              reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        if (sent < 0) { close(sock); continue; }

        uint8_t buf[4096];
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        close(sock);

        if (n >= 12) return true;
    }
    return false;
}

void SystemResolver::probeLoop() {
    udpWorks_ = probeUdp();

    // Probe getaddrinfo with a short timeout
    if (!getaddrinfoTested_) {
        auto probeQuery = DnsMessage::createQuery("google.com", DnsType::A);
        if (probeQuery) {
            auto fut = std::async(std::launch::async, [this, &probeQuery]() {
                return queryGetaddrinfo(*probeQuery);
            });
            if (fut.wait_for(std::chrono::seconds(2)) == std::future_status::ready) {
                auto result = fut.get();
                getaddrinfoWorks_ = (result && !result->answers.empty());
            } else {
                getaddrinfoWorks_ = false;
                LOG_INFO("SystemResolver: getaddrinfo timed out (circular dependency)");
            }
            getaddrinfoTested_ = true;
        }
    }

    LOG_INFO("SystemResolver: " +
             std::string(udpWorks_ ? "UDP ok" : "UDP unavailable") + ", " +
             std::string(getaddrinfoWorks_ ? "getaddrinfo ok" : "getaddrinfo unavailable") +
             " -> " + std::string(udpWorks_ || getaddrinfoWorks_ ? "system DNS" : "DoH fallback"));

    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(60));
        if (!running_) break;
        bool nowUdp = probeUdp();
        if (nowUdp != udpWorks_.load()) {
            udpWorks_ = nowUdp;
            LOG_INFO("SystemResolver: network changed -> UDP " +
                     std::string(nowUdp ? "available" : "lost"));
        }
    }
}

void SystemResolver::init() {
    if (!detected_) {
        detectSystemDns();
        detectDohUpstreams();
    }
    running_ = true;
    probeThread_ = std::thread(&SystemResolver::probeLoop, this);
}

DnsMessagePtr SystemResolver::query(const DnsMessage& req, bool allowFanOut) {
    if (req.questions.empty())
        return DnsMessage::createError(req, DnsRcode::FormErr);

    const auto& q = req.questions[0];

    // Strategy 1: getaddrinfo for A/AAAA (fast, uses system nsswitch/D-Bus)
    if ((q.qtype == DnsType::A || q.qtype == DnsType::AAAA)) {
        if (!getaddrinfoTested_) {
            // First query: try getaddrinfo with timeout
            auto result = queryGetaddrinfo(req);
            if (result && !result->answers.empty()) {
                getaddrinfoWorks_ = true;
                getaddrinfoTested_ = true;
                return result;
            }
        } else if (getaddrinfoWorks_) {
            auto result = queryGetaddrinfo(req);
            if (result && !result->answers.empty())
                return result;
        }
    }

    // Strategy 2: raw UDP to system DNS
    if (udpWorks_) {
        auto reply = queryUdp(req);
        if (reply && reply->header.rcode() != DnsRcode::ServFail)
            return reply;
    }

    // Strategy 3: DoH via libcurl (auto-detects proxy from env vars)
    auto reply = queryDoh(req);
    if (reply) return reply;

    // Last resort: try UDP even if probe said down
    if (!udpWorks_) {
        auto udpReply = queryUdp(req);
        if (udpReply) return udpReply;
    }

    return DnsMessage::createError(req, DnsRcode::ServFail);
}

DnsMessagePtr SystemResolver::queryGetaddrinfo(const DnsMessage& req) {
    const auto& q = req.questions[0];

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = nullptr;
    int rc = getaddrinfo(q.qname.c_str(), nullptr, &hints, &result);

    auto reply = DnsMessage::createReply(req);

    if (rc != 0 || !result) {
        return reply;
    }

    uint32_t ttl = 300;

    for (struct addrinfo* rp = result; rp; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET && q.qtype == DnsType::A) {
            auto* sin = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
            DnsResourceRecord rr;
            rr.name = q.qname;
            rr.type = DnsType::A;
            rr.rclass = 1;
            rr.ttl = ttl;
            rr.rdata.resize(4);
            std::memcpy(rr.rdata.data(), &sin->sin_addr, 4);
            reply->answers.push_back(std::move(rr));
        } else if (rp->ai_family == AF_INET6 && q.qtype == DnsType::AAAA) {
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
            DnsResourceRecord rr;
            rr.name = q.qname;
            rr.type = DnsType::AAAA;
            rr.rclass = 1;
            rr.ttl = ttl;
            rr.rdata.resize(16);
            std::memcpy(rr.rdata.data(), &sin6->sin6_addr, 16);
            reply->answers.push_back(std::move(rr));
        }
    }

    freeaddrinfo(result);

    if (reply->answers.empty())
        reply->header.setRcode(DnsRcode::NXDomain);

    return reply;
}

DnsMessagePtr SystemResolver::queryUdp(const DnsMessage& req) {
    if (servers_.empty()) return nullptr;

    auto wire = req.pack();

    for (auto& server : servers_) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;

        struct timeval tv{};
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server.port);
        if (inet_pton(AF_INET, server.ip.c_str(), &addr.sin_addr) != 1) {
            close(sock);
            continue;
        }

        ssize_t sent = sendto(sock, wire.data(), wire.size(), 0,
                              reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
        if (sent < 0) {
            close(sock);
            continue;
        }

        uint8_t buf[4096];
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        close(sock);

        if (n < 12) continue;

        try {
            auto reply = DnsMessage::parse(buf, n);
            if (reply) {
                reply->header.id = req.header.id;
                return reply;
            }
        } catch (...) {
            continue;
        }
    }

    return nullptr;
}

DnsMessagePtr SystemResolver::queryDoh(const DnsMessage& req) {
    auto wire = req.pack();

    for (auto& dohUrl : dohUrls_) {
        CURL* curl = curl_easy_init();
        if (!curl) continue;

        std::vector<uint8_t> responseBody;

        curl_easy_setopt(curl, CURLOPT_URL, dohUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, wire.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)wire.size());

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/dns-message");
        headers = curl_slist_append(headers, "Accept: application/dns-message");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK && responseBody.size() >= 12) {
            try {
                auto reply = DnsMessage::parse(responseBody.data(), responseBody.size());
                if (reply) {
                    reply->header.id = req.header.id;
                    return reply;
                }
            } catch (...) {
            }
        } else if (res != CURLE_OK) {
            LOG_DEBUG("SystemResolver: DoH " + dohUrl + " failed: " + curl_easy_strerror(res));
        }
    }

    return nullptr;
}
