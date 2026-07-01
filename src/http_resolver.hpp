// SPDX-License-Identifier: MIT
//
#pragma once

#include "resolver.hpp"
#include "perf_monitor.hpp"
#include "auto_tuner.hpp"
#include "connection_controller.hpp"
#include <string>
#include <vector>
#include <deque>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <mutex>
#include <future>
#include <atomic>
#include <thread>

namespace asio = boost::asio;

class HttpResolver : public Resolver {
public:
    HttpResolver(const std::string& upstream, const std::string& caFile,
                 const std::string& fallback);
    HttpResolver(const std::string& primaryUpstream, const std::string& secondaryUpstream,
                 const std::string& caFile, const std::string& fallback);
    ~HttpResolver() override;

    void init() override;
    void maintain() override;
    void reload() override;
    DnsMessagePtr query(const DnsMessage& req, bool allowFanOut = true) override;

    int countConnected() const;

private:
    struct UpstreamPool;

    struct Connection {
        asio::io_context ctx;
        std::unique_ptr<asio::ssl::stream<asio::ip::tcp::socket>> stream;
        std::atomic<bool> connected{false};
        std::atomic<bool> inUse{false};
        std::string host;
        std::string port;
        std::string target;
        UpstreamPool* poolRef{nullptr}; // back-pointer for health tracking

        void close();
        bool open(const std::string& proxyHost, const std::string& proxyPort,
                  const std::string& proxyNoProxy, asio::ssl::context& sslCtx,
                  bool useProxy, boost::system::error_code& ec);
        DnsMessagePtr exchange(const std::vector<uint8_t>& wire);
    };

    struct UpstreamPool {
        std::string host;
        std::string port;
        std::string target;
        std::vector<std::unique_ptr<Connection>> connections;
        std::mutex growMutex;
        std::atomic<int> nextConn{0};

        // Per-upstream health tracking
        std::atomic<int> errors{0};
        std::atomic<int> successes{0};
        int lastErrorRatio = 0;

        void parseUrl(const std::string& url);
    };

    DnsMessagePtr doPost(const DnsMessage& req);
    DnsMessagePtr doPost(const DnsMessage& req, bool allowFanOut);
    DnsMessagePtr doPostParallel(const std::vector<uint8_t>& wire);
    DnsMessagePtr raceUpstreams(const std::vector<uint8_t>& wire);
    DnsMessagePtr doFallback(const DnsMessage& req);

    void ensurePoolSize(UpstreamPool& pool, size_t target);
    Connection* getNextConnection(UpstreamPool& pool);

    void openConnectionAsync(Connection* conn);
    void openPoolAsync(UpstreamPool& pool);
    void warmUp();
    static void enableTcpKeepalive(asio::ip::tcp::socket& socket);
    bool openFunc(const std::string& host, const std::string& port,
                  const std::string& target,
                  asio::ssl::stream<asio::ip::tcp::socket>& stream,
                  boost::system::error_code& ec);

    std::deque<UpstreamPool> pools_;
    std::string caFile_;
    std::string fallback_;

    std::string proxy_;
    std::string noProxy_;
    bool useProxy_ = false;
    std::string proxyHost_;
    std::string proxyPort_;

    asio::ssl::context sslCtx_{asio::ssl::context::tlsv12_client};

    std::atomic<bool> warmStarted_{false};
    std::thread warmThread_;
    std::atomic<bool> running_{false};

    ConnectionController connCtrl_;

    static constexpr int MAX_CONNECTIONS = 128;
    static constexpr int MAX_ERRORS_BEFORE_ROTATE = 3;
    static constexpr int CONNECT_TIMEOUT_SEC = 4;
};
