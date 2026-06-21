// SPDX-License-Identifier: MIT
//
#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <chrono>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace asio = boost::asio;

class ConnectionController {
public:
    using OpenFunc = std::function<bool(const std::string& host, const std::string& port,
                                        const std::string& target,
                                        asio::ssl::stream<asio::ip::tcp::socket>& stream,
                                        boost::system::error_code& ec)>;

    ConnectionController();
    ~ConnectionController();

    void start();
    void stop();

    // Register/unregister a connection for maintenance
    void manage(const std::string& host, const std::string& port,
                const std::string& target,
                asio::ssl::stream<asio::ip::tcp::socket>* stream,
                std::atomic<bool>* connected);
    void unmanage(asio::ssl::stream<asio::ip::tcp::socket>* stream);

    // Notify that a connection was used successfully
    void notifyUsed(asio::ssl::stream<asio::ip::tcp::socket>* stream);

    // Notify that a connection failed — triggers immediate background reconnect
    void notifyFailure(asio::ssl::stream<asio::ip::tcp::socket>* stream);

    // Called when high latency is detected — health-checks idle connections
    void probeAllIdle();

    void setOpenFunc(OpenFunc f) { openFunc_ = std::move(f); }

    // Public helper for building a health-check DNS query
    static std::vector<uint8_t> makeHealthQuery();

    int connectedCount() const { return connectedCount_.load(); }
    int totalCount() const { return totalCount_.load(); }

private:
    struct ManagedConn {
        std::string host;
        std::string port;
        std::string target;
        asio::ssl::stream<asio::ip::tcp::socket>* stream = nullptr;
        std::atomic<bool>* connected = nullptr;
        std::chrono::steady_clock::time_point lastUse;
        std::chrono::steady_clock::time_point lastCheck;
        int failures = 0;
        bool reconnectPending = false;
    };

    // Background maintenance loop
    void run();
    bool healthCheck(ManagedConn& mc);
    void reconnectAsync(size_t idx);

    static void enableTcpKeepAlive(asio::ip::tcp::socket& socket);

    std::thread thread_;
    std::atomic<bool> running_{false};

    mutable std::mutex mutex_;
    std::vector<ManagedConn> managed_;
    OpenFunc openFunc_;

    std::atomic<int> connectedCount_{0};
    std::atomic<int> totalCount_{0};

    static constexpr int HEALTH_TIMEOUT_SEC = 2;
    static constexpr auto IDLE_CHECK_INTERVAL = std::chrono::seconds(12);
    static constexpr auto MAINTAIN_INTERVAL = std::chrono::seconds(6);
};
