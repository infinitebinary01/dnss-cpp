// SPDX-License-Identifier: MIT
//
#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <boost/asio.hpp>

namespace asio = boost::asio;

class MonitorServer {
public:
    MonitorServer(const std::string& addr);
    ~MonitorServer();

    void start();
    void stop();

private:
    void acceptLoop();
    void handleRequest(std::shared_ptr<asio::ip::tcp::socket> sock);
    std::string renderDashboard();
    std::string renderPrometheus();
    std::string renderJson();
    std::string renderHealth();
    std::string htmlEscape(const std::string& s);

    std::string addr_;
    int port_ = 0;
    asio::io_context ctx_;
    asio::ip::tcp::acceptor acceptor_{ctx_};
    std::thread acceptThread_;
    std::atomic<bool> running_{false};
};
