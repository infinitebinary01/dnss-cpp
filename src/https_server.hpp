// SPDX-License-Identifier: MIT
//
#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include "dns_protocol.hpp"

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;

class HttpsServer {
public:
    HttpsServer(const std::string& addr, const std::string& upstream,
                const std::string& certFile, const std::string& keyFile,
                bool insecure);
    ~HttpsServer();

    void listenAndServe();
    void stop();

private:
    std::string addr_;
    std::string upstream_;
    std::string certFile_;
    std::string keyFile_;
    bool insecure_;

    asio::io_context ioCtx_;
    tcp::acceptor acceptor_{ioCtx_};
    std::atomic<bool> running_{true};
};
