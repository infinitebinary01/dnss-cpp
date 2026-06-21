// SPDX-License-Identifier: MIT
//
#pragma once

#include <string>
#include <memory>
#include <mutex>
#include <atomic>
#include <boost/asio.hpp>
#include "dns_protocol.hpp"
#include "resolver.hpp"
#include "domain_map.hpp"

namespace asio = boost::asio;
namespace sys = boost::system;
using tcp = asio::ip::tcp;

class DnsServer {
public:
    DnsServer(const std::string& addr,
              std::shared_ptr<Resolver> resolver,
              const std::string& unqUpstream,
              DomainMap overrides);
    ~DnsServer();

    void listenAndServe();
    void stop();

private:
    void startUdpReceive();
    void onUdpReceive(sys::error_code ec, size_t len);
    void handleQuery(const uint8_t* data, size_t len,
                     asio::ip::udp::endpoint remote,
                     std::shared_ptr<Resolver> resolver,
                     DomainMap overrides,
                     std::string unqUpstream);

    std::string addr_;
    std::shared_ptr<Resolver> resolver_;
    std::string unqUpstream_;
    DomainMap overrides_;

    asio::io_context ioCtx_;
    asio::ip::udp::socket udpSocket_{ioCtx_};
    tcp::acceptor tcpAcceptor_{ioCtx_};

    std::array<uint8_t, 4096> recvBuf_;
    asio::ip::udp::endpoint remoteEndpoint_;

    std::atomic<bool> running_{true};
};
