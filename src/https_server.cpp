// SPDX-License-Identifier: MIT
//
#include "https_server.hpp"
#include "logger.hpp"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <thread>
#include <memory>

HttpsServer::HttpsServer(const std::string& addr, const std::string& upstream,
                         const std::string& certFile, const std::string& keyFile,
                         bool insecure)
    : addr_(addr), upstream_(upstream), certFile_(certFile),
      keyFile_(keyFile), insecure_(insecure) {}

HttpsServer::~HttpsServer() {
    stop();
}

void HttpsServer::stop() {
    running_ = false;
    beast::error_code ec;
    acceptor_.close(ec);
    ioCtx_.stop();
}

void HttpsServer::listenAndServe() {
    LOG_INFO("HTTPS server listening on " + addr_);

    auto colon = addr_.find(':');
    std::string host = (colon != std::string::npos && colon > 0) ? addr_.substr(0, colon) : "";
    int port = (colon != std::string::npos) ? std::stoi(addr_.substr(colon + 1)) : 443;
    if (host.empty()) host = "0.0.0.0";

    beast::error_code ec;

    tcp::endpoint endpoint(asio::ip::make_address(host), port);
    acceptor_.open(endpoint.protocol(), ec);
    if (ec) { LOG_ERROR("HTTPS acceptor open: " + ec.message()); return; }
    acceptor_.set_option(asio::socket_base::reuse_address(true));
    acceptor_.bind(endpoint, ec);
    if (ec) { LOG_ERROR("HTTPS acceptor bind: " + ec.message()); return; }
    acceptor_.listen(asio::socket_base::max_listen_connections, ec);

    // SSL context (used only in TLS mode)
    std::unique_ptr<ssl::context> sslCtx;
    if (!insecure_) {
        sslCtx = std::make_unique<ssl::context>(ssl::context::tlsv12_server);
        sslCtx->use_certificate_chain_file(certFile_, ec);
        if (ec) { LOG_ERROR("Failed to load cert: " + ec.message()); return; }
        sslCtx->use_private_key_file(keyFile_, ssl::context::pem, ec);
        if (ec) { LOG_ERROR("Failed to load key: " + ec.message()); return; }
    }

    while (running_) {
        tcp::socket socket(ioCtx_);
        acceptor_.accept(socket, ec);
        if (ec) {
            if (running_) LOG_ERROR("HTTPS accept error: " + ec.message());
            break;
        }

        std::thread([this, sock = std::move(socket), &sslCtx]() mutable {
            try {
                beast::tcp_stream stream(std::move(sock));

                if (!insecure_ && sslCtx) {
                    // TLS handshake
                    ssl::stream<beast::tcp_stream&> sslStream(stream, *sslCtx);
                    sslStream.handshake(ssl::stream_base::server);

                    beast::flat_buffer buffer;
                    http::request<http::string_body> req;
                    http::read(sslStream, buffer, req);

                    if (req.method() == http::verb::post &&
                        req[http::field::content_type] == "application/dns-message") {
                        // Parse DNS query
                        auto& body = req.body();
                        auto dnsReq = DnsMessage::parse(
                            reinterpret_cast<const uint8_t*>(body.data()), body.size());

                        if (dnsReq && dnsReq->hasQuestions()) {
                            LOG_DEBUG("DoH POST from " + stream.socket().remote_endpoint().address().to_string());
                            auto& q = dnsReq->question();

                            // Forward to upstream DNS server
                            DnsMessagePtr reply;
                            try {
                                asio::io_context ctx;
                                asio::ip::udp::socket dnsSock(ctx);
                                asio::ip::udp::resolver resolv(ctx);

                                auto colon = upstream_.find(':');
                                std::string upHost = (colon != std::string::npos) ? upstream_.substr(0, colon) : upstream_;
                                std::string upPort = (colon != std::string::npos) ? upstream_.substr(colon + 1) : "53";

                                auto eps = resolv.resolve(upHost, upPort);
                                dnsSock.open(asio::ip::udp::v4());

                                auto wire = dnsReq->pack();
                                dnsSock.send_to(asio::buffer(wire), *eps.begin());

                                std::array<uint8_t, 4096> respBuf;
                                asio::ip::udp::endpoint from;
                                size_t n = dnsSock.receive_from(asio::buffer(respBuf), from);
                                reply = DnsMessage::parse(respBuf.data(), n);
                                reply->header.id = dnsReq->header.id;

                            } catch (const std::exception& e) {
                                LOG_ERROR("DNS upstream error: " + std::string(e.what()));
                                reply = DnsMessage::createError(*dnsReq, DnsRcode::ServFail);
                            }

                            auto respWire = reply->pack();
                            http::response<http::vector_body<char>> resp;
                            resp.result(http::status::ok);
                            resp.version(req.version());
                            resp.set(http::field::content_type, "application/dns-message");
                            resp.body().assign(respWire.begin(), respWire.end());
                            resp.prepare_payload();
                            http::write(sslStream, resp);
                        } else {
                            http::response<http::string_body> resp;
                            resp.result(http::status::bad_request);
                            resp.version(req.version());
                            resp.set(http::field::content_type, "text/plain");
                            resp.body() = "invalid DNS message";
                            resp.prepare_payload();
                            http::write(sslStream, resp);
                        }
                    } else {
                        http::response<http::string_body> resp;
                        resp.result(http::status::bad_request);
                        resp.version(req.version());
                        resp.set(http::field::content_type, "text/plain");
                        resp.body() = "unsupported request";
                        resp.prepare_payload();
                        http::write(sslStream, resp);
                    }

                    beast::error_code ec;
                    sslStream.shutdown(ec);

                } else {
                    // Plain HTTP
                    beast::flat_buffer buffer;
                    http::request<http::string_body> req;
                    http::read(stream, buffer, req);

                    // Handle /dns-query and /resolve endpoints
                    auto target = req.target().to_string();
                    bool validPath = (target == "/dns-query" || target == "/resolve");

                    if (validPath && req.method() == http::verb::post &&
                        req[http::field::content_type] == "application/dns-message") {

                        auto& body = req.body();
                        auto dnsReq = DnsMessage::parse(
                            reinterpret_cast<const uint8_t*>(body.data()), body.size());

                        if (dnsReq && dnsReq->hasQuestions()) {
                            auto& q = dnsReq->question();
                            LOG_DEBUG("HTTP DoH from " +
                                stream.socket().remote_endpoint().address().to_string() +
                                ": " + q.qname);

                            DnsMessagePtr reply;
                            try {
                                asio::io_context ctx;
                                asio::ip::udp::socket dnsSock(ctx);
                                asio::ip::udp::resolver resolv(ctx);

                                auto colon = upstream_.find(':');
                                std::string upHost = (colon != std::string::npos) ? upstream_.substr(0, colon) : upstream_;
                                std::string upPort = (colon != std::string::npos) ? upstream_.substr(colon + 1) : "53";

                                auto eps = resolv.resolve(upHost, upPort);
                                dnsSock.open(asio::ip::udp::v4());

                                auto wire = dnsReq->pack();
                                dnsSock.send_to(asio::buffer(wire), *eps.begin());

                                std::array<uint8_t, 4096> respBuf;
                                asio::ip::udp::endpoint from;
                                size_t n = dnsSock.receive_from(asio::buffer(respBuf), from);
                                reply = DnsMessage::parse(respBuf.data(), n);
                                reply->header.id = dnsReq->header.id;
                            } catch (const std::exception& e) {
                                LOG_ERROR("DNS upstream error: " + std::string(e.what()));
                                reply = DnsMessage::createError(*dnsReq, DnsRcode::ServFail);
                            }

                            auto respWire = reply->pack();
                            http::response<http::vector_body<char>> resp;
                            resp.result(http::status::ok);
                            resp.version(req.version());
                            resp.set(http::field::content_type, "application/dns-message");
                            resp.body().assign(respWire.begin(), respWire.end());
                            resp.prepare_payload();
                            http::write(stream, resp);
                        } else {
                            http::response<http::string_body> resp;
                            resp.result(http::status::bad_request);
                            resp.version(req.version());
                            resp.set(http::field::content_type, "text/plain");
                            resp.body() = "invalid DNS message";
                            resp.prepare_payload();
                            http::write(stream, resp);
                        }

                    } else if (validPath && req.method() == http::verb::get) {
                        http::response<http::string_body> resp;
                        resp.result(http::status::not_implemented);
                        resp.version(req.version());
                        resp.set(http::field::content_type, "text/plain");
                        resp.body() = "GET method not yet implemented";
                        resp.prepare_payload();
                        http::write(stream, resp);
                    } else {
                        http::response<http::string_body> resp;
                        resp.result(http::status::bad_request);
                        resp.version(req.version());
                        resp.set(http::field::content_type, "text/plain");
                        resp.body() = "unsupported request type";
                        resp.prepare_payload();
                        http::write(stream, resp);
                    }
                }

            } catch (const std::exception& e) {
                LOG_ERROR("HTTPS handler error: " + std::string(e.what()));
            }
        }).detach();
    }
}
