// SPDX-License-Identifier: MIT
//
#include "http_resolver.hpp"
#include "logger.hpp"
#include "dns_protocol.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include <thread>
#include <chrono>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <memory>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <algorithm>
#include <future>

using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

// Try to detect system proxy from GNOME gsettings
static std::string detectGnomeProxy() {
    std::array<char, 256> buf;
    std::string mode;
    {
        std::unique_ptr<FILE, decltype(&pclose)> pipe(
            popen("gsettings get org.gnome.system.proxy mode 2>/dev/null", "r"), pclose);
        if (pipe && fgets(buf.data(), buf.size(), pipe.get()))
            mode = buf.data();
    }
    while (!mode.empty() && (mode.back() == '\n' || mode.back() == '\r'))
        mode.pop_back();
    if (mode != "'manual'") return {};

    std::string host, port;
    {
        std::unique_ptr<FILE, decltype(&pclose)> pipe(
            popen("gsettings get org.gnome.system.proxy.https host 2>/dev/null", "r"), pclose);
        if (pipe && fgets(buf.data(), buf.size(), pipe.get()))
            host = buf.data();
    }
    {
        std::unique_ptr<FILE, decltype(&pclose)> pipe(
            popen("gsettings get org.gnome.system.proxy.https port 2>/dev/null", "r"), pclose);
        if (pipe && fgets(buf.data(), buf.size(), pipe.get()))
            port = buf.data();
    }
    auto trim = [](std::string& s) {
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == '\''))
            s.pop_back();
        while (!s.empty() && s.front() == '\'') s.erase(0, 1);
    };
    trim(host);
    trim(port);
    if (!host.empty() && !port.empty())
        return "http://" + host + ":" + port + "/";
    return {};
}

HttpResolver::HttpResolver(const std::string& upstream, const std::string& caFile,
                           const std::string& fallback)
    : upstream_(upstream), caFile_(caFile), fallback_(fallback),
      sslCtx_(asio::ssl::context::tlsv12_client) {
    const char* envProxy = std::getenv("https_proxy");
    if (!envProxy) envProxy = std::getenv("HTTPS_PROXY");
    if (!envProxy) envProxy = std::getenv("http_proxy");
    if (!envProxy) envProxy = std::getenv("HTTP_PROXY");
    if (envProxy) proxy_ = envProxy;
    const char* noProxy = std::getenv("no_proxy");
    if (noProxy) noProxy_ = noProxy;

    // If no proxy from env, try system settings (GNOME/KDE)
    if (proxy_.empty()) {
        auto gnome = detectGnomeProxy();
        if (!gnome.empty()) {
            proxy_ = gnome;
            LOG_INFO("Auto-detected proxy: " + proxy_);
        }
    }
}

HttpResolver::~HttpResolver() {
    running_ = false;
    connCtrl_.stop();
    if (warmThread_.joinable())
        warmThread_.join();
    for (auto& c : connections_) c->close();
}

static bool matchesNoProxy(const std::string& host, const std::string& noProxy) {
    if (noProxy.empty()) return false;
    std::istringstream ss(noProxy);
    std::string entry;
    while (std::getline(ss, entry, ',')) {
        while (!entry.empty() && entry[0] == ' ') entry.erase(0, 1);
        while (!entry.empty() && entry.back() == ' ') entry.pop_back();
        if (entry.empty()) continue;
        if (entry == host || entry == "*") return true;
    }
    return false;
}

static void parseProxyUrl(const std::string& proxy, std::string& host, std::string& port) {
    auto pSlash = proxy.find("://");
    size_t pStart = (pSlash != std::string::npos) ? pSlash + 3 : 0;
    host = proxy.substr(pStart);
    while (!host.empty() && host.back() == '/') host.pop_back();
    port = "8000";
    auto pColon = host.rfind(':');
    if (pColon != std::string::npos) {
        port = host.substr(pColon + 1);
        host = host.substr(0, pColon);
    }
}

static void setSocketTimeout(tcp::socket& socket, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static bool parseUpstreamUrl(const std::string& upstream,
                             std::string& scheme, std::string& host,
                             std::string& port, std::string& target) {
    auto slash = upstream.find("://");
    scheme = "https";
    size_t start = 0;
    if (slash != std::string::npos) {
        scheme = upstream.substr(0, slash);
        start = slash + 3;
    }
    auto path_start = upstream.find('/', start);
    if (path_start != std::string::npos) {
        host = upstream.substr(start, path_start - start);
        target = upstream.substr(path_start);
    } else {
        host = upstream.substr(start);
        target = "/dns-query";
    }
    auto colon = host.find(':');
    if (colon != std::string::npos) {
        port = host.substr(colon + 1);
        host = host.substr(0, colon);
    } else {
        port = (scheme == "https") ? "443" : "80";
    }
    return true;
}

static size_t readHttpBody(const std::vector<uint8_t>& rawResp,
                           std::string& bodyOut, std::string& statusOut) {
    std::string respStr(reinterpret_cast<const char*>(rawResp.data()), rawResp.size());
    auto headerEnd = respStr.find("\r\n\r\n");
    if (headerEnd == std::string::npos) return 0;

    std::string headerPart = respStr.substr(0, headerEnd);
    statusOut = headerPart.substr(0, headerPart.find('\r'));

    if (statusOut.find("200") == std::string::npos) {
        bodyOut = respStr.substr(headerEnd + 4);
        return headerEnd + 4;
    }

    std::string headLow = headerPart;
    for (auto& c : headLow) c = tolower(c);
    auto clPos = headLow.find("content-length: ");
    if (clPos != std::string::npos) {
        clPos += 16;
        auto clEnd = headLow.find("\r\n", clPos);
        size_t contentLen = std::stoul(headerPart.substr(clPos, clEnd - clPos));
        bodyOut = respStr.substr(headerEnd + 4, contentLen);
        return headerEnd + 4 + contentLen;
    }

    if (headLow.find("chunked") != std::string::npos) {
        std::string body = respStr.substr(headerEnd + 4);
        std::string decoded;
        size_t pos = 0;
        while (pos < body.size()) {
            auto crlf = body.find("\r\n", pos);
            if (crlf == std::string::npos) break;
            size_t chunkSize = std::stoul(body.substr(pos, crlf - pos), nullptr, 16);
            if (chunkSize == 0) break;
            size_t chunkStart = crlf + 2;
            decoded.append(body.data() + chunkStart, chunkSize);
            pos = chunkStart + chunkSize + 2;
        }
        bodyOut = std::move(decoded);
        return headerEnd + 4;
    }

    bodyOut = respStr.substr(headerEnd + 4);
    return headerEnd + 4;
}

// Shared open logic that ConnectionController can also call
bool HttpResolver::openFunc(const std::string& host, const std::string& port,
                             const std::string& target,
                             asio::ssl::stream<asio::ip::tcp::socket>& stream,
                             boost::system::error_code& ec) {
    asio::io_context tmpCtx;
    {
        boost::system::error_code openEc;
        stream.next_layer().open(asio::ip::tcp::v4(), openEc);
        if (!openEc) {
            setSocketTimeout(stream.next_layer(), 2);
            { int syn = 2; setsockopt(stream.next_layer().native_handle(), IPPROTO_TCP, TCP_SYNCNT, &syn, sizeof(syn)); }
        }
    }

    if (useProxy_) {
        tcp::resolver resolver(tmpCtx);
        auto proxyEp = resolver.resolve(proxyHost_, proxyPort_, ec);
        if (!ec) {
            asio::connect(stream.next_layer(), proxyEp.begin(), proxyEp.end(), ec);
        }
        if (!ec) {
            { int flag = 1; setsockopt(stream.next_layer().native_handle(), SOL_TCP, TCP_NODELAY, &flag, sizeof(flag)); }

            std::string connectReq = "CONNECT " + host + ":" + port + " HTTP/1.1\r\n"
                                     "Host: " + host + ":" + port + "\r\n"
                                     "User-Agent: dnss-cpp/0.1\r\n"
                                     "Proxy-Connection: Keep-Alive\r\n"
                                     "\r\n";
            asio::write(stream.next_layer(), asio::buffer(connectReq), ec);
        }
        if (!ec) {
            std::array<char, 1024> buf;
            size_t n = stream.next_layer().read_some(asio::buffer(buf), ec);
            if (!ec) {
                std::string resp(buf.data(), n);
                if (resp.find("200") == std::string::npos)
                    ec = boost::asio::error::connection_refused;
            }
        }
        if (!ec) {
            if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
                ec = boost::asio::error::no_protocol_option;
        }
        if (!ec) {
            stream.handshake(asio::ssl::stream_base::client, ec);
        }
        if (ec) {
            boost::system::error_code closeEc;
            stream.next_layer().close(closeEc);
        } else {
            return true;
        }
    }

    tcp::resolver resolver(tmpCtx);
    auto results = resolver.resolve(host, port, ec);
    if (ec) return false;

    asio::connect(stream.next_layer(), results.begin(), results.end(), ec);
    if (ec) return false;

    { int flag = 1; setsockopt(stream.next_layer().native_handle(), SOL_TCP, TCP_NODELAY, &flag, sizeof(flag)); }

    if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str())) {
        ec = boost::asio::error::no_protocol_option;
        return false;
    }
    stream.handshake(asio::ssl::stream_base::client, ec);
    if (ec) return false;

    return true;
}

static void prewarmCache(HttpResolver* resolver);

void HttpResolver::init() {
    sslCtx_.set_default_verify_paths();
    sslCtx_.set_verify_mode(asio::ssl::verify_peer);

    parseUpstreamUrl(upstream_, upstreamScheme_, upstreamHost_,
                     upstreamPort_, upstreamTarget_);

    useProxy_ = !proxy_.empty() && !matchesNoProxy(upstreamHost_, noProxy_);
    if (useProxy_) parseProxyUrl(proxy_, proxyHost_, proxyPort_);

    LOG_INFO("HttpResolver: " + upstream_
             + (useProxy_ ? " via proxy=" + proxyHost_ + ":" + proxyPort_ : ""));

    // Start connection controller with open callback
    connCtrl_.setOpenFunc([this](const std::string& host, const std::string& port,
                                  const std::string& target,
                                  asio::ssl::stream<asio::ip::tcp::socket>& stream,
                                  boost::system::error_code& ec) -> bool {
        return openFunc(host, port, target, stream, ec);
    });
    connCtrl_.start();

    // Start background connection warm-up
    running_ = true;
    warmThread_ = std::thread([this]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        warmUp();
    });
}

void HttpResolver::maintain() {}

void HttpResolver::Connection::close() {
    if (stream) {
        boost::system::error_code ec;
        stream->next_layer().close(ec);
        stream.reset();
    }
    connected = false;
}

bool HttpResolver::Connection::open(const std::string& proxyHost,
                                     const std::string& proxyPort,
                                     const std::string& proxyNoProxy,
                                     asio::ssl::context& sslCtx,
                                     bool useProxy,
                                     boost::system::error_code& ec) {
    close();
    stream = std::make_unique<asio::ssl::stream<tcp::socket>>(ctx, sslCtx);
    boost::system::error_code openEc;
    stream->next_layer().open(asio::ip::tcp::v4(), openEc);
    if (openEc) { ec = openEc; return false; }
    setSocketTimeout(stream->next_layer(), 2);
    { int syn = 2; setsockopt(stream->next_layer().native_handle(), IPPROTO_TCP, TCP_SYNCNT, &syn, sizeof(syn)); }

    bool bypass = useProxy && matchesNoProxy(host, proxyNoProxy);
    if (useProxy && !bypass) {
        tcp::resolver resolver(ctx);
        auto proxyEp = resolver.resolve(proxyHost, proxyPort, ec);
        if (!ec) {
            asio::connect(stream->next_layer(), proxyEp.begin(), proxyEp.end(), ec);
        }
        if (!ec) {
            { int flag = 1; setsockopt(stream->next_layer().native_handle(), SOL_TCP, TCP_NODELAY, &flag, sizeof(flag)); }

            std::string connectReq = "CONNECT " + host + ":" + port + " HTTP/1.1\r\n"
                                     "Host: " + host + ":" + port + "\r\n"
                                     "User-Agent: dnss-cpp/0.1\r\n"
                                     "Proxy-Connection: Keep-Alive\r\n"
                                     "\r\n";
            asio::write(stream->next_layer(), asio::buffer(connectReq), ec);
        }
        if (!ec) {
            std::array<char, 1024> buf;
            size_t n = stream->next_layer().read_some(asio::buffer(buf), ec);
            if (!ec) {
                std::string resp(buf.data(), n);
                if (resp.find("200") == std::string::npos)
                    ec = boost::asio::error::connection_refused;
            }
        }
        if (!ec) {
            if (!SSL_set_tlsext_host_name(stream->native_handle(), host.c_str()))
                ec = boost::asio::error::no_protocol_option;
        }
        if (!ec) {
            stream->handshake(asio::ssl::stream_base::client, ec);
        }
        if (!ec) {
            connected = true;
            return true;
        }
    }

    if (ec) {
        close();
        stream = std::make_unique<asio::ssl::stream<tcp::socket>>(ctx, sslCtx);
        boost::system::error_code reOpenEc;
        stream->next_layer().open(asio::ip::tcp::v4(), reOpenEc);
        if (reOpenEc) { ec = reOpenEc; return false; }
        setSocketTimeout(stream->next_layer(), 2);
        { int syn = 2; setsockopt(stream->next_layer().native_handle(), IPPROTO_TCP, TCP_SYNCNT, &syn, sizeof(syn)); }
    }

    tcp::resolver resolver(ctx);
    auto results = resolver.resolve(host, port, ec);
    if (ec) return false;

    asio::connect(stream->next_layer(), results.begin(), results.end(), ec);
    if (ec) return false;

    { int flag = 1; setsockopt(stream->next_layer().native_handle(), SOL_TCP, TCP_NODELAY, &flag, sizeof(flag)); }

    if (!SSL_set_tlsext_host_name(stream->native_handle(), host.c_str())) {
        ec = boost::asio::error::no_protocol_option;
        return false;
    }
    stream->handshake(asio::ssl::stream_base::client, ec);
    if (ec) return false;

    connected = true;
    return true;
}

DnsMessagePtr HttpResolver::Connection::exchange(const std::vector<uint8_t>& wire) {
    if (!stream || !connected.load()) return nullptr;

    boost::system::error_code ec;

    // Aggressive timeout to cut tail latency — fail fast, retry on next connection
    setSocketTimeout(stream->next_layer(), 1); // socket read/write timeout

    std::ostringstream oss;
    oss << "POST " << target << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "User-Agent: dnss-cpp/0.1\r\n"
        << "Content-Type: application/dns-message\r\n"
        << "Accept: application/dns-message\r\n"
        << "Content-Length: " << wire.size() << "\r\n"
        << "Connection: keep-alive\r\n"
        << "\r\n";
    std::string header = oss.str();

    std::vector<asio::const_buffer> sendBufs;
    sendBufs.push_back(asio::buffer(header));
    sendBufs.push_back(asio::buffer(wire));
    asio::write(*stream, sendBufs, ec);
    if (ec) { return nullptr; }

    std::vector<uint8_t> respBuf;
    respBuf.reserve(4096);
    bool headerDone = false;
    size_t contentLength = 0;
    bool isChunked = false;

    while (true) {
        std::array<uint8_t, 4096> chunk;
        size_t n = stream->read_some(asio::buffer(chunk), ec);
        if (ec == boost::asio::error::eof) break;
        if (ec) { return nullptr; }

        size_t oldSize = respBuf.size();
        respBuf.resize(oldSize + n);
        memcpy(respBuf.data() + oldSize, chunk.data(), n);

        if (!headerDone) {
            std::string respStr(reinterpret_cast<char*>(respBuf.data()), respBuf.size());
            auto headerEnd = respStr.find("\r\n\r\n");
            if (headerEnd != std::string::npos) {
                headerDone = true;
                std::string headerPart = respStr.substr(0, headerEnd);
                std::string lowHead = headerPart;
                for (auto& c : lowHead) c = tolower(c);
                auto clPos = lowHead.find("content-length: ");
                if (clPos != std::string::npos) {
                    clPos += 16;
                    auto clEnd = lowHead.find("\r\n", clPos);
                    contentLength = std::stoul(headerPart.substr(clPos, clEnd - clPos));
                }
                if (lowHead.find("chunked") != std::string::npos) {
                    isChunked = true;
                }
                if (contentLength > 0) {
                    size_t bodySoFar = respBuf.size() - (headerEnd + 4);
                    if (bodySoFar >= contentLength) break;
                }
                if (!isChunked && contentLength == 0) break;
            }
        } else {
            if (contentLength > 0) {
                std::string tmpStr(reinterpret_cast<char*>(respBuf.data()), respBuf.size());
                auto he = tmpStr.find("\r\n\r\n");
                if (he != std::string::npos) {
                    size_t bodySoFar = respBuf.size() - (he + 4);
                    if (bodySoFar >= contentLength) break;
                }
            } else if (!isChunked) {
                break;
            }
        }
    }

    if (respBuf.empty()) {
        return nullptr;
    }

    std::string body, statusLine;
    readHttpBody(respBuf, body, statusLine);

    if (statusLine.empty()) {
        LOG_ERROR("DoH upstream error: empty status line, raw=" +
                  std::string(reinterpret_cast<char*>(respBuf.data()),
                  std::min(respBuf.size(), size_t(200))));
        return nullptr;
    }
    if (statusLine.find("200") == std::string::npos) {
        LOG_ERROR("DoH upstream error: " + statusLine);
        return nullptr;
    }
    if (body.empty()) {
        LOG_ERROR("DoH empty response body");
        return nullptr;
    }

    auto t0 = std::chrono::steady_clock::now();
    auto reply = DnsMessage::parse(
        reinterpret_cast<const uint8_t*>(body.data()), body.size());
    auto dt = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0);
    PerfMonitor::instance().recordLatency(dt);

    return reply;
}

DnsMessagePtr HttpResolver::query(const DnsMessage& req) {
    PerfMonitor::instance().recordConnUse(countConnected(), connections_.size());
    auto t0 = std::chrono::steady_clock::now();
    auto result = doPost(req);
    if (!result && !fallback_.empty()) {
        LOG_DEBUG("DoH failed, trying fallback DNS to " + fallback_);
        result = doFallback(req);
    }
    auto dt = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - t0);

    // Trigger health check probe on idle connections when latency spikes
    if (dt.count() > 500000) {
        std::thread([this]() {
            connCtrl_.probeAllIdle();
        }).detach();
    }

    PerfMonitor::instance().recordLatency(dt);
    if (!result) PerfMonitor::instance().recordError();
    return result;
}

DnsMessagePtr HttpResolver::doFallback(const DnsMessage& req) {
    auto wire = req.pack();

    auto colon = fallback_.find(':');
    std::string host = (colon != std::string::npos) ? fallback_.substr(0, colon) : fallback_;
    std::string port = (colon != std::string::npos) ? fallback_.substr(colon + 1) : "53";
    if (host.empty()) host = "8.8.8.8";

    try {
        asio::io_context ctx;
        udp::socket sock(ctx);
        udp::resolver resolv(ctx);
        auto eps = resolv.resolve(host, port);
        sock.open(udp::v4());
        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sock.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        sock.send_to(asio::buffer(wire), *eps.begin());

        std::array<uint8_t, 4096> respBuf;
        udp::endpoint from;
        size_t n = sock.receive_from(asio::buffer(respBuf), from);

        auto reply = DnsMessage::parse(respBuf.data(), n);
        if (reply) reply->header.id = req.header.id;
        return reply;
    } catch (const std::exception& e) {
        LOG_ERROR("Fallback DNS error: " + std::string(e.what()));
        return nullptr;
    }
}

void HttpResolver::ensurePoolSize(size_t target) {
    if (connections_.size() >= target) return;
    std::lock_guard<std::mutex> lock(growMutex_);
    while (connections_.size() < target) {
        auto conn = std::make_unique<Connection>();
        conn->host = upstreamHost_;
        conn->port = upstreamPort_;
        conn->target = upstreamTarget_;
        connections_.push_back(std::move(conn));
    }
}

int HttpResolver::countConnected() const {
    return connCtrl_.connectedCount();
}

void HttpResolver::openConnectionAsync(Connection* conn) {
    if (conn->inUse.exchange(true)) return;
    if (conn->stream) connCtrl_.unmanage(conn->stream.get());
    std::thread([conn, this]() {
        boost::system::error_code ec;
        conn->open(proxyHost_, proxyPort_, noProxy_, sslCtx_, useProxy_, ec);
        if (ec) conn->connected = false;
        if (conn->stream) {
            connCtrl_.manage(conn->host, conn->port, conn->target,
                             conn->stream.get(), &conn->connected);
        }
        conn->inUse = false;
    }).detach();
}

void HttpResolver::warmUp() {
    int target = AutoTuner::instance().recommendedConnections();
    ensurePoolSize(static_cast<size_t>(target));

    std::vector<std::future<bool>> futures;
    for (auto& conn : connections_) {
        futures.push_back(std::async(std::launch::async, [conn = conn.get(), this]() {
            if (conn->stream) connCtrl_.unmanage(conn->stream.get());
            boost::system::error_code ec;
            bool ok = conn->open(proxyHost_, proxyPort_, noProxy_, sslCtx_, useProxy_, ec);
            if (conn->stream) {
                connCtrl_.manage(conn->host, conn->port, conn->target,
                                 conn->stream.get(), &conn->connected);
            }
            if (!ok) conn->connected = false;
            return ok;
        }));
    }
    // Wait for all opens, then validate with a quick health check
    std::thread([this, futures = std::move(futures)]() {
        for (auto& f : futures) f.wait();
        // Validate each connection with a real DNS query
        // (connections that report 'connected' but are dead will fail here)
        auto healthWire = ConnectionController::makeHealthQuery();
        for (auto& conn : connections_) {
            if (!conn->connected.load()) continue;
            conn->inUse = true;
            auto reply = conn->exchange(healthWire);
            if (!reply) {
                connCtrl_.notifyFailure(conn->stream.get());
            } else {
                connCtrl_.notifyUsed(conn->stream.get());
            }
            conn->inUse = false;
        }
        LOG_INFO("WarmUp: " + std::to_string(countConnected()) + "/" +
                 std::to_string(connections_.size()) + " connections ready");
    }).detach();
}

DnsMessagePtr HttpResolver::doPost(const DnsMessage& req) {
    auto wire = req.pack();

    int targetConns = AutoTuner::instance().recommendedConnections();
    bool fanOut = AutoTuner::instance().fanOutEnabled();

    // Grow pool if needed
    ensurePoolSize(static_cast<size_t>(targetConns));

    // Parallel fan-out: race all connected connections, take the first to respond
    if (fanOut) {
        auto result = doPostParallel(wire);
        if (result) return result;
        // parallel failed, fall through to single-connection retry
    }

    // Try connected connections round-robin (fail fast — at most 5 tries)
    int numConns = connections_.size();
    for (int attempt = 0; attempt < std::min(numConns * 2, 5); ++attempt) {
        int idx = nextConn_.fetch_add(1, std::memory_order_relaxed) % numConns;
        auto& conn = connections_[idx];
        if (!conn->connected.load()) continue;
        if (conn->inUse.exchange(true)) continue;

        auto reply = conn->exchange(wire);
        if (reply) {
            conn->inUse = false;
            connCtrl_.notifyUsed(conn->stream.get());
            return reply;
        }
        connCtrl_.notifyFailure(conn->stream.get());
        conn->inUse = false;
    }

    // No connected connections — open just 1 synchronously, rest in background
    for (auto& conn : connections_) {
        if (conn->connected.load()) continue;
        if (conn->inUse.exchange(true)) continue;

        if (conn->stream) connCtrl_.unmanage(conn->stream.get());
        boost::system::error_code ec;
        conn->open(proxyHost_, proxyPort_, noProxy_, sslCtx_, useProxy_, ec);
        if (conn->stream) {
            connCtrl_.manage(conn->host, conn->port, conn->target,
                             conn->stream.get(), &conn->connected);
        }
        if (ec) {
            conn->inUse = false;
            continue;
        }

        auto reply = conn->exchange(wire);
        if (reply) {
            conn->inUse = false;
            connCtrl_.notifyUsed(conn->stream.get());
            // Open remaining connections in background
            for (auto& c : connections_) {
                if (!c->connected.load() && c.get() != conn.get())
                    openConnectionAsync(c.get());
            }
            return reply;
        }
        connCtrl_.notifyFailure(conn->stream.get());
        conn->inUse = false;
        break;
    }

    return nullptr;
}

DnsMessagePtr HttpResolver::doPostParallel(const std::vector<uint8_t>& wire) {
    // Fan-out: try at most 3 connected connections in round-robin
    // This limits tail latency — if 3 connections fail, fall through to sync open
    int numConns = connections_.size();
    int startIdx = nextConn_.fetch_add(1, std::memory_order_relaxed) % numConns;
    int tried = 0;

    for (int i = 0; i < numConns && tried < 3; ++i) {
        int idx = (startIdx + i) % numConns;
        auto& conn = connections_[idx];
        if (!conn->connected.load()) continue;
        if (conn->inUse.exchange(true)) continue;
        tried++;

        auto reply = conn->exchange(wire);

        if (reply) {
            conn->inUse = false;
            connCtrl_.notifyUsed(conn->stream.get());
            return reply;
        }
        connCtrl_.notifyFailure(conn->stream.get());
        conn->inUse = false;
    }

    return nullptr;
}
