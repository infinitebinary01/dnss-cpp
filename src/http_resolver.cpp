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
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <memory>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <algorithm>
#include <future>
#include <netinet/tcp.h>

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

static void setSocketTimeoutMs(tcp::socket& socket, int ms) {
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void HttpResolver::UpstreamPool::parseUrl(const std::string& url) {
    auto slash = url.find("://");
    auto start = (slash != std::string::npos) ? slash + 3 : 0;
    auto pathStart = url.find('/', start);
    if (pathStart != std::string::npos) {
        host = url.substr(start, pathStart - start);
        target = url.substr(pathStart);
    } else {
        host = url.substr(start);
        target = "/dns-query";
    }
    auto colon = host.find(':');
    if (colon != std::string::npos) {
        port = host.substr(colon + 1);
        host = host.substr(0, colon);
    } else {
        port = "443";
    }
}

HttpResolver::HttpResolver(const std::string& upstream, const std::string& caFile,
                           const std::string& fallback)
    : caFile_(caFile), fallback_(fallback),
      sslCtx_(asio::ssl::context::tlsv12_client) {
    pools_.emplace_back();
    pools_.back().parseUrl(upstream);
    const char* envProxy = std::getenv("https_proxy");
    if (!envProxy) envProxy = std::getenv("HTTPS_PROXY");
    if (!envProxy) envProxy = std::getenv("http_proxy");
    if (!envProxy) envProxy = std::getenv("HTTP_PROXY");
    if (envProxy) proxy_ = envProxy;
    const char* noProxy = std::getenv("no_proxy");
    if (noProxy) noProxy_ = noProxy;

    if (proxy_.empty()) {
        auto gnome = detectGnomeProxy();
        if (!gnome.empty()) {
            proxy_ = gnome;
            LOG_INFO("Auto-detected proxy: " + proxy_);
        }
    }
}

HttpResolver::HttpResolver(const std::string& primaryUpstream, const std::string& secondaryUpstream,
                           const std::string& caFile, const std::string& fallback)
    : caFile_(caFile), fallback_(fallback),
      sslCtx_(asio::ssl::context::tlsv12_client) {
    pools_.emplace_back();
    pools_.back().parseUrl(primaryUpstream);
    if (!secondaryUpstream.empty()) {
        pools_.emplace_back();
        pools_.back().parseUrl(secondaryUpstream);
        LOG_INFO("Multi-upstream: racing " + primaryUpstream + " + " + secondaryUpstream);
    }
    const char* envProxy = std::getenv("https_proxy");
    if (!envProxy) envProxy = std::getenv("HTTPS_PROXY");
    if (!envProxy) envProxy = std::getenv("http_proxy");
    if (!envProxy) envProxy = std::getenv("HTTP_PROXY");
    if (envProxy) proxy_ = envProxy;
    const char* noProxy = std::getenv("no_proxy");
    if (noProxy) noProxy_ = noProxy;

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
    for (auto& pool : pools_)
        for (auto& c : pool.connections) c->close();
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

static void enableFastOpen(tcp::socket& socket) {
    int qlen = 5;
    setsockopt(socket.native_handle(), SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
}

void HttpResolver::enableTcpKeepalive(asio::ip::tcp::socket& socket) {
    int keepalive = 1;
    int keepidle = 10;
    int keepintvl = 3;
    int keepcnt = 3;
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    setsockopt(socket.native_handle(), IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    setsockopt(socket.native_handle(), IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(socket.native_handle(), IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
}

// Per-thread circuit breaker for proxy
static thread_local int tlsProxyErrors = 0;
static thread_local std::chrono::steady_clock::time_point tlsCircuitOpen;
static thread_local bool tlsCircuitTripped = false;

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
            enableFastOpen(stream.next_layer());
            enableTcpKeepalive(stream.next_layer());

            std::string connectReq = "CONNECT " + host + ":" + port + " HTTP/1.1\r\n"
                                     "Host: " + host + ":" + port + "\r\n"
                                     "User-Agent: lynx/0.2\r\n"
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
    enableTcpKeepalive(stream.next_layer());

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
    // Pre-reserve max capacity for all pools
    for (auto& pool : pools_)
        pool.connections.reserve(MAX_CONNECTIONS / pools_.size());

    sslCtx_.set_default_verify_paths();
    sslCtx_.set_verify_mode(asio::ssl::verify_peer);

    useProxy_ = !proxy_.empty() && !matchesNoProxy(pools_[0].host, noProxy_);
    if (useProxy_) parseProxyUrl(proxy_, proxyHost_, proxyPort_);

    LOG_INFO("HttpResolver: " + pools_[0].host + ":" + pools_[0].port + pools_[0].target
             + (useProxy_ ? " via proxy=" + proxyHost_ + ":" + proxyPort_ : ""));
    if (pools_.size() > 1)
        LOG_INFO("Secondary upstream: " + pools_[1].host + ":" + pools_[1].port + pools_[1].target);

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

void HttpResolver::reload() {
    // Read proxy from ~/.lynx-proxy (exists + non-empty = use it, else direct)
    std::string home;
    const char* homeEnv = std::getenv("HOME");
    if (homeEnv) home = homeEnv;
    std::string proxyPath = home + "/.lynx-proxy";
    std::ifstream pf(proxyPath);
    if (pf.is_open()) {
        std::string line;
        std::getline(pf, line);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
            line.pop_back();
        if (!line.empty()) {
            proxy_ = line;
            LOG_INFO("Reload: proxy set to " + proxy_);
        } else {
            proxy_.clear();
            LOG_INFO("Reload: no proxy configured (empty ~/.lynx-proxy)");
        }
    } else {
        // Check env var as fallback
        const char* envProxy = std::getenv("https_proxy");
        if (!envProxy) envProxy = std::getenv("HTTPS_PROXY");
        if (!envProxy) envProxy = std::getenv("http_proxy");
        if (!envProxy) envProxy = std::getenv("HTTP_PROXY");
        if (envProxy && envProxy[0]) {
            proxy_ = envProxy;
            LOG_INFO("Reload: proxy set to " + proxy_ + " (from env var)");
        } else {
            proxy_.clear();
            LOG_INFO("Reload: no proxy configured (direct)");
        }
    }

    const char* noProxy = std::getenv("no_proxy");
    if (!noProxy) noProxy = std::getenv("NO_PROXY");
    if (noProxy) {
        noProxy_ = noProxy;
    } else {
        noProxy_.clear();
    }

    useProxy_ = !proxy_.empty() && !matchesNoProxy(pools_[0].host, noProxy_);
    if (useProxy_) parseProxyUrl(proxy_, proxyHost_, proxyPort_);

    LOG_INFO("HttpResolver: " + pools_[0].host + ":" + pools_[0].port + pools_[0].target
             + (useProxy_ ? " via proxy=" + proxyHost_ + ":" + proxyPort_ : ""));
}

void HttpResolver::maintain() {
    // Per-upstream health rebalancing
    if (pools_.size() < 2) return;
    for (auto& pool : pools_) {
        int total = pool.successes + pool.errors;
        if (total < 10) continue; // not enough samples
        int errRatio = (pool.errors * 100) / total;
        pool.lastErrorRatio = errRatio;

        int currentSize = pool.connections.size();
        if (errRatio > 30 && currentSize > 2) {
            // Bad pool: shrink by 1
            pool.connections.pop_back();
            LOG_DEBUG("Shrinking unhealthy pool " + pool.host + " errRatio=" +
                      std::to_string(errRatio) + "%");
        } else if (errRatio < 5 && currentSize < MAX_CONNECTIONS / 2) {
            // Healthy pool: grow by 1
            ensurePoolSize(pool, currentSize + 1);
        }
        // Decay counters to keep them recent
        pool.successes = pool.successes / 2;
        pool.errors = pool.errors / 2;
    }
}

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
            enableFastOpen(stream->next_layer());
            enableTcpKeepalive(stream->next_layer());

            std::string connectReq = "CONNECT " + host + ":" + port + " HTTP/1.1\r\n"
                                     "Host: " + host + ":" + port + "\r\n"
                                     "User-Agent: lynx/0.2\r\n"
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
    enableTcpKeepalive(stream->next_layer());

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

    // Aggressive timeout — fail fast, retry on next connection or upstream
    setSocketTimeoutMs(stream->next_layer(), 5000); // socket read/write timeout (ms)

    std::ostringstream oss;
    oss << "POST " << target << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "User-Agent: lynx/0.2\r\n"
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

DnsMessagePtr HttpResolver::query(const DnsMessage& req, bool allowFanOut) {
    static std::atomic<int> queryCount{0};
    if (queryCount.fetch_add(1, std::memory_order_relaxed) % 100 == 0)
        maintain();
    int totalConns = 0;
    for (auto& pool : pools_) totalConns += pool.connections.size();
    PerfMonitor::instance().recordConnUse(countConnected(), totalConns);
    auto t0 = std::chrono::steady_clock::now();

    // Circuit breaker: if proxy errors spiked, bypass proxy temporarily
    if (useProxy_ && tlsCircuitTripped) {
        auto now = std::chrono::steady_clock::now();
        if (now - tlsCircuitOpen < std::chrono::seconds(60)) {
            LOG_DEBUG("Circuit breaker: bypassing proxy for 60s");
            bool savedUseProxy = useProxy_;
            useProxy_ = false;
            auto result = doPost(req, allowFanOut);
            useProxy_ = savedUseProxy;
            if (result) {
                auto dt = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - t0);
                PerfMonitor::instance().recordLatency(dt);
                return result;
            }
        } else {
            tlsCircuitTripped = false;
            tlsProxyErrors = 0;
            LOG_INFO("Circuit breaker: re-enabling proxy after cooldown");
        }
    }

    auto result = doPost(req, allowFanOut);
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
    PerfMonitor::instance().recordDomainLatency(req.question().qname, dt);
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

void HttpResolver::ensurePoolSize(UpstreamPool& pool, size_t target) {
    if (pool.connections.size() >= target) return;
    std::lock_guard<std::mutex> lock(pool.growMutex);
    while (pool.connections.size() < target) {
        auto conn = std::make_unique<Connection>();
        conn->host = pool.host;
        conn->port = pool.port;
        conn->target = pool.target;
        conn->poolRef = &pool;
        pool.connections.push_back(std::move(conn));
    }
}

HttpResolver::Connection* HttpResolver::getNextConnection(HttpResolver::UpstreamPool& pool) {
    int numConns = pool.connections.size();
    if (numConns == 0) return nullptr;
    int start = pool.nextConn.fetch_add(1, std::memory_order_relaxed) % numConns;
    for (int i = 0; i < numConns; ++i) {
        int idx = (start + i) % numConns;
        auto& conn = pool.connections[idx];
        if (!conn->connected.load()) continue;
        if (conn->inUse.exchange(true)) continue;
        return conn.get();
    }
    return nullptr;
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

void HttpResolver::openPoolAsync(UpstreamPool& pool) {
    for (auto& conn : pool.connections) {
        if (!conn->connected.load())
            openConnectionAsync(conn.get());
    }
}

void HttpResolver::warmUp() {
    int targetPerPool = AutoTuner::instance().recommendedConnections()
                        / static_cast<int>(pools_.size());
    if (targetPerPool < 2) targetPerPool = 2;

    std::vector<std::future<void>> futures;
    for (auto& pool : pools_) {
        ensurePoolSize(pool, static_cast<size_t>(targetPerPool));
        for (auto& conn : pool.connections) {
            futures.push_back(std::async(std::launch::async, [conn = conn.get(), this]() {
                if (conn->stream) connCtrl_.unmanage(conn->stream.get());
                boost::system::error_code ec;
                bool ok = conn->open(proxyHost_, proxyPort_, noProxy_, sslCtx_, useProxy_, ec);
                if (conn->stream) {
                    connCtrl_.manage(conn->host, conn->port, conn->target,
                                     conn->stream.get(), &conn->connected);
                }
                if (!ok) conn->connected = false;
            }));
        }
    }

    int totalConns = 0;
    for (auto& pool : pools_) totalConns += pool.connections.size();

    std::thread([this, futures = std::move(futures), totalConns]() {
        for (auto& f : futures) f.wait();
        auto healthWire = ConnectionController::makeHealthQuery();
        for (auto& pool : pools_) {
            for (auto& conn : pool.connections) {
                if (!conn->connected.load()) continue;
                conn->inUse = true;
                auto reply = conn->exchange(healthWire);
                if (!reply) connCtrl_.notifyFailure(conn->stream.get());
                else connCtrl_.notifyUsed(conn->stream.get());
                conn->inUse = false;
            }
        }
        LOG_INFO("WarmUp: " + std::to_string(countConnected()) + "/" +
                 std::to_string(totalConns) + " connections ready");
    }).detach();
}

DnsMessagePtr HttpResolver::doPost(const DnsMessage& req) {
    return doPost(req, true);
}

DnsMessagePtr HttpResolver::doPost(const DnsMessage& req, bool allowFanOut) {
    auto wire = req.pack();

    int targetPerPool = AutoTuner::instance().recommendedConnections()
                        / static_cast<int>(pools_.size());
    if (targetPerPool < 2) targetPerPool = 2;
    bool fanOut = AutoTuner::instance().fanOutEnabled() && allowFanOut;

    // Grow pools if needed
    for (auto& pool : pools_)
        ensurePoolSize(pool, static_cast<size_t>(targetPerPool));

    // Multi-upstream racing: try one connection from each pool in parallel
    if (fanOut) {
        auto result = raceUpstreams(wire);
        if (result) return result;
    }

    // Fallback: try connections round-robin across all pools
    int backoffMs = 10;
    int totalConns = 0;
    for (auto& pool : pools_) totalConns += pool.connections.size();
    for (int attempt = 0; attempt < std::min(totalConns * 2, 12); ++attempt) {
        for (auto& pool : pools_) {
            auto* conn = getNextConnection(pool);
            if (!conn) continue;

            auto reply = conn->exchange(wire);
            if (reply) {
                conn->inUse = false;
                connCtrl_.notifyUsed(conn->stream.get());
                if (conn->poolRef) conn->poolRef->successes++;
                tlsProxyErrors = 0;
                return reply;
            }
            connCtrl_.notifyFailure(conn->stream.get());
            if (conn->poolRef) conn->poolRef->errors++;
            conn->inUse = false;

            if (useProxy_ && ++tlsProxyErrors > 5) {
                tlsCircuitTripped = true;
                tlsCircuitOpen = std::chrono::steady_clock::now();
                LOG_WARN("Circuit breaker: proxy error spike, bypassing for 60s");
            }
        }
        if (attempt < 4) {
            std::this_thread::sleep_for(std::chrono::milliseconds(backoffMs));
            backoffMs *= 2;
        }
    }

    // No connected connections — open just 1 synchronously, rest in background
    for (auto& pool : pools_) {
        for (auto& conn : pool.connections) {
            if (conn->connected.load()) continue;
            if (conn->inUse.exchange(true)) continue;

            if (conn->stream) connCtrl_.unmanage(conn->stream.get());
            boost::system::error_code ec;
            conn->open(proxyHost_, proxyPort_, noProxy_, sslCtx_, useProxy_, ec);
            if (conn->stream) {
                connCtrl_.manage(conn->host, conn->port, conn->target,
                                 conn->stream.get(), &conn->connected);
            }
            if (ec) { conn->inUse = false; continue; }

            auto reply = conn->exchange(wire);
            if (reply) {
                conn->inUse = false;
                connCtrl_.notifyUsed(conn->stream.get());
                if (conn->poolRef) conn->poolRef->successes++;
                for (auto& p : pools_)
                    openPoolAsync(p);
                tlsProxyErrors = 0;
                return reply;
            }
            connCtrl_.notifyFailure(conn->stream.get());
            if (conn->poolRef) conn->poolRef->errors++;
            conn->inUse = false;

            if (useProxy_ && ++tlsProxyErrors > 5) {
                tlsCircuitTripped = true;
                tlsCircuitOpen = std::chrono::steady_clock::now();
            }
            break;
        }
    }

    return nullptr;
}

DnsMessagePtr HttpResolver::doPostParallel(const std::vector<uint8_t>& wire) {
    return raceUpstreams(wire);
}

DnsMessagePtr HttpResolver::raceUpstreams(const std::vector<uint8_t>& wire) {
    // True parallel racing: take one connection from each pool, run exchanges
    // concurrently via std::async, return the first to respond.
    std::vector<Connection*> candidates;
    for (auto& pool : pools_) {
        auto* conn = getNextConnection(pool);
        if (conn) candidates.push_back(conn);
    }
    if (candidates.empty()) return nullptr;

    // Also grab a few more from the first pool for extra parallelism
    auto& firstPool = pools_[0];
    int extra = 0;
    for (int i = 0; i < static_cast<int>(firstPool.connections.size()) && extra < 2; ++i) {
        auto* conn = getNextConnection(firstPool);
        if (!conn) break;
        candidates.push_back(conn);
        ++extra;
    }

    std::vector<std::future<DnsMessagePtr>> futures;
    for (auto* conn : candidates) {
        futures.push_back(std::async(std::launch::async, [conn, &wire]() {
            return conn->exchange(wire);
        }));
    }

    DnsMessagePtr result;
    for (auto& f : futures) {
        if (f.wait_for(std::chrono::milliseconds(300)) == std::future_status::ready) {
            auto r = f.get();
            if (r) {
                result = std::move(r);
                break;
            }
        }
    }

    for (auto* conn : candidates) {
        conn->inUse = false;
        if (conn->stream) {
            if (result) {
                connCtrl_.notifyUsed(conn->stream.get());
                if (conn->poolRef) conn->poolRef->successes++;
            } else {
                connCtrl_.notifyFailure(conn->stream.get());
                if (conn->poolRef) conn->poolRef->errors++;
            }
        }
    }

    return result;
}
