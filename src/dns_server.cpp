// SPDX-License-Identifier: MIT
//
#include "dns_server.hpp"
#include "logger.hpp"
#include "perf_monitor.hpp"
#include "auto_tuner.hpp"

#include <boost/asio.hpp>
#include <thread>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <functional>
#include <unordered_map>
#include <chrono>

class ThreadPool {
public:
    ThreadPool(size_t n) : target_(n) {
        for (size_t i = 0; i < n; ++i)
            spawnWorker();
    }
    ~ThreadPool() {
        { std::lock_guard<std::mutex> lk(m_); stop_ = true; }
        cv_.notify_all();
        for (auto& t : workers_) if (t.joinable()) t.join();
    }
    void enqueue(std::function<void()> f) {
        { std::lock_guard<std::mutex> lk(m_); tasks_.push(std::move(f)); }
        cv_.notify_one();
    }
    bool tryEnqueue(std::function<void()> f) {
        {
            std::lock_guard<std::mutex> lk(m_);
            if (tasks_.size() >= BACKPRESSURE_LIMIT)
                return false;
            tasks_.push(std::move(f));
        }
        cv_.notify_one();
        return true;
    }
    size_t maxPending() const { return BACKPRESSURE_LIMIT; }
    size_t pending() const {
        std::lock_guard<std::mutex> lk(m_);
        return tasks_.size();
    }
    size_t workerCount() const {
        return liveCount_.load();
    }

    void resize(size_t n) {
        if (n > MAX_WORKERS) n = MAX_WORKERS;
        if (n < MIN_WORKERS) n = MIN_WORKERS;
        target_.store(n);
        std::lock_guard<std::mutex> lk(m_);
        scrubWorkers();
        while (liveCount_.load() < n)
            spawnWorker();
        cv_.notify_all();
    }
    void shutdown() {
        std::lock_guard<std::mutex> lk(m_);
        stop_ = true;
        cv_.notify_all();
    }

private:
    void spawnWorker() {
        workers_.emplace_back([this] { workerLoop(); });
        liveCount_.fetch_add(1);
    }
    void scrubWorkers() {
        for (auto it = workers_.begin(); it != workers_.end(); ) {
            if (it->joinable()) {
                ++it;
            } else {
                it->detach();
                it = workers_.erase(it);
            }
        }
    }

    // Try to exit if pool is over target (shrink)
    bool maybeShrink() {
        size_t cur = liveCount_.load();
        while (cur > target_.load()) {
            if (liveCount_.compare_exchange_weak(cur, cur - 1))
                return true;
        }
        return false;
    }

    void workerLoop() {
        bool wasShrunk = false;
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lk(m_);
                cv_.wait(lk, [this] { return stop_ || !tasks_.empty() || liveCount_.load() > target_.load(); });
                if (stop_ && tasks_.empty()) break;
                if (liveCount_.load() > target_.load() && tasks_.empty()) {
                    if (maybeShrink()) { wasShrunk = true; break; }
                    continue;
                }
                if (tasks_.empty()) continue;
                task = std::move(tasks_.front()); tasks_.pop();
            }
            try {
                task();
            } catch (const std::exception& e) {
                LOG_ERROR("Thread pool worker error: " + std::string(e.what()));
            } catch (...) {
                LOG_ERROR("Thread pool worker error: unknown exception");
            }
            // After finishing a task, check if we should shrink
            if (!stop_ && maybeShrink()) { wasShrunk = true; break; }
        }
        if (!wasShrunk) liveCount_.fetch_sub(1);
    }

    mutable std::mutex m_;
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::condition_variable cv_;
    std::atomic<bool> stop_{false};
    std::atomic<size_t> target_{8};
    std::atomic<size_t> liveCount_{0};
    static constexpr size_t MIN_WORKERS = 4;
    static constexpr size_t MAX_WORKERS = 64;
    static constexpr size_t BACKPRESSURE_LIMIT = 2000;
};

static ThreadPool& dnsPool() {
    static ThreadPool pool(12);
    return pool;
}

// Rate limiter — sharded token bucket per client IP (reduces mutex contention)
class RateLimiter {
public:
    bool allow(const std::string& ip) {
        size_t shard = fnv1a(ip) & (SHARDS - 1);
        auto& s = shards_[shard];
        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lk(s.m);
        auto& entry = s.clients[ip];
        if (now - entry.last > std::chrono::seconds(1)) {
            entry.count = 0;
            entry.last = now;
        }
        if (++entry.count > 100) return false;
        return true;
    }
private:
    struct Entry { std::chrono::steady_clock::time_point last; int count = 0; };
    struct Shard {
        std::unordered_map<std::string, Entry> clients;
        std::mutex m;
    };
    static constexpr size_t SHARDS = 16;
    std::array<Shard, SHARDS> shards_;
    static uint64_t fnv1a(const std::string& s) {
        uint64_t h = 14695981039346656037ULL;
        for (char c : s) { h ^= (uint8_t)c; h *= 1099511628211ULL; }
        return h;
    }
};

static RateLimiter rateLimiter;

DnsServer::DnsServer(const std::string& addr,
                     std::shared_ptr<Resolver> resolver,
                     const std::string& unqUpstream,
                     DomainMap overrides)
    : addr_(addr), resolver_(std::move(resolver)),
      unqUpstream_(unqUpstream), overrides_(std::move(overrides)) {}

DnsServer::~DnsServer() {
    stop();
}

void DnsServer::tcpAcceptLoop() {
    while (running_) {
        sys::error_code ec;
        tcp::socket socket(ioCtx_);
        tcpAcceptor_.accept(socket, ec);
        if (ec) {
            if (running_) LOG_ERROR("TCP accept error: " + ec.message());
            break;
        }
        auto r = resolver_;
        std::thread([sock = std::move(socket), r]() mutable {
            try {
                sock.set_option(tcp::no_delay(true));
                uint16_t net_len;
                asio::read(sock, asio::buffer(&net_len, 2));
                uint16_t len = ntohs(net_len);
                if (len < 12 || len > 65535) return;
                std::vector<uint8_t> buf(len);
                asio::read(sock, asio::buffer(buf));
                auto msg = DnsMessage::parse(buf.data(), len);
                if (!msg || !msg->hasQuestions()) return;
                auto reply = r->query(*msg);
                if (!reply) {
                    reply = DnsMessage::createError(*msg, DnsRcode::ServFail);
                }
                auto wire = reply->pack();
                uint16_t resp_len = htons(wire.size());
                std::vector<asio::const_buffer> bufs;
                bufs.push_back(asio::buffer(&resp_len, 2));
                bufs.push_back(asio::buffer(wire));
                asio::write(sock, bufs);
            } catch (const std::exception&) {}
        }).detach();
    }
}

void DnsServer::perfMonitorLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        PerfMonitor::instance().recordThreadPoolLoad(dnsPool().pending());
        PerfMonitor::instance().recordThreadPoolWorkers(static_cast<int>(dnsPool().workerCount()));
        int rec = AutoTuner::instance().recommendedThreads();
        auto prevWorkers = dnsPool().workerCount();
        if (rec != static_cast<int>(prevWorkers)) {
            dnsPool().resize(rec);
            LOG_DEBUG("ThreadPool resized to " + std::to_string(rec) + " (was " +
                      std::to_string(prevWorkers) + ")");
        }
    }
}

void DnsServer::stop() {
    running_ = false;
    sys::error_code ec;

    // Stop accepting new work
    tcpAcceptor_.close(ec);
    dnsPool().shutdown();

    // Self-connect to unblock TCP accept thread
    auto colon = addr_.find(':');
    if (colon != std::string::npos && colon + 1 < addr_.size()) {
        try {
            int tcpPort = std::stoi(addr_.substr(colon + 1));
            asio::io_context tmp;
            asio::ip::tcp::socket kicker(tmp);
            kicker.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), tcpPort), ec);
            ec.clear();
        } catch (...) {}
    }

    // Send dummy UDP packets to unblock worker receive_from() calls
    for (int i = 0; i < NUM_WORKERS; i++) {
        try {
            asio::io_context tmp;
            asio::ip::udp::socket kicker(tmp);
            kicker.open(asio::ip::udp::v4());
            kicker.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
            kicker.send_to(asio::buffer("", 1),
                asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"),
                    static_cast<uint16_t>(std::stoi(addr_.substr(colon + 1)))));
        } catch (...) {}
    }

    // Wait for all pool workers to finish their in-flight tasks
    for (auto& t : workerThreads_)
        if (t.joinable()) t.join();
    if (tcpAcceptThread_.joinable()) tcpAcceptThread_.join();
    if (perfMonitorThread_.joinable()) perfMonitorThread_.join();

    // All work is done — safe to close sockets and stop io_context
    if (udpSocket_) {
        udpSocket_->close(ec);
        udpSocket_.reset();
    }
    ioCtx_.stop();
}

void DnsServer::listenAndServe() {
    try {
    // Start the perf monitor loop early so the thread pool is managed
    // and workers are visible in telemetry, even during warmupCache().
    perfMonitorThread_ = std::thread([this]() { perfMonitorLoop(); });

    resolver_->init();

    auto colon = addr_.find(':');
    std::string host = (colon != std::string::npos && colon > 0) ? addr_.substr(0, colon) : "";
    std::string port = (colon != std::string::npos) ? addr_.substr(colon + 1) : "53";
    if (host.empty()) host = "0.0.0.0";
    uint16_t portNum = static_cast<uint16_t>(std::stoi(port));

    sys::error_code ec;

    // Main UDP socket (worker 0)
    udpSocket_ = std::make_shared<asio::ip::udp::socket>(ioCtx_);
    asio::ip::udp::endpoint udpEndpoint(asio::ip::make_address(host), portNum);
    udpSocket_->open(udpEndpoint.protocol(), ec);
    if (ec) { LOG_ERROR("Failed to open UDP socket: " + ec.message()); return; }
    udpSocket_->set_option(asio::socket_base::reuse_address(true), ec);

    // SO_REUSEPORT for all workers
    {
        int reuse = 1;
        setsockopt(udpSocket_->native_handle(), SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    }

    udpSocket_->bind(udpEndpoint, ec);
    if (ec) { LOG_ERROR("Failed to bind UDP: " + ec.message()); return; }

    // Start async receive on main socket (also workers via SO_REUSEPORT)
    startUdpReceive();

    resolver_->maintain();

    // Start multi-worker UDP listeners (SO_REUSEPORT allows multiple sockets on same port)
    LOG_INFO("DNS server listening on " + addr_ + " with " +
             std::to_string(NUM_WORKERS) + " UDP workers");

    for (int i = 0; i < NUM_WORKERS; ++i) {
        workerThreads_.emplace_back([this, i, host, portNum]() {
            udpWorker(i, portNum);
        });
    }

    tcp::endpoint tcpEndpoint(asio::ip::make_address(host), portNum);
    tcpAcceptor_.open(tcpEndpoint.protocol(), ec);
    if (ec) { LOG_ERROR("Failed to open TCP acceptor: " + ec.message()); }
    if (!ec) {
        tcpAcceptor_.set_option(asio::socket_base::reuse_address(true), ec);
        if (ec) { LOG_WARN("Failed to set TCP reuse_address: " + ec.message()); ec.clear(); }

        int reuse = 1;
        setsockopt(tcpAcceptor_.native_handle(), SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

        tcpAcceptor_.bind(tcpEndpoint, ec);
        if (ec) { LOG_WARN("Failed to bind TCP (" + ec.message() + ") — UDP only"); }
    }
    if (!ec) tcpAcceptor_.listen(asio::socket_base::max_listen_connections, ec);

    if (ec) {
        LOG_WARN("TCP DNS disabled — UDP only");
    } else {
        tcpAcceptThread_ = std::thread([this]() { tcpAcceptLoop(); });
    }

    // Main thread runs io_ctx for TCP accept
    ioCtx_.run();
    LOG_DEBUG("DNS io_context stopped");
    } catch (const std::exception& e) {
        LOG_ERROR("Fatal error in DNS server: " + std::string(e.what()));
    } catch (...) {
        LOG_ERROR("Fatal error in DNS server: unknown (not std::exception)");
    }
}

void DnsServer::udpWorker(int id, uint16_t port) {
    try {
        // Each worker opens its own UDP socket with SO_REUSEPORT
        asio::io_context workerCtx;
        asio::ip::udp::socket workerSocket(workerCtx);
        asio::ip::udp::endpoint ep(asio::ip::udp::v4(), port);

        sys::error_code ec;
        workerSocket.open(ep.protocol(), ec);
        if (ec) { LOG_ERROR("Worker " + std::to_string(id) + " open: " + ec.message()); return; }

        workerSocket.set_option(asio::socket_base::reuse_address(true), ec);
        int reuse = 1;
        setsockopt(workerSocket.native_handle(), SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
        workerSocket.bind(ep, ec);
        if (ec) { LOG_ERROR("Worker " + std::to_string(id) + " bind: " + ec.message()); return; }

        LOG_DEBUG("UDP worker " + std::to_string(id) + " started on port " + std::to_string(port));

        std::array<uint8_t, 4096> recvBuf;
        asio::ip::udp::endpoint remoteEp;

        while (running_) {
            size_t len;
            {
                sys::error_code recvEc;
                len = workerSocket.receive_from(asio::buffer(recvBuf), remoteEp, 0, recvEc);
                if (recvEc) {
                    if (running_) LOG_ERROR("Worker " + std::to_string(id) + " recv: " + recvEc.message());
                    continue;
                }
                if (len < 12) continue;
            }

            auto clientIp = remoteEp.address().to_string();
            if (!rateLimiter.allow(clientIp)) {
                LOG_WARN("Rate limit exceeded for " + clientIp);
                continue;
            }

            // Handle the query
            auto data = std::make_shared<std::vector<uint8_t>>(recvBuf.begin(), recvBuf.begin() + len);
            auto remote = remoteEp;
            auto res = resolver_;
            auto over = overrides_;
            auto unq = unqUpstream_;
            auto sock = udpSocket_;

            PerfMonitor::instance().recordDnsQuery();
            if (!dnsPool().tryEnqueue([data, remote, res, over, unq, sock]() {
                    handleQuery(data->data(), data->size(), remote, res, over, unq, sock);
                })) {
                auto req = DnsMessage::parse(data->data(), data->size());
                if (req) {
                    auto reply = DnsMessage::createError(*req, DnsRcode::ServFail);
                    if (reply) {
                        auto wire = reply->pack();
                        sys::error_code sendEc;
                        sock->send_to(asio::buffer(wire), remote, 0, sendEc);
                        if (sendEc) LOG_ERROR("UDP worker rejection send error: " + sendEc.message());
                        PerfMonitor::instance().recordError();
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        if (running_) LOG_ERROR("UDP worker " + std::to_string(id) + " error: " + std::string(e.what()));
    }
}

void DnsServer::startUdpReceive() {
    udpSocket_->async_receive_from(
        asio::buffer(recvBuf_), remoteEndpoint_,
        std::bind(&DnsServer::onUdpReceive, this,
                  std::placeholders::_1, std::placeholders::_2));
}

void DnsServer::onUdpReceive(sys::error_code ec, size_t len) {
    if (ec) {
        if (ec != asio::error::operation_aborted)
            LOG_ERROR("UDP receive error: " + ec.message());
        if (running_) startUdpReceive();
        return;
    }

    auto clientIp = remoteEndpoint_.address().to_string();
    if (!rateLimiter.allow(clientIp)) {
        LOG_WARN("Rate limit exceeded for " + clientIp);
        startUdpReceive();
        return;
    }

    // Copy data and offload to thread pool
    auto data = std::make_shared<std::vector<uint8_t>>(recvBuf_.begin(), recvBuf_.begin() + len);
    auto remote = remoteEndpoint_;
    auto resolver = resolver_;
    auto overrides = overrides_;
    auto unqUpstream = unqUpstream_;
    auto sock = udpSocket_;

    PerfMonitor::instance().recordDnsQuery();
    if (!dnsPool().tryEnqueue([data, remote, resolver, overrides, unqUpstream, sock]() {
            handleQuery(data->data(), data->size(), remote, resolver, overrides, unqUpstream, sock);
        })) {
        try {
            auto req = DnsMessage::parse(data->data(), data->size());
            if (req) {
                auto reply = DnsMessage::createError(*req, DnsRcode::ServFail);
                if (reply) {
                    auto wire = std::make_shared<std::vector<uint8_t>>(reply->pack());
                    sock->async_send_to(asio::buffer(*wire), remote,
                        [wire](sys::error_code, size_t){});
                    PerfMonitor::instance().recordError();
                }
            }
        } catch (const std::exception&) {}
    }

    startUdpReceive();
}

void DnsServer::handleQuery(const uint8_t* data, size_t len,
                             asio::ip::udp::endpoint remote,
                             std::shared_ptr<Resolver> resolver,
                             DomainMap overrides,
                             std::string unqUpstream,
                             std::shared_ptr<asio::ip::udp::socket> sock) {
    try {
        auto req = DnsMessage::parse(data, len);
        if (!req || !req->hasQuestions()) return;

        const auto& q = req->question();

        // Per-query trace ID
        auto traceId = std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count() % 100000) + "-" +
            q.qname.substr(0, std::min(q.qname.size(), size_t(16)));

        LOG_DEBUG("[" + traceId + "] query " + q.qname + " (" + std::to_string(q.qtype) +
                  ") from " + remote.address().to_string());

        DnsMessagePtr reply;

        std::string overrideAddr;
        if (overrides.getMostSpecific(q.qname, overrideAddr)) {
            try {
                asio::io_context ctx;
                asio::ip::udp::socket tmpSock(ctx);
                asio::ip::udp::resolver resolv(ctx);
                auto colon = overrideAddr.find(':');
                std::string ovHost = (colon != std::string::npos) ? overrideAddr.substr(0, colon) : overrideAddr;
                std::string ovPort = (colon != std::string::npos) ? overrideAddr.substr(colon + 1) : "53";
                auto eps = resolv.resolve(ovHost, ovPort);
                tmpSock.open(asio::ip::udp::v4());
                auto wire = req->pack();
                tmpSock.send_to(asio::buffer(wire), *eps.begin());
                std::array<uint8_t, 4096> respBuf;
                asio::ip::udp::endpoint from;
                size_t n = tmpSock.receive_from(asio::buffer(respBuf), from);
                reply = DnsMessage::parse(respBuf.data(), n);
                if (reply) reply->header.id = req->header.id;
            } catch (const std::exception& e) {
                LOG_ERROR("[" + traceId + "] Override error: " + std::string(e.what()));
                reply = DnsMessage::createError(*req, DnsRcode::ServFail);
                if (reply) PerfMonitor::instance().recordError();
            }
            LOG_DEBUG("[" + traceId + "] override -> " + overrideAddr);
        } else if (!unqUpstream.empty()) {
            auto dot = q.qname.find('.');
            auto nextDot = (dot != std::string::npos) ? q.qname.find('.', dot + 1) : std::string::npos;
            bool isUnq = (dot == std::string::npos) || (nextDot == std::string::npos) || (dot == q.qname.size() - 1);
            if (isUnq) {
                try {
                    asio::io_context ctx;
                    asio::ip::udp::socket tmpSock(ctx);
                    asio::ip::udp::resolver resolv(ctx);
                    auto colon = unqUpstream.find(':');
                    std::string uHost = (colon != std::string::npos) ? unqUpstream.substr(0, colon) : unqUpstream;
                    std::string uPort = (colon != std::string::npos) ? unqUpstream.substr(colon + 1) : "53";
                    auto eps = resolv.resolve(uHost, uPort);
                    tmpSock.open(asio::ip::udp::v4());
                    auto wire = req->pack();
                    tmpSock.send_to(asio::buffer(wire), *eps.begin());
                    std::array<uint8_t, 4096> respBuf;
                    asio::ip::udp::endpoint from;
                    size_t n = tmpSock.receive_from(asio::buffer(respBuf), from);
                    reply = DnsMessage::parse(respBuf.data(), n);
                    if (reply) reply->header.id = req->header.id;
                } catch (const std::exception& e) {
                    LOG_ERROR("[" + traceId + "] Unqualified upstream error: " + std::string(e.what()));
                    reply = DnsMessage::createError(*req, DnsRcode::ServFail);
                    if (reply) PerfMonitor::instance().recordError();
                }
            } else {
                reply = resolver->query(*req);
            }
        } else {
            reply = resolver->query(*req);
        }

        if (!reply) {
            reply = DnsMessage::createError(*req, DnsRcode::ServFail);
        }

        auto wire = reply->pack();
        // Serialize send through io_context to avoid concurrent socket access
        auto buf = std::make_shared<std::vector<uint8_t>>(std::move(wire));
        asio::post(sock->get_executor(), [sock, buf, remote]() {
            sock->async_send_to(asio::buffer(*buf), remote,
                [buf](sys::error_code ec, size_t) {
                    if (ec) LOG_ERROR("UDP send error: " + ec.message());
                });
        });

    } catch (const std::exception& e) {
        LOG_ERROR("Error handling DNS query: " + std::string(e.what()));
    } catch (...) {
        LOG_ERROR("Error handling DNS query: unknown exception");
    }
}
