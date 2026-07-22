// SPDX-License-Identifier: MIT
//
#include "connection_controller.hpp"
#include "logger.hpp"
#include "dns_protocol.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <thread>
#include <chrono>
#include <deque>
#include <sstream>
#include <cstring>
#include <cstdint>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/tcp.h>

void ConnectionController::enableTcpKeepAlive(asio::ip::tcp::socket& socket) {
    int yes = 1;
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
    setsockopt(socket.native_handle(), SOL_TCP, TCP_NODELAY, &yes, sizeof(yes));
    int idle = 10;
    int interval = 3;
    int count = 3;
    setsockopt(socket.native_handle(), SOL_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(socket.native_handle(), SOL_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    setsockopt(socket.native_handle(), SOL_TCP, TCP_KEEPCNT, &count, sizeof(count));
}

static void setSocketTimeout(asio::ip::tcp::socket& socket, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

ConnectionController::ConnectionController() = default;
ConnectionController::~ConnectionController() { stop(); }

void ConnectionController::start() {
    if (running_) return;
    running_ = true;
    thread_ = std::thread([this]() { run(); });
    reconnectWorkers_.reserve(RECONNECT_WORKERS);
    for (int i = 0; i < RECONNECT_WORKERS; ++i)
        reconnectWorkers_.emplace_back([this]() { reconnectLoop(); });
}

void ConnectionController::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
    {
        std::lock_guard<std::mutex> lk(reconnectMutex_);
        reconnectStop_ = true;
    }
    reconnectCv_.notify_all();
    for (auto& w : reconnectWorkers_)
        if (w.joinable()) w.join();
}

void ConnectionController::manage(const std::string& host, const std::string& port,
                                   const std::string& target,
                                   std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> stream,
                                   std::atomic<bool>* connected) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    ManagedConn mc;
    mc.host = host;
    mc.port = port;
    mc.target = target;
    mc.stream = stream;
    mc.connected = connected;
    mc.lastUse = now;
    mc.lastCheck = now;
    mc.failures = 0;
    mc.reconnectPending = false;
    if (connected && connected->load()) {
        connectedCount_.fetch_add(1);
        boost::system::error_code ec;
        stream->next_layer().non_blocking(false, ec);
        enableTcpKeepAlive(stream->next_layer());
        mc.lastUse = now;
    }
    managed_.push_back(std::move(mc));
    totalCount_.store(managed_.size());
}

void ConnectionController::unmanage(asio::ssl::stream<asio::ip::tcp::socket>* stream) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (size_t i = 0; i < managed_.size(); ++i) {
        if (managed_[i].stream.get() == stream) {
            if (managed_[i].connected && managed_[i].connected->load())
                connectedCount_.fetch_sub(1);
            managed_.erase(managed_.begin() + i);
            totalCount_.store(managed_.size());
            break;
        }
    }
    // Cancel any pending reconnect work for this stream to prevent
    // reconnectLoop from using a dangling stream pointer.
    {
        std::lock_guard<std::mutex> rl(reconnectMutex_);
        auto it = reconnectQueue_.begin();
        while (it != reconnectQueue_.end()) {
            if (it->stream.get() == stream)
                it = reconnectQueue_.erase(it);
            else
                ++it;
        }
    }
}

void ConnectionController::notifyUsed(asio::ssl::stream<asio::ip::tcp::socket>* stream) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& mc : managed_) {
        if (mc.stream.get() == stream) {
            mc.lastUse = std::chrono::steady_clock::now();
            mc.failures = 0;
            return;
        }
    }
}

void ConnectionController::notifyFailure(asio::ssl::stream<asio::ip::tcp::socket>* stream) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (size_t i = 0; i < managed_.size(); ++i) {
            if (managed_[i].stream.get() == stream) {
                managed_[i].failures++;
                if (managed_[i].connected && managed_[i].connected->exchange(false))
                    connectedCount_.fetch_sub(1);
                if (!managed_[i].reconnectPending) {
                    managed_[i].reconnectPending = true;
                    ReconnectWork work;
                    work.stream = managed_[i].stream;
                    work.host = managed_[i].host;
                    work.port = managed_[i].port;
                    work.target = managed_[i].target;
                    {
                        std::lock_guard<std::mutex> lk(reconnectMutex_);
                        reconnectQueue_.push_back(std::move(work));
                    }
                    reconnectCv_.notify_one();
                }
                return;
            }
        }
    }
}

void ConnectionController::probeAllIdle() {
    struct Work {
        size_t idx;
        std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> stream;
        ManagedConn snapshot;
    };
    std::vector<Work> toCheck;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();
        for (size_t i = 0; i < managed_.size(); ++i) {
            auto& mc = managed_[i];
            if (!mc.stream || !mc.connected || !mc.connected->load()) continue;
            if (mc.reconnectPending) continue;

            auto idleMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - mc.lastUse).count();
            if (idleMs >= 3000) {
                toCheck.push_back({i, mc.stream, mc});
            }
        }
    }

    if (toCheck.empty()) return;

    LOG_DEBUG("Probing " + std::to_string(toCheck.size()) + " idle connections (high latency trigger)");

    for (auto& w : toCheck) {
        ManagedConn local = w.snapshot;
        local.stream = w.stream;
        if (!healthCheck(local)) {
            LOG_DEBUG("Idle connection failed health check, reconnecting...");
            std::lock_guard<std::mutex> lock(mutex_);
            if (w.idx < managed_.size() && managed_[w.idx].stream == w.stream) {
                if (managed_[w.idx].connected && managed_[w.idx].connected->exchange(false))
                    connectedCount_.fetch_sub(1);
                boost::system::error_code ec;
                if (w.stream) w.stream->next_layer().close(ec);
                if (!managed_[w.idx].reconnectPending) {
                    managed_[w.idx].reconnectPending = true;
                    ReconnectWork rw;
                    rw.stream = w.stream;
                    rw.host = managed_[w.idx].host;
                    rw.port = managed_[w.idx].port;
                    rw.target = managed_[w.idx].target;
                    {
                        std::lock_guard<std::mutex> lk(reconnectMutex_);
                        reconnectQueue_.push_back(std::move(rw));
                    }
                    reconnectCv_.notify_one();
                }
            }
        }
    }
}

// ---------- Background maintenance ----------

void ConnectionController::run() {
    while (running_) {
        std::this_thread::sleep_for(MAINTAIN_INTERVAL);

        struct Work {
            size_t idx;
            std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> stream;
            ManagedConn snapshot;
        };
        std::vector<Work> checks;
        std::vector<size_t> reconnects;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto now = std::chrono::steady_clock::now();
            for (size_t i = 0; i < managed_.size(); ++i) {
                auto& mc = managed_[i];
                if (!mc.stream || !mc.connected) continue;
                if (mc.reconnectPending) continue;

                if (mc.connected->load()) {
                    auto idleMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - mc.lastUse).count();
                    auto sinceCheck = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - mc.lastCheck).count();

                    if (idleMs >= 3000 && sinceCheck >= std::chrono::milliseconds(IDLE_CHECK_INTERVAL).count()) {
                        checks.push_back({i, mc.stream, mc});
                    }
                } else {
                    mc.reconnectPending = true;
                    reconnects.push_back(i);
                }
            }
        }

        for (auto& w : checks) {
            ManagedConn local = w.snapshot;
            local.stream = w.stream;
            if (!healthCheck(local)) {
                LOG_DEBUG("Health check failed, reconnecting...");
                std::lock_guard<std::mutex> lock(mutex_);
                if (w.idx < managed_.size() && managed_[w.idx].stream == w.stream) {
                    if (managed_[w.idx].connected && managed_[w.idx].connected->exchange(false))
                        connectedCount_.fetch_sub(1);
                    boost::system::error_code ec;
                    if (w.stream) w.stream->next_layer().close(ec);
                    if (!managed_[w.idx].reconnectPending) {
                        managed_[w.idx].reconnectPending = true;
                        ReconnectWork rw;
                        rw.stream = w.stream;
                        rw.host = managed_[w.idx].host;
                        rw.port = managed_[w.idx].port;
                        rw.target = managed_[w.idx].target;
                        {
                            std::lock_guard<std::mutex> lk(reconnectMutex_);
                            reconnectQueue_.push_back(std::move(rw));
                        }
                        reconnectCv_.notify_one();
                    }
                }
            }
        }

        for (auto& idx : reconnects) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (idx < managed_.size()) {
                auto& mc = managed_[idx];
                LOG_INFO("[health] enqueuing reconnect for " + mc.host + ":" + mc.port);
                ReconnectWork rw;
                rw.stream = mc.stream;
                rw.host = mc.host;
                rw.port = mc.port;
                rw.target = mc.target;
                {
                    std::lock_guard<std::mutex> lk(reconnectMutex_);
                    reconnectQueue_.push_back(std::move(rw));
                }
                reconnectCv_.notify_one();
            }
        }
    }
}

// ---------- Health check ----------

std::vector<uint8_t> ConnectionController::makeHealthQuery() {
    return {0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01};
}

bool ConnectionController::healthCheck(ManagedConn& mc) {
    if (!mc.stream || !mc.connected || !mc.connected->load()) return false;

    boost::system::error_code ec;

    setSocketTimeout(mc.stream->next_layer(), HEALTH_TIMEOUT_SEC);

    auto wire = makeHealthQuery();

    std::ostringstream oss;
    oss << "POST " << mc.target << " HTTP/1.1\r\n"
        << "Host: " << mc.host << "\r\n"
        << "User-Agent: lynx/0.2\r\n"
        << "Content-Type: application/dns-message\r\n"
        << "Accept: application/dns-message\r\n"
        << "Content-Length: " << wire.size() << "\r\n"
        << "Connection: keep-alive\r\n"
        << "\r\n";
    std::string header = oss.str();

    asio::write(*mc.stream, asio::buffer(header), ec);
    if (ec) return false;
    asio::write(*mc.stream, asio::buffer(wire), ec);
    if (ec) return false;

    std::vector<uint8_t> respBuf;
    respBuf.reserve(1024);
    size_t headerEndPos = 0;
    bool headerDone = false;
    size_t contentLength = 0;
    bool isChunked = false;

    while (true) {
        std::array<uint8_t, 1024> chunk;
        size_t n = mc.stream->read_some(asio::buffer(chunk), ec);
        if (ec == boost::asio::error::eof) break;
        if (ec) return false;

        size_t oldSize = respBuf.size();
        respBuf.resize(oldSize + n);
        memcpy(respBuf.data() + oldSize, chunk.data(), n);

        if (!headerDone) {
            auto raw = reinterpret_cast<const char*>(respBuf.data());
            std::string_view sv(raw, respBuf.size());
            auto he = sv.find("\r\n\r\n");
            if (he != std::string_view::npos) {
                headerDone = true;
                headerEndPos = he;
                auto hdr = sv.substr(0, he);
                auto clTag = hdr.find("Content-Length: ");
                if (clTag != std::string_view::npos) {
                    clTag += 16;
                    auto clEnd = hdr.find("\r\n", clTag);
                    if (clEnd != std::string_view::npos) {
                        char clStr[32];
                        size_t clSize = std::min(clEnd - clTag, sizeof(clStr) - 1);
                        memcpy(clStr, raw + clTag, clSize);
                        clStr[clSize] = '\0';
                        contentLength = std::stoul(clStr);
                    }
                }
                if (hdr.find("chunked") != std::string_view::npos) {
                    isChunked = true;
                }
                if (contentLength > 0) {
                    size_t bodySoFar = respBuf.size() - (he + 4);
                    if (bodySoFar >= contentLength) break;
                }
                if (!isChunked && contentLength == 0) break;
            }
        }
        if (contentLength > 0) {
            size_t bodySoFar = respBuf.size() - (headerEndPos + 4);
            if (bodySoFar >= contentLength) break;
        } else if (!isChunked && headerDone) {
            break;
        }
    }

    setSocketTimeout(mc.stream->next_layer(), 2);

    if (respBuf.empty()) {
        return false;
    }

    mc.lastCheck = std::chrono::steady_clock::now();
    mc.failures = 0;
    return true;
}

// Single reconnect worker thread — processes queued reconnects
void ConnectionController::reconnectLoop() {
    while (true) {
        ReconnectWork work;
        {
            std::unique_lock<std::mutex> lk(reconnectMutex_);
            reconnectCv_.wait(lk, [this] {
                return reconnectStop_ || !reconnectQueue_.empty();
            });
            if (reconnectStop_ && reconnectQueue_.empty()) break;
            if (reconnectQueue_.empty()) continue;
            work = std::move(reconnectQueue_.front());
            reconnectQueue_.pop_front();
        }
        reconnectStream(std::move(work));
    }
}

// Reconnect by stream pointer — look up entry under lock, reconnect without lock,
// then update state under lock. Inspired by notifyFailure's existing pattern.
void ConnectionController::reconnectStream(ReconnectWork work) {
    int delayMs = std::min(5 * (1 << std::min(work.retries, 6)), 5000);
    std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));

    ManagedConn snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& mc : managed_) {
            if (mc.stream.get() == work.stream.get()) {
                if (!openFunc_ || !mc.connected) {
                    LOG_INFO("[reconnect] SKIP: no func or null ptr");
                    return;
                }
                if (mc.connected->load()) return;
                snapshot = mc;
                break;
            }
        }
    }
    if (!snapshot.stream) {
        LOG_INFO("[reconnect] SKIP: stream not found in managed_");
        return;
    }

    boost::system::error_code closeEc;
    snapshot.stream->next_layer().close(closeEc);

    boost::system::error_code openEc;
    bool ok = openFunc_(snapshot.host, snapshot.port, snapshot.target,
                       *snapshot.stream, openEc);
    if (ok) {
        enableTcpKeepAlive(snapshot.stream->next_layer());
    } else {
        LOG_INFO("[reconnect] FAIL " + snapshot.host + ":" + snapshot.port +
                 " ec=" + openEc.message() + " retry=" + std::to_string(work.retries));
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& mc : managed_) {
            if (mc.stream.get() == work.stream.get()) {
                if (ok && mc.connected) {
                    mc.reconnectPending = false;
                    mc.connected->store(true);
                    connectedCount_.fetch_add(1);
                    mc.lastUse = std::chrono::steady_clock::now();
                    mc.lastCheck = std::chrono::steady_clock::now();
                    mc.failures = 0;
                } else if (work.retries < 5) {
                    ReconnectWork retry;
                    retry.stream = work.stream;
                    retry.host = work.host;
                    retry.port = work.port;
                    retry.target = work.target;
                    retry.retries = work.retries + 1;
                    {
                        std::lock_guard<std::mutex> lk(reconnectMutex_);
                        reconnectQueue_.push_back(std::move(retry));
                    }
                    reconnectCv_.notify_one();
                } else {
                    mc.reconnectPending = false;
                }
                return;
            }
        }
    }
}
