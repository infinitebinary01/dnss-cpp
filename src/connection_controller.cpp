// SPDX-License-Identifier: MIT
//
#include "connection_controller.hpp"
#include "logger.hpp"
#include "dns_protocol.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <thread>
#include <chrono>
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
}

void ConnectionController::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
}

void ConnectionController::manage(const std::string& host, const std::string& port,
                                   const std::string& target,
                                   asio::ssl::stream<asio::ip::tcp::socket>* stream,
                                   std::atomic<bool>* connected) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    managed_.push_back({host, port, target, stream, connected, now, now, 0, false});
    totalCount_.store(managed_.size());
    if (connected && connected->load()) {
        connectedCount_.fetch_add(1);
        boost::system::error_code ec;
        stream->next_layer().non_blocking(false, ec);
        enableTcpKeepAlive(stream->next_layer());
    }
}

void ConnectionController::unmanage(asio::ssl::stream<asio::ip::tcp::socket>* stream) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (size_t i = 0; i < managed_.size(); ++i) {
        if (managed_[i].stream == stream) {
            if (managed_[i].connected && managed_[i].connected->load())
                connectedCount_.fetch_sub(1);
            managed_.erase(managed_.begin() + i);
            totalCount_.store(managed_.size());
            return;
        }
    }
}

void ConnectionController::notifyUsed(asio::ssl::stream<asio::ip::tcp::socket>* stream) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& mc : managed_) {
        if (mc.stream == stream) {
            mc.lastUse = std::chrono::steady_clock::now();
            mc.failures = 0;
            return;
        }
    }
}

void ConnectionController::notifyFailure(asio::ssl::stream<asio::ip::tcp::socket>* stream) {
    std::string host, port, target;
    asio::ssl::stream<asio::ip::tcp::socket>* strm = nullptr;
    size_t idx = 0;
    bool shouldReconnect = false;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (size_t i = 0; i < managed_.size(); ++i) {
            if (managed_[i].stream == stream) {
                managed_[i].failures++;
                if (managed_[i].connected && managed_[i].connected->exchange(false))
                    connectedCount_.fetch_sub(1);
                if (!managed_[i].reconnectPending) {
                    managed_[i].reconnectPending = true;
                    host = managed_[i].host;
                    port = managed_[i].port;
                    target = managed_[i].target;
                    strm = managed_[i].stream;
                    idx = i;
                    shouldReconnect = true;
                }
                return;
            }
        }
    }

    if (shouldReconnect && strm) {
        std::thread([this, host, port, target, strm, idx]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            if (!openFunc_) return;
            boost::system::error_code ec;
            strm->next_layer().close(ec);
            bool ok = openFunc_(host, port, target, *strm, ec);
            if (ok) enableTcpKeepAlive(strm->next_layer());
            std::lock_guard<std::mutex> lock(mutex_);
            if (idx < managed_.size() && managed_[idx].stream == strm) {
                managed_[idx].reconnectPending = false;
                if (ok && managed_[idx].connected) {
                    managed_[idx].connected->store(true);
                    connectedCount_.fetch_add(1);
                    managed_[idx].lastUse = std::chrono::steady_clock::now();
                    managed_[idx].lastCheck = std::chrono::steady_clock::now();
                    managed_[idx].failures = 0;
                }
            }
        }).detach();
    }

}

void ConnectionController::probeAllIdle() {
    struct Work {
        size_t idx;
        asio::ssl::stream<asio::ip::tcp::socket>* stream;
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
        std::thread([this, idx = w.idx, strm = w.stream, mc = w.snapshot]() {
            ManagedConn local = mc;
            local.stream = strm;
            if (!healthCheck(local)) {
                LOG_DEBUG("Idle connection failed health check, reconnecting...");
                boost::system::error_code ec;
                if (strm) strm->next_layer().close(ec);
                std::lock_guard<std::mutex> lock(mutex_);
                if (idx < managed_.size() && managed_[idx].stream == strm) {
                    if (managed_[idx].connected && managed_[idx].connected->exchange(false))
                        connectedCount_.fetch_sub(1);
                    if (!managed_[idx].reconnectPending) {
                        managed_[idx].reconnectPending = true;
                        std::thread([this, idx]() {
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            std::lock_guard<std::mutex> lk(mutex_);
                            reconnectAsync(idx);
                        }).detach();
                    }
                }
            }
        }).detach();
    }
}

// ---------- Background maintenance ----------

void ConnectionController::run() {
    while (running_) {
        std::this_thread::sleep_for(MAINTAIN_INTERVAL);

        struct Work {
            size_t idx;
            asio::ssl::stream<asio::ip::tcp::socket>* stream;
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
                boost::system::error_code ec;
                if (w.stream) w.stream->next_layer().close(ec);
                std::lock_guard<std::mutex> lock(mutex_);
                if (w.idx < managed_.size() && managed_[w.idx].stream == w.stream) {
                    if (managed_[w.idx].connected && managed_[w.idx].connected->exchange(false))
                        connectedCount_.fetch_sub(1);
                    if (!managed_[w.idx].reconnectPending) {
                        managed_[w.idx].reconnectPending = true;
                        std::thread([this, idx = w.idx]() {
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            std::lock_guard<std::mutex> lk(mutex_);
                            reconnectAsync(idx);
                        }).detach();
                    }
                }
            }
        }

        for (auto& idx : reconnects) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (idx < managed_.size()) {
                reconnectAsync(idx);
            }
        }
    }
}

// ---------- Health check ----------

std::vector<uint8_t> ConnectionController::makeHealthQuery() {
    std::vector<uint8_t> buf(17, 0);
    buf[0] = 0x00; buf[1] = 0x00;
    buf[2] = 0x01; buf[3] = 0x00;
    buf[4] = 0x00; buf[5] = 0x01;
    buf[8] = 0x00; buf[9] = 0x00;
    buf[10] = 0x00; buf[11] = 0x00;
    buf.push_back(0x00);
    buf.push_back(0x00); buf.push_back(0x01);
    buf.push_back(0x00); buf.push_back(0x01);
    return buf;
}

bool ConnectionController::healthCheck(ManagedConn& mc) {
    if (!mc.stream || !mc.connected || !mc.connected->load()) return false;

    boost::system::error_code ec;

    setSocketTimeout(mc.stream->next_layer(), HEALTH_TIMEOUT_SEC);

    auto wire = makeHealthQuery();

    std::ostringstream oss;
    oss << "POST " << mc.target << " HTTP/1.1\r\n"
        << "Host: " << mc.host << "\r\n"
        << "User-Agent: dnss-cpp/0.1\r\n"
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

    setSocketTimeout(mc.stream->next_layer(), 2);

    if (respBuf.empty()) {
        return false;
    }

    mc.lastCheck = std::chrono::steady_clock::now();
    mc.failures = 0;
    return true;
}

// Caller MUST hold mutex_
void ConnectionController::reconnectAsync(size_t idx) {
    if (idx >= managed_.size()) return;
    auto& mc = managed_[idx];
    if (!openFunc_ || !mc.stream || !mc.connected) return;

    boost::system::error_code ec;
    mc.stream->next_layer().close(ec);

    bool ok = openFunc_(mc.host, mc.port, mc.target, *mc.stream, ec);
    if (ok) enableTcpKeepAlive(mc.stream->next_layer());

    mc.reconnectPending = false;
    if (ok && mc.connected) {
        mc.connected->store(true);
        connectedCount_.fetch_add(1);
        mc.lastUse = std::chrono::steady_clock::now();
        mc.lastCheck = std::chrono::steady_clock::now();
        mc.failures = 0;
    }
}
