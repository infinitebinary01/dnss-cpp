// SPDX-License-Identifier: MIT
//
#include "monitor_server.hpp"
#include "perf_monitor.hpp"
#include "auto_tuner.hpp"
#include "latency_manager.hpp"
#include "caching_resolver.hpp"
#include "http_resolver.hpp"
#include "logger.hpp"

#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <fstream>
#include <filesystem>

namespace sys = boost::system;
namespace fs = std::filesystem;
using namespace std::chrono;

MonitorServer::MonitorServer(const std::string& addr,
                             const std::string& wwwRoot,
                             const std::string& logoPath)
    : addr_(addr), wwwRoot_(wwwRoot), logoPath_(logoPath) {
    auto colon = addr.find(':');
    if (colon == std::string::npos) {
        LOG_ERROR("Invalid monitoring address: " + addr);
        return;
    }
    std::string host = colon > 0 ? addr.substr(0, colon) : "127.0.0.1";
    std::string port = addr.substr(colon + 1);
    port_ = std::stoi(port);

    sys::error_code ec;
    asio::ip::tcp::endpoint ep(asio::ip::make_address(host), std::stoi(port));
    acceptor_.open(ep.protocol(), ec);
    if (!ec) {
        acceptor_.set_option(asio::socket_base::reuse_address(true), ec);
        acceptor_.bind(ep, ec);
    }
    if (!ec) {
        acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    }
    if (ec) {
        LOG_ERROR("Monitor server bind failed on " + addr + ": " + ec.message());
        acceptor_.close(ec);
    }
}

MonitorServer::~MonitorServer() {
    stop();
}

void MonitorServer::start() {
    if (!acceptor_.is_open()) return;
    running_ = true;
    acceptThread_ = std::thread([self = shared_from_this()] { self->acceptLoop(); });
    LOG_INFO("Monitor server listening on " + addr_);
}

void MonitorServer::stop() {
    running_ = false;
    sys::error_code ec;
    if (port_ > 0) {
        try {
            asio::io_context tmpCtx;
            asio::ip::tcp::socket kicker(tmpCtx);
            kicker.connect(asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), port_), ec);
        } catch (...) {}
    }
    acceptor_.close(ec);
    ctx_.stop();
    if (acceptThread_.joinable())
        acceptThread_.join();
}

void MonitorServer::acceptLoop() {
    auto self = shared_from_this();
    while (running_) {
        try {
            auto sock = std::make_shared<asio::ip::tcp::socket>(ctx_);
            sys::error_code ec;
            acceptor_.accept(*sock, ec);
            if (ec) {
                if (running_) {
                    LOG_DEBUG("Monitor accept error: " + ec.message());
                }
                continue;
            }
            std::thread t([self, sock] { self->handleRequest(sock); });
            t.detach();
        } catch (const std::exception& e) {
            LOG_ERROR("Monitor server error: " + std::string(e.what()));
        }
    }
}

void MonitorServer::handleRequest(std::shared_ptr<asio::ip::tcp::socket> sock) {
    try {
        std::array<char, 4096> buf;
        sys::error_code ec;
        size_t n = sock->read_some(asio::buffer(buf), ec);
        if (ec || n == 0) return;

        std::string req(buf.data(), n);
        std::string method, path;
        {
            std::istringstream ss(req);
            ss >> method >> path;
        }

        // SSE stream — push JSON every 1s, keep connection alive
        if (path == "/api/stream") {
            handleStream(sock);
            return;
        }

        std::string body;
        std::string contentType;
        std::string statusLine;

        if (path == "/health") {
            body = renderHealth();
            contentType = "text/plain";
            statusLine = "HTTP/1.1 200 OK\r\n";
        } else if (path == "/metrics") {
            body = renderPrometheus();
            contentType = "text/plain; version=0.0.4";
            statusLine = "HTTP/1.1 200 OK\r\n";
        } else if (path == "/api/stats") {
            body = renderJson();
            contentType = "application/json";
            statusLine = "HTTP/1.1 200 OK\r\n";
        } else if (path == "/logo.png" && !logoPath_.empty()) {
            std::ifstream f(logoPath_, std::ios::binary | std::ios::ate);
            if (f) {
                size_t sz = f.tellg();
                f.seekg(0);
                body.resize(sz, '\0');
                f.read(body.data(), sz);
                contentType = "image/png";
                statusLine = "HTTP/1.1 200 OK\r\n";
            } else {
                body = "404 Not Found";
                contentType = "text/plain";
                statusLine = "HTTP/1.1 404 Not Found\r\n";
            }
        } else {
            std::string servePath = (path == "/") ? "/index.html" : path;
            body = serveFile(servePath);
            if (!body.empty()) {
                contentType = contentTypeFor(servePath);
                statusLine = "HTTP/1.1 200 OK\r\n";
            } else {
                body = "404 Not Found";
                contentType = "text/plain";
                statusLine = "HTTP/1.1 404 Not Found\r\n";
            }
        }

        std::ostringstream resp;
        resp << statusLine
             << "Content-Type: " << contentType << "\r\n"
             << "Content-Length: " << body.size() << "\r\n"
             << "Connection: close\r\n"
             << "\r\n"
             << body;
        auto respStr = resp.str();
        asio::write(*sock, asio::buffer(respStr), ec);
    } catch (const std::exception& e) {
        LOG_DEBUG("Monitor request error: " + std::string(e.what()));
    }
    try {
        sys::error_code ec;
        sock->close(ec);
    } catch (...) {}
}

void MonitorServer::handleStream(std::shared_ptr<asio::ip::tcp::socket> sock) {
    try {
        std::string header =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n";
        asio::write(*sock, asio::buffer(header));

        while (running_) {
            std::string json = renderJson();
            std::string msg = "data: " + json + "\n\n";
            sys::error_code ec;
            asio::write(*sock, asio::buffer(msg), ec);
            if (ec) break;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } catch (...) {}
    try {
        sys::error_code ec;
        sock->close(ec);
    } catch (...) {}
}

std::string MonitorServer::serveFile(const std::string& path) {
    // Sanitize path — prevent directory traversal
    std::string clean = path;
    if (clean.find("..") != std::string::npos) return {};

    std::string filePath = wwwRoot_ + clean;
    if (!fs::exists(filePath) || !fs::is_regular_file(filePath)) return {};

    std::ifstream f(filePath, std::ios::binary);
    if (!f) return {};
    std::string content((std::istreambuf_iterator<char>(f)), {});
    return content;
}

std::string MonitorServer::contentTypeFor(const std::string& path) {
    auto dot = path.rfind('.');
    if (dot == std::string::npos) return "application/octet-stream";
    std::string ext = path.substr(dot);
    if (ext == ".html") return "text/html; charset=utf-8";
    if (ext == ".css")  return "text/css; charset=utf-8";
    if (ext == ".js")   return "application/javascript; charset=utf-8";
    if (ext == ".json") return "application/json";
    if (ext == ".png")  return "image/png";
    if (ext == ".svg")  return "image/svg+xml";
    if (ext == ".ico")  return "image/x-icon";
    return "application/octet-stream";
}

std::string MonitorServer::htmlEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '&': out += "&amp;"; break;
            case '"': out += "&quot;"; break;
            default: out += c;
        }
    }
    return out;
}

static std::string timeStr() {
    auto t = system_clock::to_time_t(system_clock::now());
    struct tm tmBuf;
    auto tm = *localtime_r(&t, &tmBuf);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string MonitorServer::renderPrometheus() {
    auto perf = PerfMonitor::instance().snapshot();
    auto& tuner = AutoTuner::instance();

    std::ostringstream out;
    out << "# HELP lynx_avg_latency_ms Average query latency\n"
        << "# TYPE lynx_avg_latency_ms gauge\n"
        << "lynx_avg_latency_ms " << perf.avgLatencyMs << "\n\n"
        << "# HELP lynx_p95_latency_ms P95 query latency\n"
        << "# TYPE lynx_p95_latency_ms gauge\n"
        << "lynx_p95_latency_ms " << perf.p95LatencyMs << "\n\n"
        << "# HELP lynx_cache_hit_rate Cache hit rate (0-1)\n"
        << "# TYPE lynx_cache_hit_rate gauge\n"
        << "lynx_cache_hit_rate " << perf.cacheHitRate << "\n\n"
        << "# HELP lynx_error_rate Error rate (0-1)\n"
        << "# TYPE lynx_error_rate gauge\n"
        << "lynx_error_rate " << perf.errorRate << "\n\n"
        << "# HELP lynx_conn_utilization Connection utilization (0-1)\n"
        << "# TYPE lynx_conn_utilization gauge\n"
        << "lynx_conn_utilization " << perf.connUtilization << "\n\n"
        << "# HELP lynx_active_connections Active upstream connections\n"
        << "# TYPE lynx_active_connections gauge\n"
        << "lynx_active_connections " << perf.activeConnections << "\n\n"
        << "# HELP lynx_recommended_connections Auto-tuner recommended connections\n"
        << "# TYPE lynx_recommended_connections gauge\n"
        << "lynx_recommended_connections " << tuner.recommendedConnections() << "\n\n"
        << "# HELP lynx_recommended_threads Auto-tuner recommended threads\n"
        << "# TYPE lynx_recommended_threads gauge\n"
        << "lynx_recommended_threads " << tuner.recommendedThreads() << "\n\n"
        << "# HELP lynx_cache_refresh_pct Cache refresh threshold percent\n"
        << "# TYPE lynx_cache_refresh_pct gauge\n"
        << "lynx_cache_refresh_pct " << tuner.cacheRefreshThresholdPct() << "\n\n"
        << "# HELP lynx_fan_out_enabled Whether parallel fan-out is active\n"
        << "# TYPE lynx_fan_out_enabled gauge\n"
        << "lynx_fan_out_enabled " << (tuner.fanOutEnabled() ? "1" : "0") << "\n\n"
        << "# HELP lynx_thread_pool_load Pending tasks in thread pool\n"
        << "# TYPE lynx_thread_pool_load gauge\n"
        << "lynx_thread_pool_load " << perf.threadPoolLoad << "\n"
        << "# HELP lynx_thread_pool_workers Actual worker threads\n"
        << "# TYPE lynx_thread_pool_workers gauge\n"
        << "lynx_thread_pool_workers " << perf.threadPoolWorkers << "\n";
    return out.str();
}

std::string MonitorServer::renderJson() {
    auto perf = PerfMonitor::instance().snapshot();
    auto& tuner = AutoTuner::instance();

    std::ostringstream j;
    j << std::fixed << std::setprecision(2);
    j << "{"
      << "\"timestamp\":\"" << timeStr() << "\","
      << "\"latency\":{"
        << "\"avg_ms\":" << perf.avgLatencyMs << ","
        << "\"p95_ms\":" << perf.p95LatencyMs
      << "},"
      << "\"cache\":{"
        << "\"hit_rate\":" << perf.cacheHitRate << ","
        << "\"turbo_hit_rate\":" << perf.turboHitRate << ","
        << "\"stale_hit_rate\":" << perf.staleHitRate
      << "},"
      << "\"errors\":{"
        << "\"rate\":" << perf.errorRate
      << "},"
      << "\"connections\":{"
        << "\"active\":" << perf.activeConnections << ","
        << "\"recommended\":" << tuner.recommendedConnections() << ","
        << "\"utilization\":" << perf.connUtilization
      << "},"
      << "\"thread_pool\":{"
        << "\"pending\":" << perf.threadPoolLoad << ","
        << "\"workers\":" << perf.threadPoolWorkers << ","
        << "\"recommended\":" << tuner.recommendedThreads()
      << "},"
      << "\"latency_manager\":{"
        << "\"target_avg_ms\":" << LatencyManager::instance().targetAvgMs() << ","
        << "\"target_p95_ms\":" << LatencyManager::instance().targetP95Ms() << ","
        << "\"urgency\":" << LatencyManager::instance().urgencyLevel() << ","
        << "\"gap_pct\":" << LatencyManager::instance().gapPct() << ","
        << "\"bottleneck\":\"" << LatencyManager::instance().bottleneck() << "\""
      << "},"
      << "\"auto_tuner\":{"
        << "\"cache_refresh_pct\":" << tuner.cacheRefreshThresholdPct() << ","
        << "\"fan_out\":" << (tuner.fanOutEnabled() ? "true" : "false") << ","
        << "\"latency_trend\":" << tuner.trendSlope() << ","
        << "\"qps\":" << tuner.currentQps() << ","
        << "\"connection_growth\":0,"
        << "\"connection_growth_per_cycle\":0,"
        << "\"total_queries\":" << PerfMonitor::instance().totalQueries() << ","
        << "\"min_ttl_secs\":" << CachingResolver::getMinTTL() << ","
        << "\"negative_ttl_secs\":" << CachingResolver::getNegativeTTL()
      << "},"
      << "\"upstream_health\":{"
        << "\"pools\":[";

    if (HttpResolver::instance()) {
        auto pools = HttpResolver::instance()->getPoolStats();
        bool first = true;
        for (auto& ps : pools) {
            if (!first) j << ",";
            first = false;
            j << "{"
              << "\"host\":\"" << ps.host << "\","
              << "\"port\":\"" << ps.port << "\","
              << "\"ip\":\"" << ps.remoteAddr << "\","
              << "\"connected\":" << ps.connected << ","
              << "\"total\":" << ps.total << ","
              << "\"err\":" << ps.errors << ","
              << "\"ok\":" << ps.successes << ","
              << "\"error_ratio\":" << ps.errorRatio
              << "}";
        }
    }

    j << "]}}";
    return j.str();
}

std::string MonitorServer::renderHealth() {
    return "OK";
}
