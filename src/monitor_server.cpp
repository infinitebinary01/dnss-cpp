// SPDX-License-Identifier: MIT
//
#include "monitor_server.hpp"
#include "perf_monitor.hpp"
#include "auto_tuner.hpp"
#include "caching_resolver.hpp"
#include "logger.hpp"

#include <sstream>
#include <iomanip>
#include <ctime>
#include <chrono>

namespace sys = boost::system;

using namespace std::chrono;

MonitorServer::MonitorServer(const std::string& addr) : addr_(addr) {
    auto colon = addr.find(':');
    if (colon == std::string::npos) {
        LOG_ERROR("Invalid monitoring address: " + addr);
        return;
    }
    std::string host = colon > 0 ? addr.substr(0, colon) : "0.0.0.0";
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
    }
}

MonitorServer::~MonitorServer() {
    stop();
}

void MonitorServer::start() {
    if (!acceptor_.is_open()) return;
    running_ = true;
    acceptThread_ = std::thread([this] { acceptLoop(); });
    LOG_INFO("Monitor server listening on " + addr_);
}

void MonitorServer::stop() {
    running_ = false;
    sys::error_code ec;
    // Self-connect to unblock accept() if close() doesn't wake it (POSIX-reliable)
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
    try {
        while (running_) {
            auto sock = std::make_shared<asio::ip::tcp::socket>(ctx_);
            sys::error_code ec;
            acceptor_.accept(*sock, ec);
            if (ec) {
                if (running_) {
                    LOG_DEBUG("Monitor accept error: " + ec.message());
                }
                break;
            }
            std::thread t(&MonitorServer::handleRequest, this, sock);
            t.detach();
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Monitor server error: " + std::string(e.what()));
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
        } else if (path == "/" || path.empty()) {
            body = renderDashboard();
            contentType = "text/html; charset=utf-8";
            statusLine = "HTTP/1.1 200 OK\r\n";
        } else {
            body = "404 Not Found";
            contentType = "text/plain";
            statusLine = "HTTP/1.1 404 Not Found\r\n";
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
    sys::error_code ec;
    sock->close(ec);
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
    auto tm = *std::localtime(&t);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string MonitorServer::renderDashboard() {
    return R"foo(<!DOCTYPE html>
<html>
<head>
<title>dnss-cpp Monitor</title>
<meta charset='utf-8'>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f5f7fa;color:#2c3e50;padding:30px;}
h1{font-size:24px;font-weight:600;color:#1a73e8;margin-bottom:4px;}
.subtitle{color:#5f6368;font-size:13px;margin-bottom:24px;}
.cards{display:flex;flex-wrap:wrap;gap:16px;margin-bottom:24px;}
.card{background:#fff;border-radius:10px;padding:18px 22px;box-shadow:0 1px 3px rgba(0,0,0,0.08);flex:1;min-width:200px;border:1px solid #e8eaed;}
.card h2{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:#5f6368;margin-bottom:12px;}
.card table{width:100%;border-collapse:collapse;}
.card td{padding:5px 0;font-size:13px;}
.card td:first-child{color:#5f6368;}
.card td:last-child{font-weight:600;text-align:right;font-variant-numeric:tabular-nums;}
.good{color:#188038!important;}
.warn{color:#ea8600!important;}
.bad{color:#d93025!important;}
.bars{display:flex;flex-direction:column;gap:14px;}
.bar-label{font-size:13px;color:#5f6368;margin-bottom:3px;}
.bar-track{height:8px;background:#e8eaed;border-radius:4px;overflow:hidden;}
.bar-fill{height:100%;border-radius:4px;transition:width 1s ease;}
.footer{margin-top:32px;padding-top:16px;border-top:1px solid #e8eaed;font-size:13px;color:#5f6368;}
.footer a{color:#1a73e8;text-decoration:none;margin-right:16px;}
.footer a:hover{text-decoration:underline;}
</style>
</head>
<body>
<h1>dnss-cpp Monitor</h1>
<p class='subtitle'>Last updated: <span id='ts'>-</span></p>

<div class='cards'>
<div class='card'>
<h2>Latency</h2>
<table>
<tr><td>Avg</td><td id='lat-avg' class='good'>-</td></tr>
<tr><td>P95</td><td id='lat-p95' class='good'>-</td></tr>
<tr><td>Errors</td><td id='err-rate' class='good'>-</td></tr>
</table>
</div>

<div class='card'>
<h2>Cache &mdash; Dual Tier</h2>
<table>
<tr><td>L1 Turbo</td><td id='turbo-hit' class='good'>-</td></tr>
<tr><td>L2 Main</td><td id='l2-hit'>-</td></tr>
<tr><td>Total Hit</td><td id='cache-hit'>-</td></tr>
<tr><td>Refresh</td><td id='cache-refresh'>-</td></tr>
</table>
</div>

<div class='card'>
<h2>Connections</h2>
<table>
<tr><td>Active</td><td id='conn-active'>-</td></tr>
<tr><td>Utilization</td><td id='conn-util'>-</td></tr>
</table>
</div>

<div class='card'>
<h2>Thread Pool</h2>
<table>
<tr><td>Pending</td><td id='pool-pending'>-</td></tr>
<tr><td>Allocated</td><td id='pool-threads'>-</td></tr>
</table>
</div>

<div class='card'>
<h2>Auto-Tuner</h2>
<table>
<tr><td>Connections</td><td id='tuner-conn'>-</td></tr>
<tr><td>Threads</td><td id='tuner-threads'>-</td></tr>
<tr><td>Refresh</td><td id='tuner-refresh'>-</td></tr>
<tr><td>Fan-Out</td><td id='tuner-fanout'>-</td></tr>
</table>
</div>
</div>

<div class='card'>
<h2>Resource Usage</h2>
<div class='bars'>
<div>
<div class='bar-label'>Connections (<span id='bar-conn-active'>0</span>/<span id='bar-conn-total'>0</span>)</div>
<div class='bar-track'><div id='bar-conn-fill' class='bar-fill' style='width:0%;background:#1a73e8;'></div></div>
</div>
<div>
<div class='bar-label'>Thread Pool (<span id='bar-pool-pending'>0</span> pending)</div>
<div class='bar-track'><div id='bar-pool-fill' class='bar-fill' style='width:0%;background:#ea8600;'></div></div>
</div>
<div>
<div class='bar-label'>L1 Turbo Hit Rate (<span id='bar-turbo-rate'>0</span>%)</div>
<div class='bar-track'><div id='bar-turbo-fill' class='bar-fill' style='width:0%;background:#1a73e8;'></div></div>
</div>
<div>
<div class='bar-label'>L2 Main Hit Rate (<span id='bar-l2-rate'>0</span>%)</div>
<div class='bar-track'><div id='bar-l2-fill' class='bar-fill' style='width:0%;background:#188038;'></div></div>
</div>
</div>
</div>

<div class='footer'>
<a href='/metrics'>Prometheus Metrics</a>
<a href='/api/stats'>JSON API</a>
<a href='/health'>Health Check</a>
</div>

<script>
function update() {
  var r = new XMLHttpRequest();
  r.onload = function() {
    if (r.status !== 200) return;
    var d = JSON.parse(r.responseText);
    var ts = new Date().toISOString().slice(11,19);
    function q(id) { return document.getElementById(id); }
    function cls(id, c) { q(id).className = c; }
    function v(id, val) { q(id).textContent = val; }
    function css(id, p, val) { q(id).style[p] = val; }

    v('ts', ts);

    var avg = d.latency.avg_ms, p95 = d.latency.p95_ms;
    var er = d.errors.rate, hr = d.cache.hit_rate, thr = d.cache.turbo_hit_rate;
    var active = d.connections.active, total = d.connections.recommended;
    var util = d.connections.utilization;
    var pending = d.thread_pool.pending, threads = d.thread_pool.recommended;
    var refresh = d.auto_tuner.cache_refresh_pct;
    var fanout = d.auto_tuner.fan_out;

    v('lat-avg', avg.toFixed(1) + ' ms');
    cls('lat-avg', avg < 100 ? 'good' : avg < 500 ? 'warn' : 'bad');
    v('lat-p95', p95.toFixed(1) + ' ms');
    cls('lat-p95', p95 < 200 ? 'good' : p95 < 1000 ? 'warn' : 'bad');
    v('err-rate', (er*100).toFixed(2) + '%');
    cls('err-rate', er < 0.05 ? 'good' : 'bad');

    var l2r = Math.max(0, hr - thr);
    v('cache-hit', (hr*100).toFixed(1) + '%');
    cls('cache-hit', hr > 0.5 ? 'good' : 'warn');
    v('turbo-hit', (thr*100).toFixed(1) + '%');
    cls('turbo-hit', thr > 0.3 ? 'good' : 'warn');
    v('l2-hit', (l2r*100).toFixed(1) + '%');
    cls('l2-hit', l2r > 0.3 ? 'good' : 'warn');
    v('cache-refresh', refresh + '%');

    v('conn-active', active + ' / ' + total);
    v('conn-util', (util*100).toFixed(1) + '%');
    v('pool-pending', pending);
    v('pool-threads', threads);

    v('tuner-conn', total);
    v('tuner-threads', threads);
    v('tuner-refresh', refresh + '%');
    v('tuner-fanout', fanout ? 'enabled' : 'disabled');

    v('bar-conn-active', active);
    v('bar-conn-total', total);
    css('bar-conn-fill', 'width', (total > 0 ? (active/total*100) : 0).toFixed(0) + '%');
    v('bar-pool-pending', pending);
    css('bar-pool-fill', 'width', Math.min(pending*10, 100).toFixed(0) + '%');
    v('bar-hit-rate', (hr*100).toFixed(1));
    css('bar-hit-fill', 'width', (hr*100).toFixed(0) + '%');
    v('bar-turbo-rate', (thr*100).toFixed(1));
    css('bar-turbo-fill', 'width', (thr*100).toFixed(0) + '%');
    var l2pct = Math.max(0, (hr - thr)*100);
    v('bar-l2-rate', l2pct.toFixed(1));
    css('bar-l2-fill', 'width', l2pct.toFixed(0) + '%');
  };
  r.open('GET', '/api/stats', true);
  r.send();
}
update();
setInterval(update, 2000);
</script>
</body>
</html>)foo";
}

std::string MonitorServer::renderPrometheus() {
    auto perf = PerfMonitor::instance().snapshot();
    auto& tuner = AutoTuner::instance();

    std::ostringstream out;
    out << "# HELP dnss_avg_latency_ms Average query latency\n"
        << "# TYPE dnss_avg_latency_ms gauge\n"
        << "dnss_avg_latency_ms " << perf.avgLatencyMs << "\n\n"
        << "# HELP dnss_p95_latency_ms P95 query latency\n"
        << "# TYPE dnss_p95_latency_ms gauge\n"
        << "dnss_p95_latency_ms " << perf.p95LatencyMs << "\n\n"
        << "# HELP dnss_cache_hit_rate Cache hit rate (0-1)\n"
        << "# TYPE dnss_cache_hit_rate gauge\n"
        << "dnss_cache_hit_rate " << perf.cacheHitRate << "\n\n"
        << "# HELP dnss_error_rate Error rate (0-1)\n"
        << "# TYPE dnss_error_rate gauge\n"
        << "dnss_error_rate " << perf.errorRate << "\n\n"
        << "# HELP dnss_conn_utilization Connection utilization (0-1)\n"
        << "# TYPE dnss_conn_utilization gauge\n"
        << "dnss_conn_utilization " << perf.connUtilization << "\n\n"
        << "# HELP dnss_active_connections Active upstream connections\n"
        << "# TYPE dnss_active_connections gauge\n"
        << "dnss_active_connections " << perf.activeConnections << "\n\n"
        << "# HELP dnss_recommended_connections Auto-tuner recommended connections\n"
        << "# TYPE dnss_recommended_connections gauge\n"
        << "dnss_recommended_connections " << tuner.recommendedConnections() << "\n\n"
        << "# HELP dnss_recommended_threads Auto-tuner recommended threads\n"
        << "# TYPE dnss_recommended_threads gauge\n"
        << "dnss_recommended_threads " << tuner.recommendedThreads() << "\n\n"
        << "# HELP dnss_cache_refresh_pct Cache refresh threshold percent\n"
        << "# TYPE dnss_cache_refresh_pct gauge\n"
        << "dnss_cache_refresh_pct " << tuner.cacheRefreshThresholdPct() << "\n\n"
        << "# HELP dnss_fan_out_enabled Whether parallel fan-out is active\n"
        << "# TYPE dnss_fan_out_enabled gauge\n"
        << "dnss_fan_out_enabled " << (tuner.fanOutEnabled() ? "1" : "0") << "\n\n"
        << "# HELP dnss_thread_pool_load Pending tasks in thread pool\n"
        << "# TYPE dnss_thread_pool_load gauge\n"
        << "dnss_thread_pool_load " << perf.threadPoolLoad << "\n";
    return out.str();
}

std::string MonitorServer::renderJson() {
    auto perf = PerfMonitor::instance().snapshot();
    auto& tuner = AutoTuner::instance();

    std::ostringstream json;
    json << std::fixed << std::setprecision(2);
    json << "{\n"
         << "  \"timestamp\": \"" << timeStr() << "\",\n"
         << "  \"latency\": {\n"
         << "    \"avg_ms\": " << perf.avgLatencyMs << ",\n"
         << "    \"p95_ms\": " << perf.p95LatencyMs << "\n"
         << "  },\n"
          << "  \"cache\": {\n"
         << "    \"hit_rate\": " << perf.cacheHitRate << ",\n"
         << "    \"turbo_hit_rate\": " << perf.turboHitRate << "\n"
         << "  },\n"
         << "  \"errors\": {\n"
         << "    \"rate\": " << perf.errorRate << "\n"
         << "  },\n"
         << "  \"connections\": {\n"
         << "    \"active\": " << perf.activeConnections << ",\n"
         << "    \"recommended\": " << tuner.recommendedConnections() << ",\n"
         << "    \"utilization\": " << perf.connUtilization << "\n"
         << "  },\n"
         << "  \"thread_pool\": {\n"
         << "    \"pending\": " << perf.threadPoolLoad << ",\n"
         << "    \"recommended\": " << tuner.recommendedThreads() << "\n"
         << "  },\n"
         << "  \"auto_tuner\": {\n"
         << "    \"cache_refresh_pct\": " << tuner.cacheRefreshThresholdPct() << ",\n"
         << "    \"fan_out\": " << (tuner.fanOutEnabled() ? "true" : "false") << "\n"
         << "  }\n"
         << "}\n";
    return json.str();
}

std::string MonitorServer::renderHealth() {
    return "OK";
}
