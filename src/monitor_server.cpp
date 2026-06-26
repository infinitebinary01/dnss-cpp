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
<title>dnss-cpp v0.2 — Nexus</title>
<meta charset='utf-8'>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'JetBrains Mono',monospace;background:#2d3037;color:#b3b1ad;padding:20px;overflow-x:hidden;min-height:100vh;}
/* Matrix rain canvas */
#matrix{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none;opacity:0.05;}
.container{position:relative;z-index:1;max-width:1200px;margin:0 auto;}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding:12px 16px;border:1px solid #3d4048;background:rgba(45,48,55,0.9);}
.header h1{font-size:18px;font-weight:700;color:#00ff41;text-shadow:0 0 10px rgba(0,255,65,0.3);}
.header h1::before{content:'> ';color:#0ae;}.header .ts{color:#5c6370;font-size:12px;}
.header .ts span{color:#00ff41;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-bottom:16px;}
.card{background:rgba(52,56,64,0.9);border:1px solid #3d4048;padding:14px 16px;position:relative;overflow:hidden;}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,#0ae,transparent);}
.card h2{font-size:10px;font-weight:700;color:#5c6370;text-transform:uppercase;letter-spacing:2px;margin-bottom:10px;}
.card h2::after{content:' []';color:#00ff41;font-size:8px;}
.stat-row{display:flex;justify-content:space-between;padding:4px 0;font-size:12px;border-bottom:1px solid rgba(26,31,41,0.5);}
.stat-row:last-child{border-bottom:none;}
.stat-label{color:#5c6370;}.stat-value{font-weight:700;font-variant-numeric:tabular-nums;}
.good{color:#00ff41;text-shadow:0 0 6px rgba(0,255,65,0.3);}
.warn{color:#e6db74;text-shadow:0 0 6px rgba(230,219,116,0.2);}
.bad{color:#ff5555;text-shadow:0 0 6px rgba(255,85,85,0.3);}
.cyan{color:#0ae;text-shadow:0 0 6px rgba(0,170,238,0.2);}
.magenta{color:#ff79c6;text-shadow:0 0 6px rgba(255,121,198,0.2);}
/* Bar charts */
.bar-track{background:#1a1f29;height:4px;border-radius:2px;margin:6px 0;overflow:hidden;}
.bar-fill{height:100%;border-radius:2px;transition:width 0.5s ease;}
.bar-good{background:#00ff41;}.bar-warn{background:#e6db74;}.bar-bad{background:#ff5555;}.bar-cyan{background:#0ae;}
.bottom-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;}
.footer{margin-top:16px;padding:10px 16px;border:1px solid #3d4048;font-size:11px;color:#5c6370;background:rgba(52,56,64,0.9);}
.footer a{color:#0ae;text-decoration:none;margin-right:20px;}.footer a:hover{text-shadow:0 0 8px rgba(0,170,238,0.5);}
/* Sparklines */
.sparkline{display:flex;align-items:flex-end;gap:2px;height:30px;padding:4px 0;}
.sparkline .bar{width:6px;border-radius:1px;transition:height 0.3s ease;min-height:2px;}
</style>
</head>
<body>
<canvas id='matrix'></canvas>
<div class='container'>
<div class='header'>
<h1>dnss-cpp nexus</h1>
<div class='ts'>SYS::UPTIME <span id='ts'>--:--:--</span></div>
</div>

<div class='grid'>
<div class='card'>
<h2>LATENCY</h2>
<div class='stat-row'><span class='stat-label'>AVG</span><span class='stat-value good' id='lat-avg'>--</span></div>
<div class='stat-row'><span class='stat-label'>P95</span><span class='stat-value' id='lat-p95'>--</span></div>
<div class='stat-row'><span class='stat-label'>ERRORS</span><span class='stat-value good' id='err-rate'>--</span></div>
<div class='stat-row'><span class='stat-label'>QPS</span><span class='stat-value cyan' id='qps'>--</span></div>
</div>

<div class='card'>
<h2>CACHE TIERS</h2>
<div class='stat-row'><span class='stat-label'>L1 TURBO</span><span class='stat-value good' id='turbo-hit'>--</span></div>
<div class='stat-row'><span class='stat-label'>L2 MAIN</span><span class='stat-value' id='l2-hit'>--</span></div>
<div class='stat-row'><span class='stat-label'>TOTAL HIT</span><span class='stat-value' id='cache-hit'>--</span></div>
<div class='stat-row'><span class='stat-label'>REFRESH</span><span class='stat-value cyan' id='cache-refresh'>--</span></div>
</div>

<div class='card'>
<h2>CONNECTIONS</h2>
<div class='stat-row'><span class='stat-label'>ACTIVE</span><span class='stat-value' id='conn-active'>--</span></div>
<div class='stat-row'><span class='stat-label'>UTILIZATION</span><span class='stat-value good' id='conn-util'>--</span></div>
<div class='bar-track'><div class='bar-fill bar-good' id='conn-bar' style='width:0%'></div></div>
<div class='stat-row' style='margin-top:4px'><span class='stat-label'>TUNER GROWTH</span><span class='stat-value cyan' id='tuner-growth'>--</span></div>
</div>

<div class='card'>
<h2>THREAD POOL</h2>
<div class='stat-row'><span class='stat-label'>PENDING</span><span class='stat-value' id='pool-pending'>--</span></div>
<div class='stat-row'><span class='stat-label'>ALLOCATED</span><span class='stat-value cyan' id='pool-threads'>--</span></div>
<div class='bar-track'><div class='bar-fill bar-cyan' id='pool-bar' style='width:0%'></div></div>
</div>

<div class='card'>
<h2>AUTO-TUNER</h2>
<div class='stat-row'><span class='stat-label'>CONNS</span><span class='stat-value' id='tuner-conn'>--</span></div>
<div class='stat-row'><span class='stat-label'>THREADS</span><span class='stat-value' id='tuner-threads'>--</span></div>
<div class='stat-row'><span class='stat-label'>REFRESH</span><span class='stat-value' id='tuner-refresh'>--</span></div>
<div class='stat-row'><span class='stat-label'>FAN-OUT</span><span class='stat-value' id='tuner-fanout'>--</span></div>
<div class='stat-row'><span class='stat-label'>LAT TREND</span><span class='stat-value' id='tuner-trend'>--</span></div>
</div>

<div class='card' style='grid-column:span 2'>
<h2>PREDICTED LATENCY &mdash; 60s WINDOW</h2>
<div class='sparkline' id='latency-spark'></div>
</div>
</div>

<div class='bottom-row'>
<div class='card'>
<h2>TOP DOMAINS BY LATENCY</h2>
<div id='top-domains'><div class='stat-row'><span class='stat-label'>collecting...</span><span class='stat-value'>--</span></div></div>
</div>
<div class='card'>
<h2>SYSTEM</h2>
<div class='stat-row'><span class='stat-label'>UPTIME</span><span class='stat-value good' id='sys-uptime'>--</span></div>
<div class='stat-row'><span class='stat-label'>TOTAL QUERIES</span><span class='stat-value cyan' id='sys-queries'>--</span></div>
<div class='stat-row'><span class='stat-label'>UDP WORKERS</span><span class='stat-value' id='sys-workers'>2</span></div>
<div class='stat-row'><span class='stat-label'>TCP</span><span class='stat-value' id='sys-tcp'>--</span></div>
<div class='stat-row'><span class='stat-label'>MODE</span><span class='stat-value good'>PROXY</span></div>
</div>
</div>

<div class='footer'>
<a href='/metrics'>[ PROMETHEUS ]</a>
<a href='/api/stats'>[ JSON ]</a>
<a href='/health'>[ HEALTH ]</a>
<a href='https://github.com/infinitebinary01/dnss-cpp'>[ GITHUB ]</a>
<span style='float:right'>dnss-cpp v0.2 &mdash; DNS over HTTPS Nexus</span>
</div>
</div>

<script>
// Matrix rain
var canvas = document.getElementById('matrix');
var ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;
var cols = Math.floor(canvas.width / 14);
var drops = Array(cols).fill(1);
var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<>/{}[]|~';
function drawMatrix() {
  ctx.fillStyle = 'rgba(45,48,55,0.07)';
  ctx.fillRect(0,0,canvas.width,canvas.height);
  ctx.fillStyle = '#00ff41';
  ctx.font = '14px monospace';
  for(var i=0;i<drops.length;i++){
    var text = chars[Math.floor(Math.random()*chars.length)];
    ctx.fillText(text,i*14,drops[i]*14);
    if(drops[i]*14>canvas.height && Math.random()>0.975) drops[i]=0;
    drops[i]++;
  }
}
setInterval(drawMatrix,50);

// Latency sparkline history (60 points)
var latHistory = [];
function update() {
  var r = new XMLHttpRequest();
  r.onload = function() {
    if (r.status !== 200) return;
    var d = JSON.parse(r.responseText);
    var ts = new Date().toISOString().slice(11,19);
    function q(id) { return document.getElementById(id); }
    function cls(id, c) { q(id).className = c; }

    q('ts').textContent = ts;
    var avg = d.latency.avg_ms, p95 = d.latency.p95_ms;
    var er = d.errors.rate, hr = d.cache.hit_rate, thr = d.cache.turbo_hit_rate;

    // Latency
    q('lat-avg').textContent = (avg < 1 ? avg.toFixed(2) : avg.toFixed(1)) + 'ms';
    cls('lat-avg', avg < 100 ? 'good' : avg < 500 ? 'warn' : 'bad');
    q('lat-p95').textContent = (p95 < 1 ? p95.toFixed(2) : p95.toFixed(1)) + 'ms';
    cls('lat-p95', p95 < 200 ? 'good' : p95 < 1000 ? 'warn' : 'bad');
    q('err-rate').textContent = (er*100).toFixed(2) + '%';
    cls('err-rate', er < 0.03 ? 'good' : 'bad');

    // Cache
    var l2r = Math.max(0, hr - thr);
    q('cache-hit').textContent = (hr*100).toFixed(1) + '%';
    cls('cache-hit', hr > 0.5 ? 'good' : 'warn');
    q('turbo-hit').textContent = (thr*100).toFixed(1) + '%';
    cls('turbo-hit', thr > 0.3 ? 'good' : 'warn');
    q('l2-hit').textContent = (l2r*100).toFixed(1) + '%';
    cls('l2-hit', l2r > 0.3 ? 'good' : 'warn');

    // Connections
    var active = d.connections.active, total = d.connections.recommended;
    var util = d.connections.utilization;
    q('conn-active').textContent = active + ' / ' + total;
    q('conn-util').textContent = (util*100).toFixed(1) + '%';
    var connBar = q('conn-bar');
    connBar.style.width = Math.min(util*100,100) + '%';
    connBar.className = 'bar-fill ' + (util < 0.7 ? 'bar-good' : util < 0.9 ? 'bar-warn' : 'bar-bad');

    // Thread pool
    var pending = d.thread_pool.pending, threads = d.thread_pool.recommended;
    q('pool-pending').textContent = pending;
    q('pool-threads').textContent = threads;
    var poolLoad = Math.min(pending / (threads||1), 1);
    q('pool-bar').style.width = (poolLoad*100) + '%';

    // Auto-tuner
    q('tuner-conn').textContent = total;
    q('tuner-threads').textContent = threads;
    var refresh = d.auto_tuner.cache_refresh_pct;
    q('tuner-refresh').textContent = refresh + '%';
    q('tuner-fanout').textContent = d.auto_tuner.fan_out ? 'ON' : 'OFF';
    cls('tuner-fanout', d.auto_tuner.fan_out ? 'good' : 'warn');

    // Trend from predicted if available
    if (d.auto_tuner.latency_trend !== undefined) {
      q('tuner-trend').textContent = d.auto_tuner.latency_trend.toFixed(1);
      cls('tuner-trend', d.auto_tuner.latency_trend < 5 ? 'good' : 'warn');
    }

    // QPS
    q('qps').textContent = d.auto_tuner.qps !== undefined ? d.auto_tuner.qps.toFixed(1) + '/s' : '--';
    q('tuner-growth').textContent = d.auto_tuner.connection_growth !== undefined ? '+' + d.auto_tuner.connection_growth_per_cycle + '/cycle' : '--';

    // System
    q('sys-queries').textContent = d.auto_tuner.total_queries !== undefined ? d.auto_tuner.total_queries.toLocaleString() : '--';

    // Sparkline
    latHistory.push(avg);
    if(latHistory.length>60) latHistory.shift();
    var spark = q('latency-spark');
    var maxLat = Math.max(1, ...latHistory);
    spark.innerHTML = latHistory.map(function(v){
      var pct = Math.max(3,(v/maxLat)*100);
      var c = v < 100 ? '#00ff41' : v < 500 ? '#e6db74' : '#ff5555';
      return '<div class="bar" style="height:'+pct+'%;background:'+c+'"></div>';
    }).join('');

    // Top domains
    if (d.top_domains && d.top_domains.length) {
      var dd = q('top-domains');
      dd.innerHTML = d.top_domains.slice(0,5).map(function(item){
        var c = item.latency < 100 ? 'good' : item.latency < 500 ? 'warn' : 'bad';
        return '<div class="stat-row"><span class="stat-label">' + item.domain + '</span><span class="stat-value ' + c + '">' + item.latency.toFixed(1) + 'ms</span></div>';
      }).join('');
    }

    // Uptime: compute from start time
    if (!this._start) this._start = Date.now();
    var elapsed = Math.floor((Date.now() - this._start)/1000);
    var h = String(Math.floor(elapsed/3600)).padStart(2,'0');
    var m = String(Math.floor((elapsed%3600)/60)).padStart(2,'0');
    var s = String(elapsed%60).padStart(2,'0');
    q('sys-uptime').textContent = h+':'+m+':'+s;
  };
  r.open('GET', '/api/stats', true);
  r.send();
}
update();
setInterval(update, 2000);
window.addEventListener('resize',function(){canvas.width=window.innerWidth;canvas.height=window.innerHeight;cols=Math.floor(canvas.width/14);});
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
         << "    \"fan_out\": " << (tuner.fanOutEnabled() ? "true" : "false") << ",\n"
         << "    \"latency_trend\": " << tuner.trendSlope() << ",\n"
         << "    \"qps\": " << tuner.currentQps() << ",\n"
         << "    \"connection_growth\": 0,\n"
         << "    \"connection_growth_per_cycle\": 0,\n"
         << "    \"total_queries\": " << PerfMonitor::instance().totalQueries() << "\n"
         << "  },\n"
         << "  \"top_domains\": [\n";

    // Add top domains by latency
    auto domains = PerfMonitor::instance().getDomainLatencies();
    std::vector<std::pair<std::string, double>> sorted;
    for (auto& [name, dl] : domains) {
        sorted.push_back({name, dl.p95});
    }
    std::sort(sorted.begin(), sorted.end(),
              [](auto& a, auto& b) { return a.second > b.second; });

    bool first = true;
    for (int i = 0; i < std::min(10, (int)sorted.size()); i++) {
        if (!first) json << ",\n";
        first = false;
        json << "    {\"domain\": \"" << sorted[i].first
             << "\", \"latency\": " << sorted[i].second << "}";
    }

    json << "\n  ]\n"
         << "}\n";
    return json.str();
}

std::string MonitorServer::renderHealth() {
    return "OK";
}
