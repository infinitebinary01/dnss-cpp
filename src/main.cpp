// SPDX-License-Identifier: MIT
//
#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <csignal>
#include <cstring>
#include <map>
#include <sstream>
#include <vector>

#include "logger.hpp"
#include "dns_protocol.hpp"
#include "domain_map.hpp"
#include "resolver.hpp"
#include "caching_resolver.hpp"
#include "http_resolver.hpp"
#include "dns_server.hpp"
#include "https_server.hpp"
#include "auto_tuner.hpp"
#include "monitor_server.hpp"

static std::atomic<bool> running{true};
static std::shared_ptr<DnsServer> dnsServer;
static std::shared_ptr<HttpsServer> httpsServer;
static std::unique_ptr<MonitorServer> monitorServer;

static void signalHandler(int) {
    running = false;
}

struct Config {
    std::string dnsListenAddr = ":53";
    std::string dnsUnqualifiedUpstream;
    std::string dnsServerForDomain;
    std::string fallbackUpstream = "8.8.8.8:53";
    bool enableDnsToHttps = false;
    std::string httpsUpstream = "https://dns.google/dns-query";
    std::string httpsClientCAFile;
    bool enableCache = true;
    bool enableHttpsToDns = false;
    std::string dnsUpstream = "8.8.8.8:53";
    std::string httpsCertFile;
    std::string httpsKeyFile;
    std::string httpsAddr = ":443";
    bool insecureHttpServer = false;
    std::string monitoringListenAddr;
    std::string logLevel = "info";
    std::string configFile;
    std::string proxy;
    std::string noProxy;
};

static void printUsage(const char* prog) {
    std::cerr << "dnss - DNS over HTTPS daemon (C++ port)\n"
              << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  --config=<file>                    path to JSON config file\n"
              << "  --dns_listen_addr=<addr>          address to listen on for DNS (default: :53)\n"
              << "  --dns_unqualified_upstream=<addr>  DNS server for unqualified requests\n"
              << "  --dns_server_for_domain=<map>      domain:addr pairs (comma-separated)\n"
              << "  --fallback_upstream=<addr>         DNS server for upstream resolution (default: 8.8.8.8:53)\n"
              << "  --enable_dns_to_https              enable DNS-to-HTTPS proxy\n"
              << "  --https_upstream=<url>             URL of DoH upstream (default: https://dns.google/dns-query)\n"
              << "  --https_client_cafile=<file>       CA file for HTTPS client\n"
              << "  --enable_cache=<bool>              enable cache (default: true)\n"
              << "  --enable_https_to_dns              enable HTTPS-to-DNS proxy\n"
              << "  --dns_upstream=<addr>              upstream DNS server for HTTPS-to-DNS (default: 8.8.8.8:53)\n"
              << "  --https_cert=<file>                TLS certificate file\n"
              << "  --https_key=<file>                 TLS key file\n"
              << "  --https_server_addr=<addr>         HTTPS listen address (default: :443)\n"
              << "  --insecure_http_server             listen on plain HTTP\n"
              << "  --monitoring_listen_addr=<addr>    monitoring HTTP listen address (default: :8080)\n"
              << "  --log_level=<level>                log level: debug|info|warn|error (default: info)\n"
              << "  --proxy=<url>                      HTTPS proxy URL (overrides https_proxy env)\n"
              << "  --no_proxy=<hosts>                 comma-separated no-proxy hosts\n"
              << "  --help, -h                         show this help\n";
}

static std::map<std::string, std::string> parseJson(const std::string& path) {
    std::map<std::string, std::string> kv;
    std::ifstream f(path);
    if (!f.is_open()) {
        LOG_ERROR("Cannot open config file: " + path);
        return kv;
    }

    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());

    // Minimal JSON parser: finds "key": "value" and "key": true/false patterns
    // Doesn't need a full parser for our simple config
    size_t pos = 0;
    while ((pos = content.find('"', pos)) != std::string::npos) {
        size_t keyStart = pos + 1;
        size_t keyEnd = content.find('"', keyStart);
        if (keyEnd == std::string::npos) break;
        std::string key = content.substr(keyStart, keyEnd - keyStart);

        size_t colon = content.find(':', keyEnd + 1);
        if (colon == std::string::npos) break;

        pos = content.find_first_not_of(" \t\r\n", colon + 1);
        if (pos == std::string::npos) break;

        if (content[pos] == '"') {
            // String value
            size_t valStart = pos + 1;
            size_t valEnd = content.find('"', valStart);
            if (valEnd == std::string::npos) break;
            kv[key] = content.substr(valStart, valEnd - valStart);
            pos = valEnd + 1;
        } else {
            // Boolean or number
            size_t valEnd = content.find_first_of(",}\n\r", pos);
            if (valEnd == std::string::npos) valEnd = content.size();
            std::string val = content.substr(pos, valEnd - pos);
            // Trim
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);
            kv[key] = val;
            pos = valEnd;
        }
    }
    return kv;
}

static Config parseArgs(int argc, char* argv[]) {
    Config cfg;

    // First pass: look for --config and load it first
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        auto eq = arg.find('=');
        std::string key = (eq != std::string::npos) ? arg.substr(0, eq) : arg;
        std::string val = (eq != std::string::npos) ? arg.substr(eq + 1) : "";

        if (key == "--config") {
            cfg.configFile = val;
            break;
        }
    }

    // Load config file if specified
    if (!cfg.configFile.empty()) {
        auto jsonKV = parseJson(cfg.configFile);
        for (auto& [k, v] : jsonKV) {
            if (k == "dns_listen_addr") cfg.dnsListenAddr = v;
            else if (k == "dns_unqualified_upstream") cfg.dnsUnqualifiedUpstream = v;
            else if (k == "dns_server_for_domain") cfg.dnsServerForDomain = v;
            else if (k == "fallback_upstream") cfg.fallbackUpstream = v;
            else if (k == "enable_dns_to_https") cfg.enableDnsToHttps = (v == "true" || v == "1");
            else if (k == "https_upstream") cfg.httpsUpstream = v;
            else if (k == "https_client_cafile") cfg.httpsClientCAFile = v;
            else if (k == "enable_cache") cfg.enableCache = (v == "true" || v == "1" || v == "");
            else if (k == "enable_https_to_dns") cfg.enableHttpsToDns = (v == "true" || v == "1");
            else if (k == "dns_upstream") cfg.dnsUpstream = v;
            else if (k == "https_cert") cfg.httpsCertFile = v;
            else if (k == "https_key") cfg.httpsKeyFile = v;
            else if (k == "https_server_addr") cfg.httpsAddr = v;
            else if (k == "insecure_http_server") cfg.insecureHttpServer = (v == "true" || v == "1");
            else if (k == "monitoring_listen_addr") cfg.monitoringListenAddr = v;
            else if (k == "log_level") cfg.logLevel = v;
            else if (k == "proxy") cfg.proxy = v;
            else if (k == "no_proxy") cfg.noProxy = v;
        }
        LOG_INFO("Loaded config from " + cfg.configFile);
    }

    // Second pass: CLI overrides config file
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            exit(0);
        }

        auto eq = arg.find('=');
        std::string key, val;
        if (eq != std::string::npos) {
            key = arg.substr(0, eq);
            val = arg.substr(eq + 1);
        } else {
            key = arg;
        }

        if (key == "--config") {
            // Already handled
        }
        else if (key == "--dns_listen_addr") cfg.dnsListenAddr = val;
        else if (key == "--dns_unqualified_upstream") cfg.dnsUnqualifiedUpstream = val;
        else if (key == "--dns_server_for_domain") cfg.dnsServerForDomain = val;
        else if (key == "--fallback_upstream") cfg.fallbackUpstream = val;
        else if (key == "--enable_dns_to_https") cfg.enableDnsToHttps = true;
        else if (key == "--https_upstream") cfg.httpsUpstream = val;
        else if (key == "--https_client_cafile") cfg.httpsClientCAFile = val;
        else if (key == "--enable_cache") {
            cfg.enableCache = (val.empty() || val == "true" || val == "1");
        }
        else if (key == "--enable_https_to_dns") cfg.enableHttpsToDns = true;
        else if (key == "--dns_upstream") cfg.dnsUpstream = val;
        else if (key == "--https_cert") cfg.httpsCertFile = val;
        else if (key == "--https_key") cfg.httpsKeyFile = val;
        else if (key == "--https_server_addr") cfg.httpsAddr = val;
        else if (key == "--insecure_http_server") cfg.insecureHttpServer = true;
        else if (key == "--monitoring_listen_addr") cfg.monitoringListenAddr = val;
        else if (key == "--log_level") cfg.logLevel = val;
        else if (key == "--proxy") cfg.proxy = val;
        else if (key == "--no_proxy") cfg.noProxy = val;
        else {
            std::cerr << "Unknown option: " << key << std::endl;
            exit(1);
        }
    }

    return cfg;
}

int main(int argc, char* argv[]) {
    auto cfg = parseArgs(argc, argv);

    if (cfg.logLevel == "debug") Logger::instance().setLevel(LogLevel::Debug);
    else if (cfg.logLevel == "info") Logger::instance().setLevel(LogLevel::Info);
    else if (cfg.logLevel == "warn") Logger::instance().setLevel(LogLevel::Warn);
    else if (cfg.logLevel == "error") Logger::instance().setLevel(LogLevel::Error);

    LOG_INFO("dnss-cpp starting");

    // Set proxy from config (if specified) before any resolver needs it
    if (!cfg.proxy.empty()) {
        setenv("https_proxy", cfg.proxy.c_str(), 1);
    }
    if (!cfg.noProxy.empty()) {
        setenv("no_proxy", cfg.noProxy.c_str(), 1);
    }

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    AutoTuner::instance().start();

    // Start monitoring server
    std::string monAddr = cfg.monitoringListenAddr.empty() ? ":8080" : cfg.monitoringListenAddr;
    monitorServer = std::make_unique<MonitorServer>(monAddr);
    monitorServer->start();

    if (!cfg.enableDnsToHttps && !cfg.enableHttpsToDns) {
        LOG_ERROR("Need to enable at least one of: --enable_dns_to_https, --enable_https_to_dns");
        return 1;
    }

    if (cfg.enableDnsToHttps) {
        auto overrides = DomainMap::fromString(cfg.dnsServerForDomain);

        auto rawResolver = std::make_unique<HttpResolver>(
            cfg.httpsUpstream, cfg.httpsClientCAFile, cfg.fallbackUpstream);

        std::shared_ptr<Resolver> resolver;
        std::shared_ptr<CachingResolver> cacheResolver;
        if (cfg.enableCache) {
            auto cr = std::make_shared<CachingResolver>(std::move(rawResolver));
            cacheResolver = cr;
            resolver = std::move(cr);
        } else {
            resolver = std::move(rawResolver);
        }

        if (cacheResolver) {
            PerfMonitor::instance().setSupplementaryStats(
                [cr = std::weak_ptr<CachingResolver>(cacheResolver)](PerfSnapshot s) {
                    if (auto r = cr.lock()) {
                        int64_t th = r->turboHits();
                        int64_t hits = r->hits();
                        int64_t total = r->total();
                        s.turboHitRate = hits > 0 ? (double)th / hits : 0;
                    }
                    return s;
                });
        }

        dnsServer = std::make_shared<DnsServer>(
            cfg.dnsListenAddr, resolver, cfg.dnsUnqualifiedUpstream, overrides);

        std::thread dnsThread([]() {
            dnsServer->listenAndServe();
        });
        dnsThread.detach();
    }

    if (cfg.enableHttpsToDns) {
        httpsServer = std::make_shared<HttpsServer>(
            cfg.httpsAddr, cfg.dnsUpstream, cfg.httpsCertFile, cfg.httpsKeyFile, cfg.insecureHttpServer);

        std::thread httpsThread([]() {
            httpsServer->listenAndServe();
        });
        httpsThread.detach();
    }

    // Main loop — wait for signal
    while (running)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    LOG_INFO("Shutting down...");

    // Graceful shutdown
    if (dnsServer) {
        LOG_INFO("Stopping DNS server...");
        dnsServer->stop();
    }
    if (httpsServer) {
        LOG_INFO("Stopping HTTPS server...");
        httpsServer->stop();
    }
    if (monitorServer) {
        LOG_INFO("Stopping monitor server...");
        monitorServer->stop();
    }

    LOG_INFO("Stopping AutoTuner...");
    AutoTuner::instance().stop();

    // Give threads time to clean up
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    LOG_INFO("dnss-cpp stopped");
    return 0;
}
