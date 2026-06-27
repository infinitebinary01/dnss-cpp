// SPDX-License-Identifier: MIT
//
#pragma once

#include "resolver.hpp"
#include "dns_protocol.hpp"
#include "perf_monitor.hpp"
#include "auto_tuner.hpp"
#include <unordered_map>
#include <shared_mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include <array>

class CachingResolver : public Resolver {
public:
    explicit CachingResolver(std::unique_ptr<Resolver> back);
    ~CachingResolver() override;

    void init() override;
    void maintain() override;
    void reload() override;
    DnsMessagePtr query(const DnsMessage& req, bool allowFanOut = true) override;

    int countConnected() const override;

    void flushCache();
    size_t cacheSize() const;
    int64_t hits() const;
    int64_t misses() const;
    int64_t total() const;
    int64_t turboHits() const { return turboHits_.load(); }

private:
    struct CacheKey {
        std::string name;
        uint16_t type;
        uint16_t qclass;

        bool operator==(const CacheKey& o) const {
            return name == o.name && type == o.type && qclass == o.qclass;
        }
    };

    struct CacheKeyHash {
        size_t operator()(const CacheKey& k) const {
            return std::hash<std::string>()(k.name) ^
                   (static_cast<size_t>(k.type) << 16) ^
                   static_cast<size_t>(k.qclass);
        }
    };

    struct CacheEntry {
        DnsMessagePtr msg;
        std::chrono::seconds ttl;
        std::chrono::steady_clock::time_point expiresAt;
        DnsQuestion question;
    };

    // L1 turbo cache — per-entry spinlock, direct-mapped hot cache
    static constexpr size_t TURBO_SIZE = 1024;
    struct TurboSlot {
        std::atomic<uint64_t> keyHash{0};
        std::atomic_flag lock = ATOMIC_FLAG_INIT;
        DnsMessagePtr msg;
        std::chrono::steady_clock::time_point expiresAt;
    };
    std::array<TurboSlot, TURBO_SIZE> turbo_;
    std::array<std::atomic<int>, TURBO_SIZE> turboFreq_;

    static uint64_t turboHash(const CacheKey& k);
    bool turboLookup(uint64_t h, DnsMessagePtr& out);
    void turboInsert(uint64_t h, DnsMessagePtr msg, std::chrono::steady_clock::time_point expiresAt);

    // L2 main LRU cache
    std::unique_ptr<Resolver> back_;
    std::unordered_map<CacheKey, CacheEntry, CacheKeyHash> cache_;
    mutable std::shared_mutex cacheMutex_;

    std::thread maintainThread_;
    std::thread refreshThread_;
    std::thread adaptivePrewarmThread_;
    std::atomic<bool> running_{false};

    std::atomic<int64_t> totalQueries_{0};
    std::atomic<int64_t> cacheHits_{0};
    std::atomic<int64_t> cacheMisses_{0};
    std::atomic<int64_t> cacheRecorded_{0};
    std::atomic<int64_t> preemptiveRefreshes_{0};
    std::atomic<int64_t> turboHits_{0};

    // Adaptive prewarm: track popular domains
    std::unordered_map<std::string, std::atomic<uint64_t>> prewarmTracker_;
    std::mutex prewarmMutex_;
    void doAdaptivePrewarm();

    static constexpr size_t maxCacheSize = 2000;
    static constexpr std::chrono::seconds minTTL{30};
    static constexpr std::chrono::seconds maxTTL{7200};
    static constexpr std::chrono::seconds negativeTTL{30};

    bool shouldCache(const DnsQuestion& question, const DnsMessage& reply);
    std::chrono::seconds computeCacheTTL(const DnsMessage& reply);
    void clobberTTL(DnsMessage& msg, std::chrono::seconds ttl);
    DnsMessagePtr buildCachedReply(const DnsMessage& req, const DnsMessage& cached);
    bool isExpired(const CacheEntry& entry);
    bool needsRefresh(const CacheEntry& entry);
    void gcCache();
    void preemptiveRefreshLoop();
    void refreshEntry(const CacheKey& key, CacheEntry& entry);
};
