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
#include <deque>
#include <condition_variable>

class CachingResolver : public Resolver {
public:
    explicit CachingResolver(std::unique_ptr<Resolver> back);
    ~CachingResolver() override;

    void init() override;
    void maintain() override;
    void reload() override;
    DnsMessagePtr query(const DnsMessage& req, bool allowFanOut = true) override;
    DnsMessagePtr peekCache(const DnsMessage& req) override;
    DnsMessagePtr peekCacheRaw(const uint8_t* data, size_t len) override;

    int countConnected() const override;

    void flushCache();
    void setCacheFile(const std::string& path) { cacheFile_ = path; }
    void saveCache();
    void loadCache();
    size_t cacheSize() const;
    int64_t hits() const;
    int64_t misses() const;
    int64_t total() const;
    int64_t turboHits() const { return turboHits_.load(); }
    int64_t staleHits() const { return staleHits_.load(); }

    // Dynamic TTL controls (used by AutoTuner)
    static int getMinTTL() { return minTTLSecs.load(); }
    static int getNegativeTTL() { return negativeTTLSecs.load(); }
    static int getStaleThreshold() { return staleThresholdSecs.load(); }
    static void setMinTTL(int secs) { minTTLSecs.store(secs); }
    static void setNegativeTTL(int secs) { negativeTTLSecs.store(secs); }
    static void setStaleThreshold(int secs) { staleThresholdSecs.store(secs); }

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
    };

    // L1 turbo cache — per-entry spinlock, direct-mapped hot cache
    static constexpr size_t TURBO_SIZE = 4096;
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
    std::thread warmupThread_;
    std::thread staleRefreshWorker_;
    std::atomic<bool> running_{false};

    // Bounded stale-while-revalidate work queue (replaces detached thread storm)
    std::mutex staleRefreshMutex_;
    std::condition_variable staleRefreshCv_;
    struct StaleRefreshWork {
        CacheKey key;
        DnsQuestion question;
    };
    std::deque<StaleRefreshWork> staleRefreshQueue_;
    static constexpr size_t MAX_STALE_REFRESH_QUEUE = 64;

    std::atomic<int64_t> totalQueries_{0};
    std::atomic<int64_t> cacheHits_{0};
    std::atomic<int64_t> cacheMisses_{0};
    std::atomic<int64_t> cacheRecorded_{0};
    std::atomic<int64_t> preemptiveRefreshes_{0};
    std::atomic<int64_t> staleHits_{0};
    std::atomic<int64_t> turboHits_{0};

    // Persistent disk cache
    std::string cacheFile_;
    static constexpr uint32_t CACHE_MAGIC = 0x4C594E58;
    static constexpr uint32_t CACHE_VERSION = 1;

    // Adaptive prewarm: track popular domains
    std::unordered_map<std::string, uint64_t> prewarmTracker_;
    std::mutex prewarmMutex_;
    void doAdaptivePrewarm();
    void warmupCache();

    static constexpr size_t maxCacheSize = 50000;
    static constexpr std::chrono::seconds maxTTL{7200};

    static std::atomic<int> minTTLSecs;
    static std::atomic<int> negativeTTLSecs;
    static std::atomic<int> staleThresholdSecs;

    bool shouldCache(const DnsQuestion& question, const DnsMessage& reply);
    std::chrono::seconds computeCacheTTL(const DnsMessage& reply);
    void clobberTTL(DnsMessage& msg, std::chrono::seconds ttl);
    DnsMessagePtr buildCachedReply(const DnsMessage& req, const DnsMessage& cached);
    bool isExpired(const CacheEntry& entry);
    bool needsRefresh(const CacheEntry& entry);
    void gcCache();
    void preemptiveRefreshLoop();
    void refreshEntry(const CacheKey& key, const DnsQuestion& question);
};
