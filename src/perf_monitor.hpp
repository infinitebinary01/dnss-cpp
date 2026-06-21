// SPDX-License-Identifier: MIT
//
#pragma once

#include <atomic>
#include <chrono>
#include <array>
#include <cstdint>
#include <functional>

struct PerfSnapshot {
    double avgLatencyMs = 0;
    double p95LatencyMs = 0;
    double cacheHitRate = 0;
    double turboHitRate = 0;
    double errorRate = 0;
    double connUtilization = 0;
    int activeConnections = 0;
    int threadPoolLoad = 0;
};

using SupplementaryStatsFn = std::function<PerfSnapshot(PerfSnapshot)>;

class PerfMonitor {
public:
    static PerfMonitor& instance();

    void recordLatency(std::chrono::microseconds us);
    void recordCacheHit();
    void recordCacheMiss();
    void recordError();
    void recordConnUse(int active, int total);
    void recordThreadPoolLoad(int pending);

    void setSupplementaryStats(SupplementaryStatsFn fn);

    PerfSnapshot snapshot() const;
    int64_t totalQueries() const { return counters_.queries_.load(std::memory_order_relaxed); }

private:
    PerfMonitor() = default;

    static constexpr int WINDOW_SIZE = 256;
    struct LatencyRing {
        std::array<std::atomic<uint64_t>, WINDOW_SIZE> latencies_{};
        std::atomic<uint64_t> writeIdx_{0};
    };
    LatencyRing latencyRing_;

    struct Counters {
        std::atomic<int64_t> cacheHits_{0};
        std::atomic<int64_t> cacheMisses_{0};
        std::atomic<int64_t> errors_{0};
        std::atomic<int64_t> queries_{0};
    };
    Counters counters_;

    std::atomic<int> activeConns_{0};
    std::atomic<int> totalConns_{0};
    std::atomic<int> poolPending_{0};

    mutable SupplementaryStatsFn extraStatsFn_;
};
