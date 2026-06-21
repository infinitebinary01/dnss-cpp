// SPDX-License-Identifier: MIT
//
#include "perf_monitor.hpp"
#include <algorithm>
#include <cmath>

PerfMonitor& PerfMonitor::instance() {
    static PerfMonitor inst;
    return inst;
}

void PerfMonitor::recordLatency(std::chrono::microseconds us) {
    auto idx = latencyRing_.writeIdx_.fetch_add(1, std::memory_order_relaxed);
    latencyRing_.latencies_[idx % WINDOW_SIZE].store(us.count(), std::memory_order_relaxed);
    counters_.queries_.fetch_add(1, std::memory_order_relaxed);
}

void PerfMonitor::recordCacheHit() {
    counters_.cacheHits_.fetch_add(1, std::memory_order_relaxed);
}

void PerfMonitor::recordCacheMiss() {
    counters_.cacheMisses_.fetch_add(1, std::memory_order_relaxed);
}

void PerfMonitor::recordError() {
    counters_.errors_.fetch_add(1, std::memory_order_relaxed);
}

void PerfMonitor::recordConnUse(int active, int total) {
    activeConns_.store(active, std::memory_order_relaxed);
    totalConns_.store(total, std::memory_order_relaxed);
}

void PerfMonitor::recordThreadPoolLoad(int pending) {
    poolPending_.store(pending, std::memory_order_relaxed);
}

void PerfMonitor::setSupplementaryStats(SupplementaryStatsFn fn) {
    extraStatsFn_ = std::move(fn);
}

PerfSnapshot PerfMonitor::snapshot() const {
    PerfSnapshot s;

    uint64_t idx = latencyRing_.writeIdx_.load(std::memory_order_relaxed);
    size_t count = std::min<size_t>(idx, WINDOW_SIZE);

    if (count > 0) {
        std::array<uint64_t, WINDOW_SIZE> samples;
        for (size_t i = 0; i < count; i++) {
            samples[i] = latencyRing_.latencies_[(idx - count + i) % WINDOW_SIZE].load(std::memory_order_relaxed);
        }
        std::sort(samples.begin(), samples.begin() + count);

        double sum = 0;
        for (size_t i = 0; i < count; i++) sum += samples[i];
        s.avgLatencyMs = sum / count / 1000.0;
        s.p95LatencyMs = samples[static_cast<size_t>(count * 0.95)] / 1000.0;
    }

    int64_t hits = counters_.cacheHits_.load(std::memory_order_relaxed);
    int64_t misses = counters_.cacheMisses_.load(std::memory_order_relaxed);
    int64_t total = hits + misses;
    s.cacheHitRate = total > 0 ? static_cast<double>(hits) / total : 0;

    int64_t errors = counters_.errors_.load(std::memory_order_relaxed);
    int64_t totalReq = counters_.queries_.load(std::memory_order_relaxed);
    s.errorRate = totalReq > 0 ? static_cast<double>(errors) / totalReq : 0;

    int active = activeConns_.load(std::memory_order_relaxed);
    int totalC = totalConns_.load(std::memory_order_relaxed);
    s.connUtilization = totalC > 0 ? static_cast<double>(active) / totalC : 0;
    s.activeConnections = active;
    s.threadPoolLoad = poolPending_.load(std::memory_order_relaxed);

    if (extraStatsFn_) {
        s = extraStatsFn_(s);
    }

    return s;
}
