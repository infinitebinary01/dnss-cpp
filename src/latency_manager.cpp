#include "latency_manager.hpp"
#include "logger.hpp"
#include <algorithm>

LatencyManager& LatencyManager::instance() {
    static LatencyManager mgr;
    return mgr;
}

void LatencyManager::setTargets(const Targets& t) {
    std::lock_guard<std::mutex> lock(targetsMutex_);
    targets_ = t;
}

double LatencyManager::targetAvgMs() const {
    std::lock_guard<std::mutex> lock(targetsMutex_);
    return targets_.avgMs;
}

double LatencyManager::targetP95Ms() const {
    std::lock_guard<std::mutex> lock(targetsMutex_);
    return targets_.p95Ms;
}

void LatencyManager::evaluate(const PerfSnapshot& perf) {
    lastAvg_.store(perf.avgLatencyMs);
    lastP95_.store(perf.p95LatencyMs);

    Targets t;
    {
        std::lock_guard<std::mutex> lock(targetsMutex_);
        t = targets_;
    }

    double avgRatio = perf.avgLatencyMs / t.avgMs;
    double p95Ratio = perf.p95LatencyMs / t.p95Ms;
    double rawGap = std::max(avgRatio, p95Ratio);
    if (rawGap < 1.0) rawGap = 1.0;

    smoothedGap_.store(smoothedGap_.load() * 0.7 + rawGap * 0.3);
    double gap = smoothedGap_.load();

    gapPct_.store((gap - 1.0) * 100.0);

    gapHistory_.push_back(gap);
    if (gapHistory_.size() > MAX_GAP_HISTORY)
        gapHistory_.pop_front();

    if (gap >= 1.1) {
        consecutiveOver_ = std::min(consecutiveOver_ + 1, 10);
    } else {
        consecutiveOver_ = std::max(0, consecutiveOver_ - 1);
    }

    int urgency = 0;
    if (gap > 10.0)       urgency = 5;
    else if (gap > 5.0)   urgency = 4;
    else if (gap > 3.0)   urgency = 3;
    else if (gap > 2.0)   urgency = 2;
    else if (gap > 1.5)   urgency = 1;

    if (consecutiveOver_ >= 3 && urgency > 0)
        urgency = std::min(urgency + 1, 5);
    if (consecutiveOver_ >= 6)
        urgency = std::min(urgency + 1, 5);

    urgency_.store(urgency);

    // Bottleneck detection — the FIRST matching condition wins
    std::string reason = "upstream";
    if (perf.threadPoolLoad > 10)
        reason = "queue";
    else if (perf.cacheHitRate < 0.5)
        reason = "cache";
    else if (perf.connUtilization > 0.9)
        reason = "upstream";

    {
        std::lock_guard<std::mutex> lock(bottleneckMutex_);
        bottleneck_ = reason;
    }

    LOG_DEBUG("LatencyMgr: gap=" + std::to_string(static_cast<int>(gapPct_.load())) +
              "% urgency=" + std::to_string(urgency) +
              " bottleneck=" + reason +
              " avg=" + std::to_string(perf.avgLatencyMs) +
              " p95=" + std::to_string(perf.p95LatencyMs));
}

int LatencyManager::threadBoost() const {
    int u = urgency_.load();
    if (u <= 0) return 0;

    std::string bot;
    {
        std::lock_guard<std::mutex> lock(bottleneckMutex_);
        bot = bottleneck_;
    }

    // More threads help when bottleneck is queue wait or parallel upstream fan-out
    if (bot == "queue")
        return u * 3;
    if (bot == "upstream")
        return u * 2;
    return u;  // cache or unknown: modest boost
}

int LatencyManager::connBoost() const {
    int u = urgency_.load();
    if (u <= 0) return 0;

    std::string bot;
    {
        std::lock_guard<std::mutex> lock(bottleneckMutex_);
        bot = bottleneck_;
    }

    if (bot == "upstream" || bot == "cache")
        return u * 2;
    return u;  // queue or unknown: modest boost
}

int LatencyManager::cacheRefreshBoost() const {
    int u = urgency_.load();
    if (u <= 0) return 0;
    return std::min(2 + u * 2, 12);  // 4-12% additive
}

std::string LatencyManager::bottleneck() const {
    std::lock_guard<std::mutex> lock(bottleneckMutex_);
    return bottleneck_;
}
