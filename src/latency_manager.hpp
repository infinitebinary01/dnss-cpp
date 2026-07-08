#pragma once

#include "perf_monitor.hpp"
#include <atomic>
#include <mutex>
#include <string>
#include <deque>

class LatencyManager {
public:
    static LatencyManager& instance();

    struct Targets {
        double avgMs = 50.0;
        double p95Ms = 200.0;
    };

    void setTargets(const Targets& t);
    void evaluate(const PerfSnapshot& perf);

    int urgencyLevel() const { return urgency_.load(); }
    int threadBoost() const;
    int connBoost() const;
    bool forceFanOut() const { return urgency_.load() > 0; }
    int cacheRefreshBoost() const;

    double gapPct() const { return gapPct_.load(); }
    std::string bottleneck() const;
    double targetAvgMs() const;
    double targetP95Ms() const;

private:
    LatencyManager() = default;

    Targets targets_;
    mutable std::mutex targetsMutex_;

    std::atomic<double> smoothedGap_{0};
    std::atomic<int> urgency_{0};
    std::atomic<double> gapPct_{0};
    std::atomic<double> lastAvg_{0};
    std::atomic<double> lastP95_{0};
    std::string bottleneck_ = "none";
    mutable std::mutex bottleneckMutex_;

    int consecutiveOver_ = 0;
    std::deque<double> gapHistory_;

    static constexpr size_t MAX_GAP_HISTORY = 30;
};
