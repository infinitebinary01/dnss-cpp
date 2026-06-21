// SPDX-License-Identifier: MIT
//
#pragma once

#include "perf_monitor.hpp"
#include <atomic>
#include <chrono>
#include <thread>
#include <array>
#include <deque>

class AutoTuner {
public:
    static AutoTuner& instance();

    ~AutoTuner();

    void tune();
    void start();
    void stop();

    int recommendedConnections() const { return connCount_.load(); }
    int recommendedThreads() const { return threadCount_.load(); }
    int cacheRefreshThresholdPct() const { return refreshPct_.load(); }
    bool fanOutEnabled() const { return fanOut_.load(); }

    double predictedLatencyMs() const { return predictedLat_.load(); }
    double latencyVariance() const { return latVariance_.load(); }
    double trendSlope() const { return trendSlope_.load(); }

private:
    AutoTuner() = default;

    std::atomic<int> connCount_{12};
    std::atomic<int> threadCount_{8};
    std::atomic<int> refreshPct_{10};
    std::atomic<bool> fanOut_{true};

    std::atomic<double> predictedLat_{0};
    std::atomic<double> latVariance_{0};
    std::atomic<double> trendSlope_{0};

    std::thread tuneThread_;
    std::atomic<bool> running_{false};

    // PID state
    double prevLatency_ = 0;
    double prevErrorRate_ = 0;
    double integral_ = 0;
    double prevDerivative_ = 0;

    // Learning state
    using TimePoint = std::chrono::steady_clock::time_point;
    std::deque<std::pair<TimePoint, double>> latHistory_;
    std::deque<std::pair<TimePoint, double>> qpsHistory_;
    int consecutiveHighLat_ = 0;
    int consecutiveHighErr_ = 0;
    int consecutiveLowLoad_ = 0;

    // Predictive baseline
    double baselineLat_ = 0;
    int samplesCollected_ = 0;

    static constexpr size_t MAX_HISTORY = 60; // 5 min at 5s intervals
    static constexpr int MIN_CONNS = 12;
    static constexpr int MAX_CONNS = 32;
    static constexpr int MIN_THREADS = 8;
    static constexpr int MAX_THREADS = 16;

    double computeTrend();
    double computeVariance();
    double computeQps();
    double kalmanFilter(double measurement);
    double kalmanEstimate_ = 0;
    double kalmanError_ = 1;
};
