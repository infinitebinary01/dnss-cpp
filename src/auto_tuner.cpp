// SPDX-License-Identifier: MIT
//
#include "auto_tuner.hpp"
#include "logger.hpp"
#include <thread>
#include <algorithm>
#include <cmath>
#include <numeric>

AutoTuner& AutoTuner::instance() {
    static AutoTuner inst;
    return inst;
}

AutoTuner::~AutoTuner() {
    stop();
}

void AutoTuner::stop() {
    running_ = false;
    if (tuneThread_.joinable())
        tuneThread_.join();
}

void AutoTuner::start() {
    running_ = true;
    tuneThread_ = std::thread([this]() {
        try {
            while (running_) {
                for (int i = 0; i < 50 && running_; i++)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (!running_) break;
                tune();
            }
        } catch (const std::exception& e) {
            LOG_ERROR("AutoTuner thread error: " + std::string(e.what()));
        }
    });
}

// Kalman filter for latency smoothing
double AutoTuner::kalmanFilter(double measurement) {
    double processNoise = 0.01;
    double measurementNoise = 5.0;

    // Predict
    double pred = kalmanEstimate_;
    double predError = kalmanError_ + processNoise;

    // Update
    double kg = predError / (predError + measurementNoise);
    kalmanEstimate_ = pred + kg * (measurement - pred);
    kalmanError_ = (1 - kg) * predError;

    return kalmanEstimate_;
}

double AutoTuner::computeTrend() {
    if (latHistory_.size() < 10) return 0;
    size_t n = latHistory_.size();
    double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
    for (size_t i = 0; i < n; i++) {
        double x = i;
        double y = latHistory_[i].second;
        sumX += x; sumY += y;
        sumXY += x * y; sumX2 += x * x;
    }
    double slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    return slope;
}

double AutoTuner::computeVariance() {
    if (latHistory_.size() < 5) return 0;
    double mean = 0;
    for (auto& p : latHistory_) mean += p.second;
    mean /= latHistory_.size();
    double var = 0;
    for (auto& p : latHistory_) var += (p.second - mean) * (p.second - mean);
    return var / latHistory_.size();
}

double AutoTuner::computeQps() {
    if (qpsHistory_.size() < 2) return 0;
    auto latest = qpsHistory_.back().first;
    auto earliest = qpsHistory_.front().first;
    auto span = std::chrono::duration_cast<std::chrono::seconds>(latest - earliest).count();
    if (span < 1) return 0;

    double totalQueries = 0;
    for (auto& p : qpsHistory_) totalQueries += p.second;
    return totalQueries / span;
}

void AutoTuner::tune() {
    auto perf = PerfMonitor::instance().snapshot();
    auto now = std::chrono::steady_clock::now();

    double rawLat = perf.avgLatencyMs;
    double err = perf.errorRate;
    double hitRate = perf.cacheHitRate;

    // Constrain
    if (rawLat < 1) rawLat = 1;
    if (rawLat > 10000) rawLat = 10000;

    // Kalman filter for smooth latency
    double lat = kalmanFilter(rawLat);
    predictedLat_.store(lat);

    // Track history for trend analysis
    latHistory_.push_back({now, lat});
    if (latHistory_.size() > MAX_HISTORY)
        latHistory_.pop_front();

    // Track query rate from PerfMonitor
    auto& pm = PerfMonitor::instance();
    int64_t queries = pm.totalQueries();
    static int64_t lastQueries = 0;
    static TimePoint lastQpsCheck = now;
    double qps = 0;
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastQpsCheck).count();
    if (elapsed >= 1) {
        qps = static_cast<double>(queries - lastQueries) / elapsed;
        lastQueries = queries;
        lastQpsCheck = now;
    }
    qpsHistory_.push_back({now, qps});
    if (qpsHistory_.size() > MAX_HISTORY)
        qpsHistory_.pop_front();

    // Compute trend and variance
    double trend = computeTrend();
    double variance = computeVariance();
    trendSlope_.store(trend);
    latVariance_.store(variance);

    // --- Predictive PID Controller ---
    double latencyError = (lat - prevLatency_) / (prevLatency_ > 0 ? prevLatency_ : 1);
    if (prevLatency_ <= 0) latencyError = 0;

    // Integral term with anti-windup
    integral_ += latencyError * 0.1;
    integral_ = std::clamp(integral_, -5.0, 5.0);

    // Derivative term (rate of change of error)
    double derivative = latencyError - prevDerivative_;
    prevDerivative_ = latencyError;

    // PID output: Kp*error + Ki*integral + Kd*derivative
    double Kp = 1.0, Ki = 0.3, Kd = 0.5;
    double pidOutput = Kp * latencyError + Ki * integral_ + Kd * derivative;

    // Track consecutive states for aggressive response
    if (lat > 200) consecutiveHighLat_++;
    else consecutiveHighLat_ = std::max(0, consecutiveHighLat_ - 1);

    if (err > 0.05) consecutiveHighErr_++;
    else consecutiveHighErr_ = std::max(0, consecutiveHighErr_ - 1);

    if (lat < 50 && err < 0.01) consecutiveLowLoad_++;
    else consecutiveLowLoad_ = std::max(0, consecutiveLowLoad_ - 1);

    // --- Connection count ---
    int curConn = connCount_.load();
    int newConn = curConn;

    // Rapid growth on errors or sustained high latency
    if (err > 0.03 || consecutiveHighErr_ >= 2) {
        newConn = std::min(curConn + 2, MAX_CONNS);
        LOG_DEBUG("AI-Tuner: +2 connections (" + std::to_string(newConn) + ") — errors");
    } else if (lat > 300 && qps > 5 && curConn < MAX_CONNS) {
        newConn = std::min(curConn + 1, MAX_CONNS);
        LOG_DEBUG("AI-Tuner: +1 connection (" + std::to_string(newConn) + ") — high latency under load");
    } else if (trend > 10 && curConn < MAX_CONNS) {
        newConn = std::min(curConn + 1, MAX_CONNS);
        LOG_DEBUG("AI-Tuner: +1 connection (" + std::to_string(newConn) + ") — rising trend");
    } else if (consecutiveLowLoad_ >= 6 && curConn > MIN_CONNS) {
        newConn = curConn - 1;
        LOG_DEBUG("AI-Tuner: -1 connection (" + std::to_string(newConn) + ") — low load");
    }

    connCount_.store(newConn);

    // --- Fan-out ---
    // Keep fan-out on during boot phase (first 60s) to prevent premature disable
    bool bootPhase = samplesCollected_ < 12;
    // Use P95 to detect tail latency (the Kalman avg may be smooth but tail is high)
    bool tailIssue = perf.p95LatencyMs > 120;
    if (bootPhase || err > 0.03 || tailIssue || lat > 300 || (variance > 50 && consecutiveHighLat_ >= 2)) {
        if (!fanOut_.load()) {
            fanOut_.store(true);
            LOG_DEBUG("AI-Tuner: enabling fan-out (err=" + std::to_string(err) +
                      " lat=" + std::to_string(lat) + " p95=" + std::to_string(perf.p95LatencyMs) +
                      " var=" + std::to_string(variance) + ")");
        }
    } else if (samplesCollected_ > 24 && err < 0.01 && perf.p95LatencyMs < 60 && variance < 20) {
        if (fanOut_.load()) {
            fanOut_.store(false);
            LOG_DEBUG("AI-Tuner: disabling fan-out — stable low load");
        }
    }

    // --- Thread pool ---
    int load = perf.threadPoolLoad;
    int curThreads = threadCount_.load();
    int newThreads = curThreads;

    // Only grow if pool is consistently busy AND latency is elevated
    if (load > 3 && lat > 100 && curThreads < MAX_THREADS) {
        newThreads = std::min(curThreads + 2, MAX_THREADS);
        LOG_DEBUG("AI-Tuner: +2 threads (" + std::to_string(newThreads) + ") — busy+latent");
    } else if (load > 5 && curThreads < MAX_THREADS) {
        newThreads = std::min(curThreads + 1, MAX_THREADS);
        LOG_DEBUG("AI-Tuner: +1 thread (" + std::to_string(newThreads) + ") — busy");
    }

    // Decrease threads when idle for sustained periods
    if (load == 0 && consecutiveLowLoad_ >= 6 && curThreads > 8) {
        newThreads = curThreads - 1;
        LOG_DEBUG("AI-Tuner: -1 thread (" + std::to_string(newThreads) + ") — idle");
    } else if (load < 3 && consecutiveLowLoad_ >= 12 && curThreads > 8) {
        newThreads = curThreads - 1;
        LOG_DEBUG("AI-Tuner: -1 thread (" + std::to_string(newThreads) + ") — low load");
    }

    // Clamp to valid range
    if (newThreads < MIN_THREADS) newThreads = MIN_THREADS;
    if (newThreads > MAX_THREADS) newThreads = MAX_THREADS;
    threadCount_.store(newThreads);
    // --- Cache refresh threshold ---
    int curRefresh = refreshPct_.load();
    // Boot phase: if hit rate is low, be aggressive about refresh
    if (samplesCollected_ < 12) {
        refreshPct_.store(15);
    } else if (hitRate < 0.3 && curRefresh < 30) {
        refreshPct_.store(std::min(curRefresh + 5, 30));
        LOG_DEBUG("AI-Tuner: cache refresh " + std::to_string(refreshPct_.load()) + "% (low hit rate)");
    } else if (hitRate > 0.8 && curRefresh > 5) {
        refreshPct_.store(std::max(curRefresh - 2, 5));
    }

    prevLatency_ = lat;
    prevErrorRate_ = err;

    samplesCollected_++;

    LOG_INFO("AI-Tuner: conns=" + std::to_string(connCount_.load()) +
             " threads=" + std::to_string(threadCount_.load()) +
             " refresh=" + std::to_string(refreshPct_.load()) + "%" +
             " fanout=" + (fanOut_.load() ? "on" : "off") +
             " lat=" + std::to_string(lat) + "ms" +
             " trend=" + std::to_string(trend) +
             " var=" + std::to_string(variance) +
             " err=" + std::to_string(err) +
             " hit=" + std::to_string(hitRate) +
             " pid=" + std::to_string(pidOutput) +
             " load=" + std::to_string(load));
}
