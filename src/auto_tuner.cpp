// SPDX-License-Identifier: MIT
//
#include "auto_tuner.hpp"
#include "caching_resolver.hpp"
#include "latency_manager.hpp"
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

    // LatencyManager evaluates gap to targets and computes urgency
    LatencyManager::instance().evaluate(perf);
    int latUrgency = LatencyManager::instance().urgencyLevel();

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
    qps_.store(qps);

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

    // --- Anomaly detection (runs BEFORE growth so cuts are not undone) ---
    int load = perf.threadPoolLoad;
    bool anomalyHit = false;

    // Stuck queue: pending > 200 for 3+ cycles
    if (load > 200 && consecutiveHighLat_ >= 3) {
        int curT = threadCount_.load();
        int curC = connCount_.load();
        int newT = std::max(curT - 2, MIN_THREADS);
        int newC = std::max(curC - 2, MIN_CONNS);
        threadCount_.store(newT);
        connCount_.store(newC);
        int curMin = CachingResolver::getMinTTL();
        CachingResolver::setMinTTL(std::min(curMin + 120, 1200));
        CachingResolver::setNegativeTTL(std::min(
            CachingResolver::getNegativeTTL() + 120, 600));
        LOG_WARN("AI-Tuner: ANOMALY — queue=" + std::to_string(load) +
                 " cutting threads=" + std::to_string(newT) +
                 " conns=" + std::to_string(newC));
        consecutiveHighLat_ = 0;
        consecutiveHighErr_ = 0;
        anomalyHit = true;
    }

    // Error spike: >3% for 2+ consecutive cycles
    if (err > 0.03 && consecutiveHighErr_ >= 2) {
        int curC = connCount_.load();
        connCount_.store(std::max(curC - 1, MIN_CONNS));
        LOG_WARN("AI-Tuner: ANOMALY — error spike " + std::to_string(err) +
                 " cutting connections");
        consecutiveHighErr_ = 0;
        anomalyHit = true;
    }

    // Hit rate collapse: <50% after 60+ samples
    if (hitRate < 0.5 && samplesCollected_ > 60) {
        CachingResolver::setMinTTL(std::min(
            CachingResolver::getMinTTL() + 300, 1800));
        CachingResolver::setNegativeTTL(std::min(
            CachingResolver::getNegativeTTL() + 120, 900));
        LOG_WARN("AI-Tuner: ANOMALY — hit rate collapse to " +
                 std::to_string(hitRate) + " increasing TTLs");
        anomalyHit = true;
    }

    bool skipGrowth = anomalyHit;
    if (anomalyHit) {
        anomalyCooldown_ = 6; // prevent growth for ~30 seconds
    } else if (anomalyCooldown_ > 0) {
        anomalyCooldown_--;
        if (anomalyCooldown_ > 0) skipGrowth = true;
    }

    if (skipGrowth) {
        prevLatency_ = lat;
        prevErrorRate_ = err;
        samplesCollected_++;
        LOG_INFO("AI-Tuner:" +
                 std::string(anomalyHit ? " ANOMALY" : "") +
                 " cooldown=" + std::to_string(anomalyCooldown_) +
                 " conns=" + std::to_string(connCount_.load()) +
                 " threads=" + std::to_string(threadCount_.load()) +
                 " refresh=" + std::to_string(refreshPct_.load()) + "%" +
                 " minTTL=" + std::to_string(CachingResolver::getMinTTL()) + "s" +
                 " negTTL=" + std::to_string(CachingResolver::getNegativeTTL()) + "s" +
                 " fanout=" + (fanOut_.load() ? "on" : "off") +
                 " lat=" + std::to_string(lat) + "ms" +
                 " trend=" + std::to_string(trend) +
                 " var=" + std::to_string(variance) +
                 " err=" + std::to_string(err) +
                 " hit=" + std::to_string(hitRate) +
                 " pid=" + std::to_string(pidOutput) +
                 " load=" + std::to_string(load) +
                 " urgen=" + std::to_string(latUrgency) +
                 " gap=" + std::to_string(static_cast<int>(LatencyManager::instance().gapPct())) +
                 "% bot=" + LatencyManager::instance().bottleneck());
        return;
    }

    // --- Connection count (turbo-aware) ---
    double util = perf.connUtilization;
    int curConn = connCount_.load();
    int newConn = curConn;

    // Turbo connection growth: when pending queue is deep, add connections aggressively
    int poolLoad = perf.threadPoolLoad;
    bool inTurbo = (turboCycles_ >= 2);
    if (inTurbo && poolLoad > 50) {
        int growth = std::min(4, MAX_CONNS - curConn);
        if (growth > 0) {
            newConn = curConn + growth;
            LOG_DEBUG("AI-Tuner: TURBO +" + std::to_string(growth) +
                      " connections (" + std::to_string(newConn) +
                      ") — load=" + std::to_string(poolLoad));
        }
    }

    // Proxy saturation detection: if latency is high AND connections are already
    // moderate, more connections will only congest the proxy further. Shrink instead.
    // Only trigger when threads are NOT the bottleneck (util < 0.7 means connections
    // are underutilized — high latency is from the network, not connection congestion).
    bool proxySaturated = (lat > 1000 && util < 0.7 && curConn > MIN_CONNS);
    if (!inTurbo) {
        if (proxySaturated) {
            newConn = std::max(curConn - 1, MIN_CONNS);
            if (newConn != curConn)
                LOG_DEBUG("AI-Tuner: -1 connection (" +
                          std::to_string(newConn) + ") — proxy saturated");
        } else if (consecutiveLowLoad_ >= 3 && curConn > MIN_CONNS) {
            newConn = curConn - 1;
            LOG_DEBUG("AI-Tuner: -1 connection (" + std::to_string(newConn) + ") — low load");
        }
    }

    // Only grow when proxy is NOT saturated
    if (!inTurbo && !proxySaturated) {
        if (util > 0.90 && lat > 200 && curConn < MAX_CONNS) {
            int growth = util > 0.95 ? 3 : 2;
            newConn = std::min(curConn + growth, MAX_CONNS);
            LOG_DEBUG("AI-Tuner: +" + std::to_string(growth) + " connections (" +
                      std::to_string(newConn) + ") — parallelism bottleneck (util=" +
                      std::to_string(static_cast<int>(util * 100)) + "% lat=" + std::to_string(lat) + "ms)");
        } else if (util > 0.70 && trend > 3 && qps > 5 && curConn < MAX_CONNS) {
            newConn = std::min(curConn + 2, MAX_CONNS);
            LOG_DEBUG("AI-Tuner: +2 connections (" +
                      std::to_string(newConn) + ") — pre-emptive (util=" +
                      std::to_string(static_cast<int>(util * 100)) + "% trend=" + std::to_string(trend) + ")");
        } else if (util > 0.85 && qps > 5 && curConn < MAX_CONNS) {
            int growth = util > 0.95 ? 3 : 2;
            newConn = std::min(curConn + growth, MAX_CONNS);
            LOG_DEBUG("AI-Tuner: +" + std::to_string(growth) + " connections (" +
                      std::to_string(newConn) + ") — utilization " +
                      std::to_string(static_cast<int>(util * 100)) + "%");
        } else if (err > 0.02 || consecutiveHighErr_ >= 2) {
            newConn = std::min(curConn + 2, MAX_CONNS);
            LOG_DEBUG("AI-Tuner: +2 connections (" + std::to_string(newConn) + ") — errors");
        } else if (lat > 200 && qps > 5 && curConn < MAX_CONNS) {
            newConn = std::min(curConn + 1, MAX_CONNS);
            LOG_DEBUG("AI-Tuner: +1 connection (" + std::to_string(newConn) + ") — high latency under load");
        } else if (trend > 5 && curConn < MAX_CONNS) {
            newConn = std::min(curConn + 1, MAX_CONNS);
            LOG_DEBUG("AI-Tuner: +1 connection (" + std::to_string(newConn) + ") — rising trend");
        }
    }

    // LatencyManager boost: urgency-driven connection growth
    if (latUrgency > 0 && !proxySaturated && newConn < MAX_CONNS) {
        int lmBoost = LatencyManager::instance().connBoost();
        int boosted = std::min(newConn + lmBoost, MAX_CONNS);
        if (boosted > newConn) {
            LOG_DEBUG("AI-Tuner: LM +" + std::to_string(boosted - newConn) +
                      " connections (" + std::to_string(boosted) + ") — urgency=" +
                      std::to_string(latUrgency));
            newConn = boosted;
        }
    }
    connCount_.store(newConn);

    // --- Fan-out ---
    // Keep fan-out on during boot phase (first 60s) to prevent premature disable
    bool bootPhase = samplesCollected_ < 12;
    // LatencyManager keeps fan-out on when urgency is high
    bool lmForceFan = LatencyManager::instance().forceFanOut();
    // Use P95 to detect tail latency (the Kalman avg may be smooth but tail is high)
    bool tailIssue = perf.p95LatencyMs > 120;
    if (bootPhase || lmForceFan || err > 0.03 || tailIssue || lat > 300 || (variance > 50 && consecutiveHighLat_ >= 2)) {
        bool expected = false;
        if (fanOut_.compare_exchange_weak(expected, true)) {
            LOG_DEBUG("AI-Tuner: enabling fan-out (err=" + std::to_string(err) +
                      " lat=" + std::to_string(lat) + " p95=" + std::to_string(perf.p95LatencyMs) +
                      " var=" + std::to_string(variance) + ")");
        }
    } else if (!lmForceFan && samplesCollected_ > 24 && err < 0.01 && perf.p95LatencyMs < 60 && variance < 20) {
        bool expected = true;
        if (fanOut_.compare_exchange_weak(expected, false)) {
            LOG_DEBUG("AI-Tuner: disabling fan-out — stable low load");
        }
    }

    // --- Thread pool (turbo-aware) ---
    int curThreads = threadCount_.load();
    int newThreads = curThreads;

    // Turbo mode: aggressive scaling when pending queue is deep
    if (load > 50) {
        turboCycles_ = std::min(turboCycles_ + 1, 10);
        if (turboCycles_ >= 2) {
            int growth = std::min(8, MAX_THREADS - curThreads);
            if (growth > 0) {
                newThreads = curThreads + growth;
                LOG_DEBUG("AI-Tuner: TURBO +" + std::to_string(growth) +
                          " threads (" + std::to_string(newThreads) + ") — load=" +
                          std::to_string(load));
            } else {
                // Already at MAX_THREADS — stop accumulating
                turboCycles_ = std::min(turboCycles_, 5);
            }
        }
    } else if (load < 20) {
        turboCycles_ = std::max(0, turboCycles_ - 1);
    } else {
        turboCycles_ = std::max(0, turboCycles_ - 1);
    }

    // Only use PID-based growth when not in turbo mode
    inTurbo = (turboCycles_ >= 2);
    if (!inTurbo) {
        // Preemptive: rising trend with moderate utilization — add thread before queue grows
        if (util > 0.5 && trend > 3 && curThreads < MAX_THREADS) {
            newThreads = std::min(curThreads + 1, MAX_THREADS);
            LOG_DEBUG("AI-Tuner: +1 thread (" + std::to_string(newThreads) +
                      ") — preemptive (util=" + std::to_string(static_cast<int>(util * 100)) +
                      "% trend=" + std::to_string(trend) + ")");
        } else if (util > 0.8 && lat > 200 && curThreads < MAX_THREADS) {
            newThreads = std::min(curThreads + 2, MAX_THREADS);
            LOG_DEBUG("AI-Tuner: +2 threads (" + std::to_string(newThreads) +
                      ") — parallelism bottleneck (util=" + std::to_string(static_cast<int>(util * 100)) +
                      "% lat=" + std::to_string(lat) + "ms)");
        } else if (load > 3 && lat > 100 && curThreads < MAX_THREADS) {
            newThreads = std::min(curThreads + 2, MAX_THREADS);
            LOG_DEBUG("AI-Tuner: +2 threads (" + std::to_string(newThreads) + ") — busy+latent");
        } else if (load > 5 && curThreads < MAX_THREADS) {
            newThreads = std::min(curThreads + 1, MAX_THREADS);
            LOG_DEBUG("AI-Tuner: +1 thread (" + std::to_string(newThreads) + ") — busy");
        }
    }

    // Only shrink when not in turbo
    if (!inTurbo) {
        // Threads > connections × 1.2 → excess threads contend on connections
        if (curThreads > curConn + curConn / 5 && curThreads > MIN_THREADS) {
            newThreads = std::max(curConn + curConn / 5, MIN_THREADS);
            LOG_DEBUG("AI-Tuner: -" + std::to_string(curThreads - newThreads) +
                      " threads (" + std::to_string(newThreads) + ") — excess vs connections");
        } else if (util < 0.7) {
            if (load == 0 && consecutiveLowLoad_ >= 3 && curThreads > MIN_THREADS) {
                newThreads = curThreads - 1;
                LOG_DEBUG("AI-Tuner: -1 thread (" + std::to_string(newThreads) + ") — idle");
            } else if (load < 3 && consecutiveLowLoad_ >= 12 && curThreads > MIN_THREADS) {
                newThreads = curThreads - 1;
                LOG_DEBUG("AI-Tuner: -1 thread (" + std::to_string(newThreads) + ") — low load");
            }
        }
    }

    // LatencyManager boost: urgency-driven thread growth
    if (latUrgency > 0 && !inTurbo && newThreads < MAX_THREADS) {
        int lmBoost = LatencyManager::instance().threadBoost();
        int boosted = std::min(newThreads + lmBoost, MAX_THREADS);
        if (boosted > newThreads) {
            LOG_DEBUG("AI-Tuner: LM +" + std::to_string(boosted - newThreads) +
                      " threads (" + std::to_string(boosted) + ") — urgency=" +
                      std::to_string(latUrgency));
            newThreads = boosted;
        }
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
    } else if (latUrgency > 0 && curRefresh < 50) {
        int lmRefresh = LatencyManager::instance().cacheRefreshBoost();
        int boosted = std::min(curRefresh + lmRefresh, 10);
        refreshPct_.store(boosted);
        LOG_DEBUG("AI-Tuner: cache refresh " + std::to_string(boosted) + "% (urgency=" +
                  std::to_string(latUrgency) + ")");
    } else if (hitRate < 0.3 && curRefresh < 30) {
        refreshPct_.store(std::min(curRefresh + 5, 10));
        LOG_DEBUG("AI-Tuner: cache refresh " + std::to_string(refreshPct_.load()) + "% (low hit rate)");
    } else if (hitRate > 0.8 && curRefresh > 5) {
        refreshPct_.store(std::max(curRefresh - 2, 5));
    }

    // --- Cache TTL tuning ---
    if (samplesCollected_ > 12) {
        int curMin = CachingResolver::getMinTTL();
        int curNeg = CachingResolver::getNegativeTTL();

        // High latency + moderate hit rate → upstream is slow, cache more aggressively
        if (lat > 80 && hitRate < 0.92 && curMin < 900) {
            CachingResolver::setMinTTL(curMin + 60);
            CachingResolver::setNegativeTTL(std::min(curNeg + 60, 600));
            LOG_DEBUG("AI-Tuner: +60s TTLs (lat=" + std::to_string(lat) +
                      " hit=" + std::to_string(hitRate) + ")");
        }

        // Low latency + high hit rate → upstream is fast, relax TTLs
        if (lat < 40 && hitRate > 0.95 && curMin > 300) {
            CachingResolver::setMinTTL(curMin - 60);
            LOG_DEBUG("AI-Tuner: -60s minTTL (lat=" + std::to_string(lat) +
                      " hit=" + std::to_string(hitRate) + ")");
        }
    }

    prevLatency_ = lat;
    prevErrorRate_ = err;

    samplesCollected_++;

    LOG_INFO("AI-Tuner: conns=" + std::to_string(connCount_.load()) +
             " threads=" + std::to_string(threadCount_.load()) +
             " refresh=" + std::to_string(refreshPct_.load()) + "%" +
             " minTTL=" + std::to_string(CachingResolver::getMinTTL()) + "s" +
             " negTTL=" + std::to_string(CachingResolver::getNegativeTTL()) + "s" +
             " fanout=" + (fanOut_.load() ? "on" : "off") +
             " lat=" + std::to_string(lat) + "ms" +
             " trend=" + std::to_string(trend) +
             " var=" + std::to_string(variance) +
             " err=" + std::to_string(err) +
             " hit=" + std::to_string(hitRate) +
             " pid=" + std::to_string(pidOutput) +
             " load=" + std::to_string(load) +
             " urgen=" + std::to_string(latUrgency) +
             " gap=" + std::to_string(static_cast<int>(LatencyManager::instance().gapPct())) +
             "% bot=" + LatencyManager::instance().bottleneck());
}
