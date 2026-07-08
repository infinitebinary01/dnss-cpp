// SPDX-License-Identifier: MIT
//
#include "caching_resolver.hpp"
#include "logger.hpp"
#include <algorithm>
#include <thread>
#include <vector>
#include <fstream>
#include <cstring>
#include <immintrin.h>

uint64_t CachingResolver::turboHash(const CacheKey& k) {
    uint64_t h = 14695981039346656037ULL;
    for (char c : k.name) { h ^= (uint8_t)c; h *= 1099511628211ULL; }
    h ^= (uint64_t)k.type << 16;
    h ^= (uint64_t)k.qclass;
    return h;
}



CachingResolver::CachingResolver(std::unique_ptr<Resolver> back)
    : back_(std::move(back)) {
    for (auto& f : turboFreq_) f.store(0);
}

CachingResolver::~CachingResolver() {
    running_ = false;
    if (maintainThread_.joinable()) maintainThread_.join();
    if (refreshThread_.joinable()) refreshThread_.join();
    if (adaptivePrewarmThread_.joinable()) adaptivePrewarmThread_.join();
    saveCache();
}

bool CachingResolver::turboLookup(uint64_t h, DnsMessagePtr& out) {
    size_t idx = h & (TURBO_SIZE - 1);
    auto& slot = turbo_[idx];
    while (slot.lock.test_and_set(std::memory_order_acquire)) {
        _mm_pause();
    }
    if (slot.keyHash.load(std::memory_order_relaxed) != h) {
        slot.lock.clear(std::memory_order_release);
        return false;
    }
    auto m = slot.msg;
    auto exp = slot.expiresAt;
    slot.lock.clear(std::memory_order_release);
    if (!m) return false;
    if (std::chrono::steady_clock::now() >= exp) return false;
    out = std::move(m);
    turboFreq_[idx].fetch_add(1, std::memory_order_relaxed);
    return true;
}

void CachingResolver::turboInsert(uint64_t h, DnsMessagePtr msg,
                                   std::chrono::steady_clock::time_point expiresAt) {
    size_t idx = h & (TURBO_SIZE - 1);
    auto& slot = turbo_[idx];
    while (slot.lock.test_and_set(std::memory_order_acquire)) {
        _mm_pause();
    }
    slot.keyHash.store(h, std::memory_order_relaxed);
    slot.msg = std::move(msg);
    slot.expiresAt = expiresAt;
    slot.lock.clear(std::memory_order_release);
    turboFreq_[idx].store(0, std::memory_order_relaxed);
}

void CachingResolver::saveCache() {
    if (cacheFile_.empty()) return;
    std::ofstream out(cacheFile_, std::ios::binary);
    if (!out) {
        LOG_WARN("Cannot write cache file: " + cacheFile_);
        return;
    }
    std::unique_lock lock(cacheMutex_);
    uint32_t magic = CACHE_MAGIC;
    uint32_t ver = CACHE_VERSION;
    uint32_t count = 0;
    // First pass: count non-expired entries
    auto now = std::chrono::steady_clock::now();
    auto sysNow = std::chrono::system_clock::now();
    for (auto& [key, entry] : cache_) {
        if (now < entry.expiresAt) count++;
    }
    out.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
    out.write(reinterpret_cast<const char*>(&ver), sizeof(ver));
    out.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (auto& [key, entry] : cache_) {
        if (now >= entry.expiresAt) continue;
        auto remaining = std::chrono::duration_cast<std::chrono::seconds>(entry.expiresAt - now).count();
        if (remaining < 1) continue;
        if (key.name.size() > 255 || !entry.msg) continue;
        auto wire = entry.msg->pack();
        if (wire.size() > 65535) continue;
        uint8_t nameLen = static_cast<uint8_t>(key.name.size());
        uint16_t type = key.type;
        uint16_t qclass = key.qclass;
        uint32_t ttl = static_cast<uint32_t>(remaining);
        uint16_t wireLen = static_cast<uint16_t>(wire.size());
        out.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
        out.write(key.name.data(), nameLen);
        out.write(reinterpret_cast<const char*>(&type), sizeof(type));
        out.write(reinterpret_cast<const char*>(&qclass), sizeof(qclass));
        out.write(reinterpret_cast<const char*>(&ttl), sizeof(ttl));
        out.write(reinterpret_cast<const char*>(&wireLen), sizeof(wireLen));
        out.write(reinterpret_cast<const char*>(wire.data()), wire.size());
    }
    LOG_INFO("Cache saved: " + std::to_string(count) + " entries to " + cacheFile_);
}

void CachingResolver::loadCache() {
    if (cacheFile_.empty()) return;
    std::ifstream in(cacheFile_, std::ios::binary);
    if (!in) {
        LOG_WARN("Cannot read cache file: " + cacheFile_);
        return;
    }
    uint32_t magic, ver, count;
    in.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if (magic != CACHE_MAGIC) {
        LOG_WARN("Invalid cache file magic");
        return;
    }
    in.read(reinterpret_cast<char*>(&ver), sizeof(ver));
    if (ver != CACHE_VERSION) {
        LOG_WARN("Unsupported cache version: " + std::to_string(ver));
        return;
    }
    in.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (count > 100000) {
        LOG_WARN("Cache entry count too large: " + std::to_string(count));
        return;
    }
    std::unique_lock lock(cacheMutex_);
    auto now = std::chrono::steady_clock::now();
    int loaded = 0;
    for (uint32_t i = 0; i < count && in.good(); i++) {
        uint8_t nameLen;
        in.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
        std::string name(nameLen, '\0');
        in.read(&name[0], nameLen);
        uint16_t type, qclass;
        in.read(reinterpret_cast<char*>(&type), sizeof(type));
        in.read(reinterpret_cast<char*>(&qclass), sizeof(qclass));
        uint32_t ttl;
        in.read(reinterpret_cast<char*>(&ttl), sizeof(ttl));
        uint16_t wireLen;
        in.read(reinterpret_cast<char*>(&wireLen), sizeof(wireLen));
        if (!in.good() || wireLen < 12 || wireLen > 4096) continue;
        std::vector<uint8_t> wire(wireLen);
        in.read(reinterpret_cast<char*>(wire.data()), wireLen);
        if (!in.good()) continue;
        auto msg = DnsMessage::parse(wire.data(), wireLen);
        if (!msg || !msg->hasQuestions()) continue;
        CacheKey key{name, type, qclass};
        auto remaining = std::chrono::seconds(ttl);
        clobberTTL(*msg, remaining);
        CacheEntry entry;
        entry.msg = std::move(msg);
        entry.ttl = remaining;
        entry.expiresAt = now + remaining;
        cache_[key] = std::move(entry);
        loaded++;
    }
    LOG_INFO("Cache loaded: " + std::to_string(loaded) + " entries from " + cacheFile_);
    in.close();
}

void CachingResolver::warmupCache() {
    const char* topDomains[] = {
        "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
        "twitter.com", "instagram.com", "reddit.com", "linkedin.com", "whatsapp.com",
        "zoom.us", "netflix.com", "microsoft.com", "apple.com", "cloudflare.com",
        "github.com", "stackoverflow.com", "yahoo.com", "bing.com", "pop-os.org"
    };
    int warmed = 0;
    for (auto name : topDomains) {
        auto q = DnsMessage::createQuery(name, DnsType::A);
        if (q && this->query(*q, false)) warmed++;
        auto q4 = DnsMessage::createQuery(name, DnsType::AAAA);
        if (q4 && this->query(*q4, false)) warmed++;
    }
    LOG_INFO("Cache warmup: " + std::to_string(warmed) + " entries pre-populated");
}

void CachingResolver::init() {
    back_->init();
    warmupCache();
}

void CachingResolver::reload() {
    back_->reload();
}

void CachingResolver::maintain() {
    back_->maintain();
    running_ = true;

    // GC thread: removes expired entries every 30s
    maintainThread_ = std::thread([this]() {
        try {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                if (!running_) break;
                gcCache();
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Cache GC thread error: " + std::string(e.what()));
        }
    });

    // Preemptive refresh thread: check every 10s for entries nearing expiry
    refreshThread_ = std::thread([this]() {
        try {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                if (!running_) break;
                std::vector<std::pair<CacheKey, DnsQuestion>> toRefresh;
                {
                std::shared_lock lock(cacheMutex_);
                for (auto& [key, entry] : cache_) {
                        if (running_ && needsRefresh(entry) &&
                            entry.ttl >= minTTL) {
                            toRefresh.emplace_back(key, DnsQuestion{key.name, key.type, key.qclass});
                        }
                    }
                }
                for (auto& [key, question] : toRefresh) {
                    if (!running_) break;
                    try {
                        refreshEntry(key, question);
                    } catch (const std::exception& e) {
                        LOG_ERROR("Cache refresh error for " + key.name + ": " + std::string(e.what()));
                    }
                }
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Cache refresh thread error: " + std::string(e.what()));
        }
    });

    // Adaptive prewarm: every 60s, prewarm top-10 most-queried domains
    adaptivePrewarmThread_ = std::thread([this]() {
        try {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::seconds(60));
                if (!running_) break;
                doAdaptivePrewarm();
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Adaptive prewarm thread error: " + std::string(e.what()));
        }
    });
}

bool CachingResolver::needsRefresh(const CacheEntry& entry) {
    if (isExpired(entry)) return false;
    int threshold = AutoTuner::instance().cacheRefreshThresholdPct();
    auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
        entry.expiresAt - std::chrono::steady_clock::now());
    auto total = entry.ttl;
    if (total.count() <= 0) return false;
    auto remainingPct = remaining.count() * 100 / total.count();
    return remainingPct < threshold;
}

void CachingResolver::refreshEntry(const CacheKey& key, const DnsQuestion& question) {
    DnsMessage query;
    query.header.id = 0;
    query.header.flags = 0;
    query.header.setRd(true);
    query.header.qdcount = 1;
    query.questions.push_back(question);

    auto reply = back_->query(query);
    if (!reply) return;

    if (shouldCache(question, *reply)) {
        auto ttl = computeCacheTTL(*reply);
        if (reply->header.rcode() == DnsRcode::NXDomain ||
            reply->header.rcode() == DnsRcode::ServFail ||
            reply->header.rcode() == DnsRcode::Refused) {
            ttl = negativeTTL;
        }
        clobberTTL(*reply, ttl);
        std::unique_lock lock(cacheMutex_);
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            it->second.msg = std::move(reply);
            it->second.ttl = ttl;
            it->second.expiresAt = std::chrono::steady_clock::now() + ttl;
            preemptiveRefreshes_++;
            LOG_DEBUG("preemptive refresh: " + key.name +
                      " TTL " + std::to_string(ttl.count()) + "s");
        }
    }
}

DnsMessagePtr CachingResolver::query(const DnsMessage& req, bool allowFanOut) {
    totalQueries_++;

    if (req.questions.size() != 1)
        return back_->query(req, allowFanOut);

    const auto& q = req.questions[0];
    CacheKey key{q.qname, q.qtype, q.qclass};
    uint64_t h = turboHash(key);

    // Track for adaptive prewarm
    {
        std::lock_guard<std::mutex> lock(prewarmMutex_);
        prewarmTracker_[q.qname]++;
    }

    // L1 turbo lookup (lock-free fast path)
    {
        DnsMessagePtr turboMsg;
        if (turboLookup(h, turboMsg)) {
            cacheHits_++;
            turboHits_++;
            PerfMonitor::instance().recordCacheHit();
            return buildCachedReply(req, *turboMsg);
        }
    }

    // L2 main cache lookup
    {
        std::shared_lock lock(cacheMutex_);
        auto it = cache_.find(key);
        if (it != cache_.end() && !isExpired(it->second) && it->second.msg) {
            cacheHits_++;
            PerfMonitor::instance().recordCacheHit();
            turboInsert(h, it->second.msg, it->second.expiresAt);
            return buildCachedReply(req, *it->second.msg);
        }
    }

    cacheMisses_++;
    PerfMonitor::instance().recordCacheMiss();

    // Honor auto-tuner's fan-out decision (honed globally based on latency/errors)
    auto reply = back_->query(req, AutoTuner::instance().fanOutEnabled());
    if (!reply) return nullptr;

    if (shouldCache(q, *reply)) {
        auto ttl = computeCacheTTL(*reply);
        if (reply->header.rcode() == DnsRcode::NXDomain ||
            reply->header.rcode() == DnsRcode::ServFail ||
            reply->header.rcode() == DnsRcode::Refused) {
            ttl = negativeTTL;
        }
        clobberTTL(*reply, ttl);
        auto expiresAt = std::chrono::steady_clock::now() + ttl;
        {
            std::unique_lock lock(cacheMutex_);
            if (cache_.size() >= maxCacheSize) {
                // Evict the entry with shortest remaining TTL
                auto nowEvict = std::chrono::steady_clock::now();
                auto evictIt = cache_.begin();
                uint64_t minTTLval = UINT64_MAX;
                for (auto it = cache_.begin(); it != cache_.end(); ++it) {
                    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
                        it->second.expiresAt - nowEvict).count();
                    if (rem > 0 && static_cast<uint64_t>(rem) < minTTLval) {
                        minTTLval = rem;
                        evictIt = it;
                    }
                }
                cache_.erase(evictIt);
            }
            CacheEntry entry;
            entry.msg = reply->copy();
            entry.ttl = ttl;
            entry.expiresAt = expiresAt;
            cache_[key] = std::move(entry);
            cacheRecorded_++;
        }
        turboInsert(h, reply->copy(), expiresAt);
        LOG_DEBUG("cache: recorded " + q.qname + " TTL " +
                  std::to_string(std::chrono::duration_cast<std::chrono::seconds>(ttl).count()) + "s");
    }

    return reply;
}

bool CachingResolver::shouldCache(const DnsQuestion& question, const DnsMessage& reply) {
    if (!reply.header.qr()) return false;
    if (reply.header.opcode() != 0) return false;
    if (reply.questions.size() != 1) return false;
    if (reply.header.tc()) return false;
    if (reply.questions[0].qname != question.qname ||
        reply.questions[0].qtype != question.qtype) {
        return false;
    }
    uint8_t rcode = reply.header.rcode();
    if (rcode == DnsRcode::NXDomain) return true;
    if (rcode == DnsRcode::ServFail) return true;
    if (rcode == DnsRcode::Refused) return true;
    if (rcode != DnsRcode::NoError) return false;
    if (!reply.answers.empty()) return true;
    if (!reply.authorities.empty()) return true;
    return false;
}

std::chrono::seconds CachingResolver::computeCacheTTL(const DnsMessage& reply) {
    uint32_t min_ttl = maxTTL.count();
    bool has_rr = false;
    for (auto* section : {&reply.answers, &reply.authorities, &reply.additionals}) {
        for (auto& rr : *section) {
            if (rr.ttl < min_ttl) min_ttl = rr.ttl;
            has_rr = true;
        }
    }
    std::chrono::seconds ttl = has_rr ? std::chrono::seconds(min_ttl) : minTTL;
    if (ttl < minTTL) ttl = minTTL;
    if (ttl > maxTTL) ttl = maxTTL;
    return ttl;
}

void CachingResolver::clobberTTL(DnsMessage& msg, std::chrono::seconds ttl) {
    uint32_t ttl_s = static_cast<uint32_t>(ttl.count());
    for (auto& rr : msg.answers) rr.ttl = ttl_s;
    for (auto& rr : msg.authorities) rr.ttl = ttl_s;
    for (auto& rr : msg.additionals) rr.ttl = ttl_s;
}

DnsMessagePtr CachingResolver::buildCachedReply(const DnsMessage& req,
                                                  const DnsMessage& cached) {
    auto reply = DnsMessage::createReply(req);
    reply->answers = cached.answers;
    reply->header.ancount = static_cast<uint16_t>(cached.answers.size());
    reply->authorities = cached.authorities;
    reply->header.nscount = static_cast<uint16_t>(cached.authorities.size());
    reply->additionals = cached.additionals;
    reply->header.arcount = static_cast<uint16_t>(cached.additionals.size());
    return reply;
}

bool CachingResolver::isExpired(const CacheEntry& entry) {
    return std::chrono::steady_clock::now() >= entry.expiresAt;
}

void CachingResolver::gcCache() {
    std::unique_lock lock(cacheMutex_);
    size_t before = cache_.size();
    for (auto it = cache_.begin(); it != cache_.end();) {
        if (isExpired(it->second)) {
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }
    LOG_DEBUG("cache GC: " + std::to_string(before) + " -> " +
              std::to_string(cache_.size()) + " entries");
}

void CachingResolver::flushCache() {
    std::unique_lock lock(cacheMutex_);
    cache_.clear();
    LOG_INFO("cache flushed");
}

size_t CachingResolver::cacheSize() const {
    std::shared_lock lock(cacheMutex_);
    return cache_.size();
}

int64_t CachingResolver::hits() const { return cacheHits_.load(); }
int64_t CachingResolver::misses() const { return cacheMisses_.load(); }
int64_t CachingResolver::total() const { return totalQueries_.load(); }

int CachingResolver::countConnected() const { return back_->countConnected(); }

void CachingResolver::doAdaptivePrewarm() {
    std::vector<std::pair<std::string, uint64_t>> sorted;
    {
        std::lock_guard<std::mutex> lock(prewarmMutex_);
        for (auto& [name, count] : prewarmTracker_) {
            if (count > 0) sorted.push_back({name, count});
        }
        prewarmTracker_.clear();
    }
    if (sorted.empty()) return;

    std::sort(sorted.begin(), sorted.end(),
              [](auto& a, auto& b) { return a.second > b.second; });

    int prewarmed = 0;
    int count = 0;
    for (auto& [name, _] : sorted) {
        if (++count > 10) break;
        CacheKey key{name, DnsType::A, 1};
        DnsMessagePtr dummy;
        if (turboLookup(turboHash(key), dummy)) continue;

        auto q = DnsMessage::createQuery(name, DnsType::A);
        if (q) {
            if (back_->query(*q, false)) {
                prewarmed++;
            }
        }
    }

    if (prewarmed > 0) {
        LOG_INFO("Adaptive prewarm: " + std::to_string(prewarmed) +
                 " domains refreshed");
    }
}
