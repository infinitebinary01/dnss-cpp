// SPDX-License-Identifier: MIT
//
#include "caching_resolver.hpp"
#include "logger.hpp"
#include <algorithm>
#include <thread>

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
}

bool CachingResolver::turboLookup(uint64_t h, DnsMessagePtr& out) {
    size_t idx = h & (TURBO_SIZE - 1);
    auto& slot = turbo_[idx];
    while (slot.lock.test_and_set(std::memory_order_acquire)) {}
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
    while (slot.lock.test_and_set(std::memory_order_acquire)) {}
    slot.keyHash.store(h, std::memory_order_relaxed);
    slot.msg = std::move(msg);
    slot.expiresAt = expiresAt;
    slot.lock.clear(std::memory_order_release);
    turboFreq_[idx].store(0, std::memory_order_relaxed);
}

void CachingResolver::init() {
    back_->init();
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
                std::unique_lock lock(cacheMutex_);
                for (auto& [key, entry] : cache_) {
                    if (running_ && needsRefresh(entry) &&
                        entry.ttl >= minTTL) {
                        lock.unlock();
                        try {
                            refreshEntry(key, entry);
                        } catch (const std::exception& e) {
                            LOG_ERROR("Cache refresh error for " + key.name + ": " + std::string(e.what()));
                        }
                        lock.lock();
                    }
                }
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Cache refresh thread error: " + std::string(e.what()));
        }
    });
}

bool CachingResolver::needsRefresh(const CacheEntry& entry) {
    if (isExpired(entry)) return false;
    int threshold = AutoTuner::instance().cacheRefreshThresholdPct();
    auto remaining = entry.expiresAt - std::chrono::steady_clock::now();
    auto total = entry.expiresAt - (entry.expiresAt - entry.ttl);
    if (total.count() <= 0) return false;
    auto remainingPct = remaining.count() * 100 / total.count();
    return remainingPct < threshold;
}

void CachingResolver::refreshEntry(const CacheKey& key, CacheEntry& entry) {
    DnsMessage query;
    query.header.id = 0;
    query.header.flags = 0;
    query.header.setRd(true);
    query.header.qdcount = 1;
    query.questions.push_back(entry.question);

    auto reply = back_->query(query);
    if (!reply) return;

    if (shouldCache(entry.question, *reply)) {
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
            it->second.msg = reply->copy();
            it->second.ttl = ttl;
            it->second.expiresAt = std::chrono::steady_clock::now() + ttl;
            preemptiveRefreshes_++;
            LOG_DEBUG("preemptive refresh: " + key.name +
                      " TTL " + std::to_string(ttl.count()) + "s");
        }
    }
}

DnsMessagePtr CachingResolver::query(const DnsMessage& req) {
    totalQueries_++;

    if (req.questions.size() != 1)
        return back_->query(req);

    const auto& q = req.questions[0];
    CacheKey key{q.qname, q.qtype, q.qclass};
    uint64_t h = turboHash(key);

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
        if (it != cache_.end() && !isExpired(it->second)) {
            cacheHits_++;
            PerfMonitor::instance().recordCacheHit();
            turboInsert(h, it->second.msg, it->second.expiresAt);
            return buildCachedReply(req, *it->second.msg);
        }
    }

    cacheMisses_++;
    PerfMonitor::instance().recordCacheMiss();
    auto reply = back_->query(req);
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
            if (cache_.size() < maxCacheSize) {
                CacheEntry entry;
                entry.msg = reply->copy();
                entry.ttl = ttl;
                entry.expiresAt = expiresAt;
                entry.question = q;
                cache_[key] = std::move(entry);
                cacheRecorded_++;
            }
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
