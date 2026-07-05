// SPDX-License-Identifier: MIT
//
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <array>
#include <cstring>
#include <stdexcept>
#include <arpa/inet.h>
#include <netinet/in.h>

#if defined(__SSE4_2__) && !defined(NO_SIMD)
#include <smmintrin.h>
#endif

struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;

    bool qr() const { return (flags >> 15) & 1; }
    uint8_t opcode() const { return (flags >> 11) & 0xF; }
    bool aa() const { return (flags >> 10) & 1; }
    bool tc() const { return (flags >> 9) & 1; }
    bool rd() const { return (flags >> 8) & 1; }
    bool ra() const { return (flags >> 7) & 1; }
    uint8_t rcode() const { return flags & 0xF; }

    void setQr(bool v) { flags = (flags & ~0x8000) | (v << 15); }
    void setOpcode(uint8_t v) { flags = (flags & ~0x7800) | ((v & 0xF) << 11); }
    void setAa(bool v) { flags = (flags & ~0x0400) | (v << 10); }
    void setTc(bool v) { flags = (flags & ~0x0200) | (v << 9); }
    void setRd(bool v) { flags = (flags & ~0x0100) | (v << 8); }
    void setRa(bool v) { flags = (flags & ~0x0080) | (v << 7); }
    void setRcode(uint8_t v) { flags = (flags & ~0x000F) | (v & 0xF); }
};

struct DnsQuestion {
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;
};

struct DnsResourceRecord {
    std::string name;
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    std::vector<uint8_t> rdata;

    std::string rdataToString() const;
};

class DnsMessage;
using DnsMessagePtr = std::shared_ptr<DnsMessage>;

class DnsMessage {
public:
    DnsHeader header{};
    std::vector<DnsQuestion> questions;
    std::vector<DnsResourceRecord> answers;
    std::vector<DnsResourceRecord> authorities;
    std::vector<DnsResourceRecord> additionals;

    static DnsMessagePtr parse(const uint8_t* data, size_t len);
    std::vector<uint8_t> pack() const;

    static DnsMessagePtr createQuery(const std::string& name, uint16_t qtype,
                                     uint16_t qclass = 0x0001);
    static DnsMessagePtr createReply(const DnsMessage& query);
    static DnsMessagePtr createError(const DnsMessage& query, uint8_t rcode);

    DnsMessagePtr copy() const;

    std::string toString() const;
    bool hasQuestions() const { return !questions.empty(); }
    const DnsQuestion& question(size_t idx = 0) const { return questions[idx]; }
    size_t numQuestions() const { return questions.size(); }
};

inline uint16_t rdataToUint16(const std::vector<uint8_t>& rdata, size_t off = 0) {
    if (off + 2 > rdata.size()) return 0;
    return (rdata[off] << 8) | rdata[off + 1];
}

inline uint32_t rdataToUint32(const std::vector<uint8_t>& rdata, size_t off = 0) {
    if (off + 4 > rdata.size()) return 0;
    return (static_cast<uint32_t>(rdata[off]) << 24) |
           (static_cast<uint32_t>(rdata[off + 1]) << 16) |
           (static_cast<uint32_t>(rdata[off + 2]) << 8) |
           rdata[off + 3];
}

struct DnsType {
    static constexpr uint16_t A = 1;
    static constexpr uint16_t NS = 2;
    static constexpr uint16_t CNAME = 5;
    static constexpr uint16_t SOA = 6;
    static constexpr uint16_t PTR = 12;
    static constexpr uint16_t MX = 15;
    static constexpr uint16_t TXT = 16;
    static constexpr uint16_t AAAA = 28;
    static constexpr uint16_t ANY = 255;
};

struct DnsRcode {
    static constexpr uint8_t NoError = 0;
    static constexpr uint8_t FormErr = 1;
    static constexpr uint8_t ServFail = 2;
    static constexpr uint8_t NXDomain = 3;
    static constexpr uint8_t NotImp = 4;
    static constexpr uint8_t Refused = 5;
};

namespace dns_helpers {

// SIMD-accelerated case-insensitive name comparison
inline bool nameEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    // Case-insensitive comparison: DNS names are case-insensitive
#if defined(__SSE4_2__) && !defined(NO_SIMD)
    const char* pa = a.data();
    const char* pb = b.data();
    size_t len = a.size();
    size_t i = 0;
    // Process 16 bytes at a time with SSE4.2 (only full chunks)
    for (; i + 16 <= len; i += 16) {
        __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pa + i));
        __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pb + i));
        __m128i diff = _mm_xor_si128(va, vb);
        // Exact match — continue
        if (_mm_testz_si128(diff, diff)) continue;
        // Check if the only difference is bit 5 (case bit)
        __m128i nonCaseMask = _mm_set1_epi8(~0x20);
        __m128i nonCaseDiff = _mm_and_si128(diff, nonCaseMask);
        if (_mm_testz_si128(nonCaseDiff, nonCaseDiff) == 0) return false;
        // Bit-5-only differences must be actual letter pairs (A-Z / a-z)
        // Normalize both to lowercase and verify they're in 'a'..'z'
        __m128i caseMask = _mm_set1_epi8(0x20);
        __m128i lowVa = _mm_or_si128(va, caseMask);
        __m128i ge_a = _mm_cmpeq_epi8(_mm_max_epu8(lowVa, _mm_set1_epi8('a')), lowVa);
        __m128i le_z = _mm_cmpeq_epi8(_mm_min_epu8(lowVa, _mm_set1_epi8('z')), lowVa);
        __m128i letter = _mm_and_si128(ge_a, le_z);
        // Combine with exact-match positions (those don't need the letter check)
        __m128i exact = _mm_cmpeq_epi8(diff, _mm_setzero_si128());
        __m128i ok = _mm_or_si128(exact, letter);
        if (_mm_movemask_epi8(ok) != 0xFFFF) return false;
    }
    // Tail bytes (less than 16)
    for (; i < len; ++i) {
        char ca = pa[i], cb = pb[i];
        if (ca == cb) continue;
        if (ca >= 'A' && ca <= 'Z') ca |= 0x20;
        if (cb >= 'A' && cb <= 'Z') cb |= 0x20;
        if (ca != cb) return false;
    }
    return true;
#else
    auto ciEq = [](char ca, char cb) {
        if (ca == cb) return true;
        if (ca >= 'A' && ca <= 'Z') ca |= 0x20;
        if (cb >= 'A' && cb <= 'Z') cb |= 0x20;
        return ca == cb;
    };
    for (size_t i = 0; i < a.size(); ++i) {
        if (!ciEq(a[i], b[i])) return false;
    }
    return true;
#endif
}

// Fast wire-to-name with inline buffer for small names
inline std::string wireToName(const uint8_t*& p, const uint8_t* end,
                               const uint8_t* start) {
    std::string name;
    name.reserve(64);
    bool jumped = false;
    const uint8_t* saved = nullptr;
    int jumpCount = 0;

    while (true) {
        if (p >= end) throw std::runtime_error("truncated DNS name");
        uint8_t len = *p;
        if (len == 0) {
            if (!jumped) ++p;
            break;
        }
        if ((len & 0xC0) == 0xC0) {
            if (p + 1 >= end) throw std::runtime_error("truncated DNS pointer");
            if (++jumpCount > 10) throw std::runtime_error("DNS compression pointer cycle");
            uint16_t offset = ((len & 0x3F) << 8) | p[1];
            if (!jumped) {
                p += 2;
                saved = p;
            }
            p = start + offset;
            jumped = true;
            continue;
        }
        ++p;
        if (p + len > end) throw std::runtime_error("truncated DNS label");
        if (!name.empty()) name.push_back('.');
        name.append(reinterpret_cast<const char*>(p), len);
        p += len;
    }
    if (jumped && saved) p = saved;
    return name;
}

inline std::string nameToWire(const std::string& name) {
    std::string out;
    if (name == "." || name.empty()) {
        out.push_back(0);
        return out;
    }
    out.reserve(name.size() + 2);
    size_t start = 0;
    while (start <= name.size()) {
        auto dot = name.find('.', start);
        size_t end = (dot != std::string::npos) ? dot : name.size();
        size_t len = end - start;
        if (len > 0) {
            if (len > 63) throw std::runtime_error("label too long");
            out.push_back(static_cast<uint8_t>(len));
            out.append(name.data() + start, len);
        }
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    out.push_back(0);
    return out;
}

} // namespace dns_helpers
