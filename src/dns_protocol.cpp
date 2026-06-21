// SPDX-License-Identifier: MIT
//
#include "dns_protocol.hpp"
#include <cstring>
#include <algorithm>
#include <sstream>

static uint16_t readU16(const uint8_t* p) {
    return (p[0] << 8) | p[1];
}

static void writeU16(uint8_t* p, uint16_t v) {
    p[0] = (v >> 8) & 0xFF;
    p[1] = v & 0xFF;
}

static uint32_t readU32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           p[3];
}

static void writeU32(uint8_t* p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

std::string DnsResourceRecord::rdataToString() const {
    if (type == DnsType::A && rdata.size() >= 4) {
        char buf[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = rdataToUint32(rdata, 0);
        inet_ntop(AF_INET, &addr, buf, sizeof(buf));
        return buf;
    }
    if (type == DnsType::AAAA && rdata.size() >= 16) {
        char buf[INET6_ADDRSTRLEN];
        struct in6_addr addr;
        memcpy(addr.s6_addr, rdata.data(), 16);
        inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
        return buf;
    }
    if (type == DnsType::CNAME || type == DnsType::NS || type == DnsType::PTR) {
        const uint8_t* p = rdata.data();
        const uint8_t* end = p + rdata.size();
        return dns_helpers::wireToName(p, end, rdata.data());
    }
    if (type == DnsType::MX && rdata.size() >= 2) {
        uint16_t pref = rdataToUint16(rdata, 0);
        const uint8_t* p = rdata.data() + 2;
        const uint8_t* end = p + rdata.size() - 2;
        auto name = dns_helpers::wireToName(p, end, rdata.data());
        return std::to_string(pref) + " " + name;
    }
    if (type == DnsType::SOA && rdata.size() >= 22) {
        const uint8_t* p = rdata.data();
        const uint8_t* end = p + rdata.size();
        // Parse MNAME and RNAME (now stored uncompressed after parse fix)
        auto mname = dns_helpers::wireToName(p, end, rdata.data());
        auto rname = dns_helpers::wireToName(p, end, rdata.data());
        // Remaining should be 5 x uint32 = 20 bytes
        if (p + 20 <= end) {
            uint32_t serial = readU32(p); p += 4;
            uint32_t refresh = readU32(p); p += 4;
            uint32_t retry = readU32(p); p += 4;
            uint32_t expire = readU32(p); p += 4;
            uint32_t minimum = readU32(p); p += 4;
            return mname + " " + rname + " " +
                   std::to_string(serial) + " " +
                   std::to_string(refresh) + " " +
                   std::to_string(retry) + " " +
                   std::to_string(expire) + " " +
                   std::to_string(minimum);
        }
    }
    std::string hex;
    for (auto b : rdata) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        hex += buf;
    }
    return "\\#" + hex;
}

static std::string typeToString(uint16_t type) {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 41: return "OPT";
        case 255: return "ANY";
        default: return "TYPE" + std::to_string(type);
    }
}

DnsMessagePtr DnsMessage::parse(const uint8_t* data, size_t len) {
    if (len < 12) throw std::runtime_error("truncated DNS header");

    auto msg = std::make_shared<DnsMessage>();
    const uint8_t* p = data;
    const uint8_t* end = data + len;

    msg->header.id = readU16(p); p += 2;
    msg->header.flags = readU16(p); p += 2;
    msg->header.qdcount = readU16(p); p += 2;
    msg->header.ancount = readU16(p); p += 2;
    msg->header.nscount = readU16(p); p += 2;
    msg->header.arcount = readU16(p); p += 2;

    // Pre-allocate vectors with known sizes
    msg->questions.reserve(msg->header.qdcount);
    msg->answers.reserve(msg->header.ancount);
    msg->authorities.reserve(msg->header.nscount);
    msg->additionals.reserve(msg->header.arcount);

    for (int i = 0; i < msg->header.qdcount; ++i) {
        DnsQuestion q;
        q.qname = dns_helpers::wireToName(p, end, data);
        if (p + 4 > end) throw std::runtime_error("truncated question");
        q.qtype = readU16(p); p += 2;
        q.qclass = readU16(p); p += 2;
        msg->questions.push_back(std::move(q));
    }

    for (int i = 0; i < msg->header.ancount; ++i) {
        DnsResourceRecord rr;
        rr.name = dns_helpers::wireToName(p, end, data);
        if (p + 10 > end) throw std::runtime_error("truncated RR");
        rr.type = readU16(p); p += 2;
        rr.rclass = readU16(p); p += 2;
        rr.ttl = readU32(p); p += 4;
        uint16_t rdlen = readU16(p); p += 2;
        if (p + rdlen > end) throw std::runtime_error("truncated RDLEN");
        // Decompress domain names in RDATA for types that use compression pointers,
        // since compression offsets are relative to the start of the message (data),
        // not the start of the RDATA buffer.
        {
            const uint8_t* rdStart = p;
            switch (rr.type) {
                case DnsType::CNAME:
                case DnsType::NS:
                case DnsType::PTR: {
                    const uint8_t* np = rdStart;
                    auto name = dns_helpers::wireToName(np, end, data);
                    auto wireName = dns_helpers::nameToWire(name);
                    rr.rdata.assign(wireName.begin(), wireName.end());
                    break;
                }
                case DnsType::MX: {
                    if (rdlen < 2) throw std::runtime_error("truncated MX RDATA");
                    uint16_t pref = readU16(rdStart);
                    const uint8_t* np = rdStart + 2;
                    auto name = dns_helpers::wireToName(np, end, data);
                    auto wireName = dns_helpers::nameToWire(name);
                    rr.rdata.resize(2 + wireName.size());
                    writeU16(rr.rdata.data(), pref);
                    memcpy(rr.rdata.data() + 2, wireName.data(), wireName.size());
                    break;
                }
                case DnsType::SOA: {
                    const uint8_t* np = rdStart;
                    auto mname = dns_helpers::wireToName(np, end, data);
                    auto rname = dns_helpers::wireToName(np, end, data);
                    size_t remaining = rdlen - (np - rdStart);
                    if (remaining < 20) throw std::runtime_error("truncated SOA RDATA");
                    auto wireMname = dns_helpers::nameToWire(mname);
                    auto wireRname = dns_helpers::nameToWire(rname);
                    rr.rdata.resize(wireMname.size() + wireRname.size() + 20);
                    uint8_t* wp = rr.rdata.data();
                    memcpy(wp, wireMname.data(), wireMname.size()); wp += wireMname.size();
                    memcpy(wp, wireRname.data(), wireRname.size()); wp += wireRname.size();
                    memcpy(wp, np, 20);
                    break;
                }
                default:
                    rr.rdata.assign(rdStart, rdStart + rdlen);
                    break;
            }
        }
        p += rdlen;
        msg->answers.push_back(std::move(rr));
    }

    for (int i = 0; i < msg->header.nscount; ++i) {
        DnsResourceRecord rr;
        rr.name = dns_helpers::wireToName(p, end, data);
        if (p + 10 > end) throw std::runtime_error("truncated RR");
        rr.type = readU16(p); p += 2;
        rr.rclass = readU16(p); p += 2;
        rr.ttl = readU32(p); p += 4;
        uint16_t rdlen = readU16(p); p += 2;
        if (p + rdlen > end) throw std::runtime_error("truncated RDLEN");
        {
            const uint8_t* rdStart = p;
            switch (rr.type) {
                case DnsType::CNAME:
                case DnsType::NS:
                case DnsType::PTR: {
                    const uint8_t* np = rdStart;
                    auto name = dns_helpers::wireToName(np, end, data);
                    auto wireName = dns_helpers::nameToWire(name);
                    rr.rdata.assign(wireName.begin(), wireName.end());
                    break;
                }
                case DnsType::MX: {
                    if (rdlen < 2) throw std::runtime_error("truncated MX RDATA");
                    uint16_t pref = readU16(rdStart);
                    const uint8_t* np = rdStart + 2;
                    auto name = dns_helpers::wireToName(np, end, data);
                    auto wireName = dns_helpers::nameToWire(name);
                    rr.rdata.resize(2 + wireName.size());
                    writeU16(rr.rdata.data(), pref);
                    memcpy(rr.rdata.data() + 2, wireName.data(), wireName.size());
                    break;
                }
                case DnsType::SOA: {
                    const uint8_t* np = rdStart;
                    auto mname = dns_helpers::wireToName(np, end, data);
                    auto rname = dns_helpers::wireToName(np, end, data);
                    size_t remaining = rdlen - (np - rdStart);
                    if (remaining < 20) throw std::runtime_error("truncated SOA RDATA");
                    auto wireMname = dns_helpers::nameToWire(mname);
                    auto wireRname = dns_helpers::nameToWire(rname);
                    rr.rdata.resize(wireMname.size() + wireRname.size() + 20);
                    uint8_t* wp = rr.rdata.data();
                    memcpy(wp, wireMname.data(), wireMname.size()); wp += wireMname.size();
                    memcpy(wp, wireRname.data(), wireRname.size()); wp += wireRname.size();
                    memcpy(wp, np, 20);
                    break;
                }
                default:
                    rr.rdata.assign(rdStart, rdStart + rdlen);
                    break;
            }
        }
        p += rdlen;
        msg->authorities.push_back(std::move(rr));
    }

    for (int i = 0; i < msg->header.arcount; ++i) {
        DnsResourceRecord rr;
        rr.name = dns_helpers::wireToName(p, end, data);
        if (p + 10 > end) throw std::runtime_error("truncated RR");
        rr.type = readU16(p); p += 2;
        rr.rclass = readU16(p); p += 2;
        rr.ttl = readU32(p); p += 4;
        uint16_t rdlen = readU16(p); p += 2;
        if (p + rdlen > end) throw std::runtime_error("truncated RDLEN");
        {
            const uint8_t* rdStart = p;
            switch (rr.type) {
                case DnsType::CNAME:
                case DnsType::NS:
                case DnsType::PTR: {
                    const uint8_t* np = rdStart;
                    auto name = dns_helpers::wireToName(np, end, data);
                    auto wireName = dns_helpers::nameToWire(name);
                    rr.rdata.assign(wireName.begin(), wireName.end());
                    break;
                }
                case DnsType::MX: {
                    if (rdlen < 2) throw std::runtime_error("truncated MX RDATA");
                    uint16_t pref = readU16(rdStart);
                    const uint8_t* np = rdStart + 2;
                    auto name = dns_helpers::wireToName(np, end, data);
                    auto wireName = dns_helpers::nameToWire(name);
                    rr.rdata.resize(2 + wireName.size());
                    writeU16(rr.rdata.data(), pref);
                    memcpy(rr.rdata.data() + 2, wireName.data(), wireName.size());
                    break;
                }
                case DnsType::SOA: {
                    const uint8_t* np = rdStart;
                    auto mname = dns_helpers::wireToName(np, end, data);
                    auto rname = dns_helpers::wireToName(np, end, data);
                    size_t remaining = rdlen - (np - rdStart);
                    if (remaining < 20) throw std::runtime_error("truncated SOA RDATA");
                    auto wireMname = dns_helpers::nameToWire(mname);
                    auto wireRname = dns_helpers::nameToWire(rname);
                    rr.rdata.resize(wireMname.size() + wireRname.size() + 20);
                    uint8_t* wp = rr.rdata.data();
                    memcpy(wp, wireMname.data(), wireMname.size()); wp += wireMname.size();
                    memcpy(wp, wireRname.data(), wireRname.size()); wp += wireRname.size();
                    memcpy(wp, np, 20);
                    break;
                }
                default:
                    rr.rdata.assign(rdStart, rdStart + rdlen);
                    break;
            }
        }
        p += rdlen;
        msg->additionals.push_back(std::move(rr));
    }

    return msg;
}

std::vector<uint8_t> DnsMessage::pack() const {
    size_t size = 12;
    for (auto& q : questions) size += dns_helpers::nameToWire(q.qname).size() + 4;
    for (auto& rr : answers) size += dns_helpers::nameToWire(rr.name).size() + 10 + rr.rdata.size();
    for (auto& rr : authorities) size += dns_helpers::nameToWire(rr.name).size() + 10 + rr.rdata.size();
    for (auto& rr : additionals) size += dns_helpers::nameToWire(rr.name).size() + 10 + rr.rdata.size();

    std::vector<uint8_t> buf(size);
    uint8_t* p = buf.data();

    writeU16(p, header.id); p += 2;
    writeU16(p, header.flags); p += 2;
    writeU16(p, static_cast<uint16_t>(questions.size())); p += 2;
    writeU16(p, static_cast<uint16_t>(answers.size())); p += 2;
    writeU16(p, static_cast<uint16_t>(authorities.size())); p += 2;
    writeU16(p, static_cast<uint16_t>(additionals.size())); p += 2;

    for (auto& q : questions) {
        auto wire = dns_helpers::nameToWire(q.qname);
        memcpy(p, wire.data(), wire.size()); p += wire.size();
        writeU16(p, q.qtype); p += 2;
        writeU16(p, q.qclass); p += 2;
    }

    for (auto& rr : answers) {
        auto wire = dns_helpers::nameToWire(rr.name);
        memcpy(p, wire.data(), wire.size()); p += wire.size();
        writeU16(p, rr.type); p += 2;
        writeU16(p, rr.rclass); p += 2;
        writeU32(p, rr.ttl); p += 4;
        writeU16(p, static_cast<uint16_t>(rr.rdata.size())); p += 2;
        memcpy(p, rr.rdata.data(), rr.rdata.size()); p += rr.rdata.size();
    }
    for (auto& rr : authorities) {
        auto wire = dns_helpers::nameToWire(rr.name);
        memcpy(p, wire.data(), wire.size()); p += wire.size();
        writeU16(p, rr.type); p += 2;
        writeU16(p, rr.rclass); p += 2;
        writeU32(p, rr.ttl); p += 4;
        writeU16(p, static_cast<uint16_t>(rr.rdata.size())); p += 2;
        memcpy(p, rr.rdata.data(), rr.rdata.size()); p += rr.rdata.size();
    }
    for (auto& rr : additionals) {
        auto wire = dns_helpers::nameToWire(rr.name);
        memcpy(p, wire.data(), wire.size()); p += wire.size();
        writeU16(p, rr.type); p += 2;
        writeU16(p, rr.rclass); p += 2;
        writeU32(p, rr.ttl); p += 4;
        writeU16(p, static_cast<uint16_t>(rr.rdata.size())); p += 2;
        memcpy(p, rr.rdata.data(), rr.rdata.size()); p += rr.rdata.size();
    }

    return buf;
}

DnsMessagePtr DnsMessage::createQuery(const std::string& name, uint16_t qtype, uint16_t qclass) {
    auto msg = std::make_shared<DnsMessage>();
    msg->header.id = 0;
    msg->header.flags = 0;
    msg->header.setRd(true);
    msg->header.qdcount = 1;

    DnsQuestion q;
    q.qname = name;
    q.qtype = qtype;
    q.qclass = qclass;
    msg->questions.push_back(std::move(q));
    return msg;
}

DnsMessagePtr DnsMessage::createReply(const DnsMessage& query) {
    auto msg = query.copy();
    msg->header.setQr(true);
    msg->header.setRa(true);
    msg->header.ancount = 0;
    msg->answers.clear();
    msg->authorities.clear();
    msg->additionals.clear();
    msg->header.nscount = 0;
    msg->header.arcount = 0;
    return msg;
}

DnsMessagePtr DnsMessage::createError(const DnsMessage& query, uint8_t rcode) {
    auto msg = createReply(query);
    msg->header.setRcode(rcode);
    return msg;
}

DnsMessagePtr DnsMessage::copy() const {
    auto msg = std::make_shared<DnsMessage>();
    msg->header = header;
    msg->questions = questions;
    msg->answers = answers;
    msg->authorities = authorities;
    msg->additionals = additionals;
    return msg;
}

std::string DnsMessage::toString() const {
    std::ostringstream os;
    os << ";; id: " << header.id
       << " flags: " << (header.qr() ? "QR " : "")
       << (header.aa() ? "AA " : "")
       << (header.tc() ? "TC " : "")
       << (header.rd() ? "RD " : "")
       << (header.ra() ? "RA " : "")
       << " rcode: " << (int)header.rcode()
       << " qd: " << header.qdcount
       << " an: " << header.ancount
       << " ns: " << header.nscount
       << " ar: " << header.arcount
       << "\n";

    for (auto& q : questions) {
        os << ";; Q: " << q.qname << " " << typeToString(q.qtype)
           << " " << (q.qclass == 1 ? "IN" : "CLASS" + std::to_string(q.qclass)) << "\n";
    }

    auto printRRs = [&](const std::vector<DnsResourceRecord>& rrs) {
        for (auto& rr : rrs) {
            os << rr.name << " " << rr.ttl << " "
               << (rr.rclass == 1 ? "IN" : "CLASS" + std::to_string(rr.rclass))
               << " " << typeToString(rr.type)
               << " " << rr.rdataToString() << "\n";
        }
    };

    printRRs(answers);
    printRRs(authorities);
    printRRs(additionals);

    return os.str();
}
