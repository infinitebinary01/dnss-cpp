// SPDX-License-Identifier: MIT
//
#include "domain_map.hpp"
#include <sstream>
#include <algorithm>
#include <cctype>

static std::string canonicalize(const std::string& domain) {
    std::string d = domain;
    if (d.empty()) return ".";
    if (d.back() != '.') d.push_back('.');
    for (auto& c : d) c = std::tolower(static_cast<unsigned char>(c));
    return d;
}

void DomainMap::set(const std::string& domain, const std::string& value) {
    map_[canonicalize(domain)] = value;
}

bool DomainMap::getExact(const std::string& domain, std::string& value) const {
    auto it = map_.find(canonicalize(domain));
    if (it == map_.end()) return false;
    value = it->second;
    return true;
}

static size_t countLabels(const std::string& domain) {
    if (domain.empty()) return 0;
    size_t count = 0;
    for (char c : domain) {
        if (c == '.') ++count;
    }
    return count;
}

static bool isSubDomain(const std::string& sub, const std::string& domain) {
    // Check if 'sub' is a subdomain of 'domain' (or equal to it).
    // Both should be canonicalized (lowercase, ending in dot).
    if (sub == domain) return true;
    if (sub.size() <= domain.size()) return false;
    if (sub.compare(sub.size() - domain.size(), domain.size(), domain) != 0)
        return false;
    return sub[sub.size() - domain.size() - 1] == '.';
}

bool DomainMap::getMostSpecific(const std::string& domain, std::string& value) const {
    std::string d = canonicalize(domain);
    size_t bestCount = 0;
    bool found = false;
    std::string bestVal;

    for (const auto& [key, val] : map_) {
        if (!isSubDomain(d, key)) continue;
        size_t c = countLabels(key);
        if (c > bestCount) {
            bestCount = c;
            bestVal = val;
            found = true;
        }
    }

    if (found) value = bestVal;
    return found;
}

DomainMap DomainMap::fromString(const std::string& s) {
    DomainMap m;
    std::istringstream ss(s);
    std::string pair;
    while (std::getline(ss, pair, ',')) {
        // Trim whitespace
        auto trim = [](std::string& str) {
            size_t start = 0;
            while (start < str.size() && std::isspace(str[start])) ++start;
            size_t end = str.size();
            while (end > start && std::isspace(str[end - 1])) --end;
            str = str.substr(start, end - start);
        };
        trim(pair);
        if (pair.empty()) continue;

        auto colon = pair.find(':');
        if (colon == std::string::npos || colon == 0) {
            // no domain or no value - skip invalid entries silently
            continue;
        }
        std::string domain = pair.substr(0, colon);
        trim(domain);
        std::string addr = pair.substr(colon + 1);
        trim(addr);
        m.set(domain, addr);
    }
    return m;
}
