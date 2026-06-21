// SPDX-License-Identifier: MIT
//
#pragma once

#include <string>
#include <map>
#include <vector>
#include <cstdint>

class DomainMap {
public:
    void set(const std::string& domain, const std::string& value);
    bool getExact(const std::string& domain, std::string& value) const;
    bool getMostSpecific(const std::string& domain, std::string& value) const;
    bool empty() const { return map_.empty(); }

    static DomainMap fromString(const std::string& s);

private:
    std::map<std::string, std::string> map_;
};
