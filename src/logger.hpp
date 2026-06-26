// SPDX-License-Identifier: MIT
//
#pragma once

#include <string>
#include <iostream>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <mutex>

enum class LogLevel { Debug, Info, Warn, Error };

class Logger {
public:
    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    void setLevel(LogLevel l) { level_ = l; }
    void setJsonFormat(bool j) { jsonFormat_ = j; }
    LogLevel level() const { return level_; }
    bool jsonFormat() const { return jsonFormat_; }

    void log(LogLevel l, const std::string& msg) {
        if (l < level_) return;
        std::lock_guard<std::mutex> lock(mutex_);
        auto t = std::time(nullptr);
        auto tm = *std::localtime(&t);
        if (jsonFormat_) {
            std::string escaped;
            escaped.reserve(msg.size());
            for (char c : msg) {
                if (c == '"') escaped += "\\\"";
                else if (c == '\\') escaped += "\\\\";
                else if (c == '\n') escaped += "\\n";
                else escaped += c;
            }
            std::cerr << "{\"ts\":\"" << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S")
                      << "\",\"level\":\"" << levelName(l)
                      << "\",\"msg\":\"" << escaped << "\"}" << std::endl;
        } else {
            std::cerr << std::put_time(&tm, "%H:%M:%S") << " "
                      << levelName(l) << ": " << msg << std::endl;
        }
    }

    static std::string levelName(LogLevel l) {
        switch (l) {
            case LogLevel::Debug: return "DEBUG";
            case LogLevel::Info:  return "INFO";
            case LogLevel::Warn:  return "WARN";
            case LogLevel::Error: return "ERROR";
        }
        return "UNKNOWN";
    }

private:
    LogLevel level_ = LogLevel::Info;
    bool jsonFormat_ = false;
    std::mutex mutex_;
};

#define LOG_DEBUG(msg) Logger::instance().log(LogLevel::Debug, msg)
#define LOG_INFO(msg)  Logger::instance().log(LogLevel::Info, msg)
#define LOG_WARN(msg)  Logger::instance().log(LogLevel::Warn, msg)
#define LOG_ERROR(msg) Logger::instance().log(LogLevel::Error, msg)
