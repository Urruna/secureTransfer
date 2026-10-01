// ============================================================================
//  SecureTransfer - 第一阶段：基础 TCP 通信
//  file: include/common/log.h
//
//  说明：极简日志模块（header-only），供网络层、应用层以及后续的
//        AES / CMAC / 安全协议模块共用。
//
//  输出格式：
//        [INFO] [Bob] TCP server listening on 0.0.0.0:9000
//        [WARN] [Network] recv() 超时
//        [ERROR] [Network] Failed to connect to 127.0.0.1:9000
//
//  安全提示：日志中禁止输出 K_master、会话密钥等敏感数据。
//  如果以后确实需要打印密钥，必须放在 DEBUG 级别并且默认关闭。
// ============================================================================

#ifndef SECURETRANSFER_COMMON_LOG_H
#define SECURETRANSFER_COMMON_LOG_H

#include <cstdlib>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

// Windows 的 <windows.h> 会把 ERROR 定义成数值宏，与我们下面的 stlog::Level::ERROR 冲突；
// 这里先取消该宏（本工程不需要 Win32 的 ERROR 常量）。
#ifdef ERROR
#undef ERROR
#endif

namespace stlog {

/// 日志级别，数值越大越严重。
enum class Level {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3
};

/// 进程内全局最低日志级别，默认 INFO。
/// 使用函数内静态变量，避免头文件中出现全局可变对象。
inline Level& minLevelRef() {
    static Level level = Level::INFO;
    return level;
}

inline void setMinLevel(Level level) {
    minLevelRef() = level;
}

inline Level minLevel() {
    return minLevelRef();
}

/// 通过字符串设置日志级别，可用于命令行参数或环境变量。
inline bool setMinLevelByName(const std::string& name) {
    if (name == "DEBUG" || name == "debug") {
        setMinLevel(Level::DEBUG);
        return true;
    }
    if (name == "INFO" || name == "info") {
        setMinLevel(Level::INFO);
        return true;
    }
    if (name == "WARN" || name == "warn") {
        setMinLevel(Level::WARN);
        return true;
    }
    if (name == "ERROR" || name == "error") {
        setMinLevel(Level::ERROR);
        return true;
    }
    return false;
}

/// 读取环境变量 ST_LOG_LEVEL（可选：DEBUG / INFO / WARN / ERROR）。
inline void initFromEnvironment() {
    const char* value = std::getenv("ST_LOG_LEVEL");
    if (value != nullptr) {
        setMinLevelByName(std::string(value));
    }
}

inline const char* levelName(Level level) {
    switch (level) {
        case Level::DEBUG:
            return "DEBUG";
        case Level::INFO:
            return "INFO";
        case Level::WARN:
            return "WARN";
        case Level::ERROR:
            return "ERROR";
    }
    return "UNKNOWN";
}

inline std::mutex& logMutex() {
    static std::mutex mutex;
    return mutex;
}

/// 输出一条日志。多线程环境下每次输出都会加锁，避免日志交错。
inline void write(Level level, const std::string& module, const std::string& message) {
    if (static_cast<int>(level) < static_cast<int>(minLevel())) {
        return;
    }
    const std::lock_guard<std::mutex> lock(logMutex());
    std::cout << '[' << levelName(level) << "] [" << module << "] " << message << std::endl;
}

}  // namespace stlog

// 直接传入已经拼好的 std::string
#define ST_LOG_DEBUG(module, message) ::stlog::write(::stlog::Level::DEBUG, (module), (message))
#define ST_LOG_INFO(module, message) ::stlog::write(::stlog::Level::INFO, (module), (message))
#define ST_LOG_WARN(module, message) ::stlog::write(::stlog::Level::WARN, (module), (message))
#define ST_LOG_ERROR(module, message) ::stlog::write(::stlog::Level::ERROR, (module), (message))

// 用流式写法拼消息，例如：ST_LOG_INFO_STREAM("Bob", "port=" << port);
#define ST_LOG_DEBUG_STREAM(module, expression)          \
    do {                                                 \
        std::ostringstream st_log_oss;                   \
        st_log_oss << expression;                        \
        ::stlog::write(::stlog::Level::DEBUG, (module), st_log_oss.str()); \
    } while (false)

#define ST_LOG_INFO_STREAM(module, expression)           \
    do {                                                 \
        std::ostringstream st_log_oss;                   \
        st_log_oss << expression;                        \
        ::stlog::write(::stlog::Level::INFO, (module), st_log_oss.str()); \
    } while (false)

#define ST_LOG_WARN_STREAM(module, expression)           \
    do {                                                 \
        std::ostringstream st_log_oss;                   \
        st_log_oss << expression;                        \
        ::stlog::write(::stlog::Level::WARN, (module), st_log_oss.str()); \
    } while (false)

#define ST_LOG_ERROR_STREAM(module, expression)          \
    do {                                                 \
        std::ostringstream st_log_oss;                   \
        st_log_oss << expression;                        \
        ::stlog::write(::stlog::Level::ERROR, (module), st_log_oss.str()); \
    } while (false)

#endif  // SECURETRANSFER_COMMON_LOG_H
