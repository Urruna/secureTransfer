// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/common/hex.h
//
//  说明：十六进制转换，供配置文件解析、日志与测试使用。
//        注意：只用于显示密钥的"指纹"或短摘要，不要把完整密钥写进日志。
// ============================================================================

#ifndef SECURETRANSFER_COMMON_HEX_H
#define SECURETRANSFER_COMMON_HEX_H

#include <string>

#include "common/types.h"

inline std::string toHex(const Byte* data, std::size_t length) {
    static const char* const kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(length * 2);
    for (std::size_t i = 0; i < length; ++i) {
        out.push_back(kDigits[(data[i] >> 4) & 0x0F]);
        out.push_back(kDigits[data[i] & 0x0F]);
    }
    return out;
}

inline std::string toHex(const Bytes& data) {
    return toHex(data.data(), data.size());
}

template <std::size_t N>
std::string toHex(const std::array<Byte, N>& data) {
    return toHex(data.data(), N);
}

inline int hexDigitValue(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/// 解析十六进制字符串；允许中间出现空格、冒号或短横线。
/// 长度为奇数或含非法字符时返回 false。
inline bool fromHex(const std::string& text, Bytes& out) {
    Bytes result;
    int high = -1;
    for (char c : text) {
        if (c == ' ' || c == ':' || c == '-' || c == '\t' || c == '\r' || c == '\n') {
            continue;
        }
        const int value = hexDigitValue(c);
        if (value < 0) {
            return false;
        }
        if (high < 0) {
            high = value;
        } else {
            result.push_back(static_cast<Byte>((high << 4) | value));
            high = -1;
        }
    }
    if (high >= 0) {
        return false;
    }
    out = result;
    return true;
}

template <std::size_t N>
bool fromHex(const std::string& text, std::array<Byte, N>& out) {
    Bytes parsed;
    if (!fromHex(text, parsed)) {
        return false;
    }
    return copyToArray(parsed, out);
}

#endif  // SECURETRANSFER_COMMON_HEX_H
