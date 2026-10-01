// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/common/types.h
//
//  说明：全项目统一的类型别名。所有密钥与数据一律使用无符号字节
//        （uint8_t / Bytes），不使用 char*，避免中文与高位字节出错。
// ============================================================================

#ifndef SECURETRANSFER_COMMON_TYPES_H
#define SECURETRANSFER_COMMON_TYPES_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

using Byte = uint8_t;
using Bytes = std::vector<Byte>;

using Block128 = std::array<Byte, 16>;  // 一个 AES 分组
using Key128 = std::array<Byte, 16>;    // AES-128 密钥
using Nonce = std::array<Byte, 16>;     // CTR 初始计数器块
using MacTag = std::array<Byte, 16>;    // CMAC 输出

// 课程 project_q1.md 第 5 节建议的 Session ID 宽度为 8 字节，这里遵循课程要求。
using SessionId = std::array<Byte, 8>;

/// 数据包方向。参与 MAC 计算，用于防止反射攻击
/// （把对端发来的合法包原样发回去）。
enum class Direction : Byte {
    kClientToServer = 0x01,
    kServerToClient = 0x02
};

inline Direction opposite(Direction direction) {
    return direction == Direction::kClientToServer ? Direction::kServerToClient
                                                   : Direction::kClientToServer;
}

inline const char* directionToString(Direction direction) {
    return direction == Direction::kClientToServer ? "C2S" : "S2C";
}

/// Bytes -> Bytes（拷贝），便于统一调用点。
inline Bytes toBytes(const Bytes& data) {
    return data;
}

/// std::array<Byte, N> -> Bytes。
template <std::size_t N>
Bytes toBytes(const std::array<Byte, N>& data) {
    return Bytes(data.begin(), data.end());
}

/// 由 UTF-8 文本（或任意 C 字符串）构造 Bytes。
inline Bytes stringToBytes(const std::string& text) {
    return Bytes(text.begin(), text.end());
}

/// Bytes -> std::string（按字节原样转换，二进制数据不会被截断）。
inline std::string bytesToString(const Bytes& data) {
    return std::string(data.begin(), data.end());
}

/// std::array<Byte, N> -> std::string。
template <std::size_t N>
std::string arrayToString(const std::array<Byte, N>& data) {
    return std::string(data.begin(), data.end());
}

/// 把 Bytes 复制进固定长度的数组；长度不匹配时返回 false 且不修改 out。
template <std::size_t N>
bool copyToArray(const Bytes& from, std::array<Byte, N>& out) {
    if (from.size() != N) {
        return false;
    }
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = from[i];
    }
    return true;
}

inline bool isAllZero(const Bytes& data) {
    for (Byte b : data) {
        if (b != 0) {
            return false;
        }
    }
    return true;
}

inline bool isAllZero(const MacTag& tag) {
    for (Byte b : tag) {
        if (b != 0) {
            return false;
        }
    }
    return true;
}

#endif  // SECURETRANSFER_COMMON_TYPES_H
