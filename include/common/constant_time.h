// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/common/constant_time.h
//
//  说明：常数时间比较。校验 MAC / 认证标签时不能用 memcmp 提前返回，
//        否则会把"第几个字节开始不同"的信息通过执行时间泄漏出去。
// ============================================================================

#ifndef SECURETRANSFER_COMMON_CONSTANT_TIME_H
#define SECURETRANSFER_COMMON_CONSTANT_TIME_H

#include <cstddef>

#include "common/types.h"

/// 比较两段等长数据，耗时只与长度有关，与内容无关。
inline bool constantTimeEquals(const Byte* left, const Byte* right, std::size_t length) {
    Byte difference = 0;
    for (std::size_t i = 0; i < length; ++i) {
        difference = static_cast<Byte>(difference | static_cast<Byte>(left[i] ^ right[i]));
    }
    return difference == 0;
}

inline bool constantTimeEquals(const MacTag& left, const MacTag& right) {
    return constantTimeEquals(left.data(), right.data(), left.size());
}

#endif  // SECURETRANSFER_COMMON_CONSTANT_TIME_H
