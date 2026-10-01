// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: src/common/random.cpp
// ============================================================================

#include "common/random.h"

#if defined(_WIN32)
// Windows 没有 /dev/urandom，改用系统 CSPRNG：BCryptGenRandom。
// 注意：bcrypt.h 依赖 windows.h 里的 LONG / ULONG / PUCHAR 等类型，必须先包含它。
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601  // Windows 7 及以上：提供 BCryptGenRandom
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include <random>

#include "common/log.h"

namespace {

const char* const kLogModule = "Random";

#if defined(_WIN32)

/// 用系统首选的 CSPRNG 填满 out[0..length)。返回是否成功。
bool fillFromSystemRng(Byte* out, std::size_t length) {
    const NTSTATUS status =
        ::BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(out), static_cast<ULONG>(length),
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status >= 0;  // NTSTATUS >= 0 表示成功
}

#endif  // _WIN32

}  // namespace

Bytes RandomSource::bytes(std::size_t length) {
    Bytes out(length);
    if (length > 0) {
        fill(out.data(), length);
    }
    return out;
}

RandomSource& RandomSource::system() {
    static SystemRandom instance;
    return instance;
}

SystemRandom::SystemRandom() {
#if !defined(_WIN32)
    device_ = ::open("/dev/urandom", O_RDONLY);
    if (device_ < 0) {
        ST_LOG_WARN(kLogModule,
                    "无法打开 /dev/urandom，回退到 std::random_device（安全性较弱）");
    }
#endif
}

SystemRandom::~SystemRandom() {
#if !defined(_WIN32)
    if (device_ >= 0) {
        ::close(device_);
        device_ = -1;
    }
#endif
}

bool SystemRandom::openedDevice() const {
#if defined(_WIN32)
    return true;  // BCryptGenRandom 随系统提供，无需打开设备
#else
    return device_ >= 0;
#endif
}

void SystemRandom::fill(Byte* out, std::size_t length) {
    if (length == 0) {
        return;
    }

#if defined(_WIN32)
    if (fillFromSystemRng(out, length)) {
        return;
    }
    ST_LOG_WARN(kLogModule, "BCryptGenRandom 失败，回退到 std::random_device（安全性较弱）");
#else
    if (device_ >= 0) {
        std::size_t offset = 0;
        while (offset < length) {
            const ssize_t got = ::read(device_, out + offset, length - offset);
            if (got > 0) {
                offset += static_cast<std::size_t>(got);
                continue;
            }
            if (got < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
        if (offset == length) {
            return;
        }
        ST_LOG_WARN(kLogModule, "从 /dev/urandom 读取随机数不完整，回退到 std::random_device");
    }
#endif

    static std::random_device fallback;
    for (std::size_t i = 0; i < length; ++i) {
        out[i] = static_cast<Byte>(fallback() & 0xFF);
    }
}

FixedRandom::FixedRandom(Byte seed) : state_(seed) {}

void FixedRandom::fill(Byte* out, std::size_t length) {
    for (std::size_t i = 0; i < length; ++i) {
        // 线性同余，仅为可复现，不是密码学随机数。
        state_ = static_cast<Byte>(state_ * 37u + 11u);
        out[i] = state_;
    }
}
