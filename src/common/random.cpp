// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: src/common/random.cpp
// ============================================================================

#include "common/random.h"

#include <fcntl.h>
#include <unistd.h>

#include <random>

#include "common/log.h"

namespace {

const char* const kLogModule = "Random";

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
    device_ = ::open("/dev/urandom", O_RDONLY);
    if (device_ < 0) {
        ST_LOG_WARN(kLogModule,
                    "无法打开 /dev/urandom，回退到 std::random_device（安全性较弱）");
    }
}

SystemRandom::~SystemRandom() {
    if (device_ >= 0) {
        ::close(device_);
        device_ = -1;
    }
}

bool SystemRandom::openedDevice() const {
    return device_ >= 0;
}

void SystemRandom::fill(Byte* out, std::size_t length) {
    if (length == 0) {
        return;
    }

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
