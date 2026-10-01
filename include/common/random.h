// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/common/random.h
//
//  说明：随机数来源抽象。
//        * SystemRandom ：正式运行使用（/dev/urandom），用于 Nonce / SessionId；
//        * FixedRandom  ：测试使用，输出可复现，便于做"已知值测试(KAT)"。
//        协议层只依赖 RandomSource 接口，因此测试时可以完全确定化。
// ============================================================================

#ifndef SECURETRANSFER_COMMON_RANDOM_H
#define SECURETRANSFER_COMMON_RANDOM_H

#include <array>
#include <cstddef>
#include <cstdint>

#include "common/types.h"

class RandomSource {
public:
    virtual ~RandomSource() = default;

    /// 用随机字节填满 out[0..length)。
    virtual void fill(Byte* out, std::size_t length) = 0;

    Bytes bytes(std::size_t length);

    template <std::size_t N>
    std::array<Byte, N> array() {
        std::array<Byte, N> out{};
        if (N > 0) {
            fill(out.data(), N);
        }
        return out;
    }

    /// 进程级系统随机源（单例）。
    static RandomSource& system();
};

/// 来自操作系统的随机源：优先 /dev/urandom，失败时退回 std::random_device。
class SystemRandom : public RandomSource {
public:
    SystemRandom();
    ~SystemRandom() override;

    SystemRandom(const SystemRandom&) = delete;
    SystemRandom& operator=(const SystemRandom&) = delete;

    void fill(Byte* out, std::size_t length) override;
    bool openedDevice() const;

private:
    int device_ = -1;
};

/// 测试用确定随机源：同一个种子得到同一串字节。
class FixedRandom : public RandomSource {
public:
    explicit FixedRandom(Byte seed = 0x5A);

    void fill(Byte* out, std::size_t length) override;

private:
    Byte state_;
};

#endif  // SECURETRANSFER_COMMON_RANDOM_H
