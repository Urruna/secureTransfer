// ============================================================================
//  SecureTransfer - 第三部分：应用层（文件 / 图像传输）
//  file: include/application/crc32.h
//
//  说明：自己实现的 CRC32（IEEE 802.3 多项式 0xEDB88320，反射算法）。
//
//  用途：**端到端一致性校验**——文件被切成很多块之后，
//        接收方用 CRC32 快速确认"拼回来的字节与原始文件一致"。
//
//  ⚠ 边界说明（报告里要写清楚，避免与 CMAC 混淆）：
//      * 密码学完整性（防篡改、防伪造）由**每包的 CMAC** 保证；
//      * CRC32 只是"非密码学"的差错检测，能发现传输/重组过程中的意外错误，
//        但**不能**抵抗刻意构造的碰撞，因此不能替代 CMAC。
// ============================================================================

#ifndef SECURETRANSFER_APPLICATION_CRC32_H
#define SECURETRANSFER_APPLICATION_CRC32_H

#include <array>
#include <cstddef>
#include <cstdint>

#include "common/types.h"

namespace {

/// 生成 256 项查表（首次调用时初始化一次）。
inline const std::array<std::uint32_t, 256>& crc32Table() {
    static const std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> out{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t value = i;
            for (int bit = 0; bit < 8; ++bit) {
                value = (value & 1u) ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
            }
            out[i] = value;
        }
        return out;
    }();
    return table;
}

}  // namespace

/// 流式 CRC32：可以分多次 update，最后用 value() 取结果。
class Crc32 {
public:
    void update(const Byte* data, std::size_t length) {
        const auto& table = crc32Table();
        for (std::size_t i = 0; i < length; ++i) {
            state_ = table[(state_ ^ data[i]) & 0xFFu] ^ (state_ >> 8);
        }
    }

    void update(const Bytes& data) {
        if (!data.empty()) {
            update(data.data(), data.size());
        }
    }

    std::uint32_t value() const {
        return state_ ^ 0xFFFFFFFFu;
    }

    void reset() {
        state_ = 0xFFFFFFFFu;
    }

    /// 便捷函数：一次性计算一段数据的 CRC32。
    static std::uint32_t compute(const Byte* data, std::size_t length) {
        Crc32 crc;
        crc.update(data, length);
        return crc.value();
    }

    static std::uint32_t compute(const Bytes& data) {
        return compute(data.data(), data.size());
    }

private:
    std::uint32_t state_ = 0xFFFFFFFFu;
};

#endif  // SECURETRANSFER_APPLICATION_CRC32_H
