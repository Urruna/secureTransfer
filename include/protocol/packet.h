// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/protocol/packet.h
//
//  说明：统一数据包格式。Packet 整体放在第一阶段 Frame::payload 内部，
//        因此网络层（Network / Frame）一行都不用改。
//
//  线上格式（全部为网络字节序 / 大端）：
//
//      偏移  长度  字段
//       0     2    Magic        = 0x53 0x54 ("ST")
//       2     1    Version      = 0x01
//       3     1    Type         = MessageType
//       4     1    Direction    = 0x01 (C→S) / 0x02 (S→C)
//       5     8    SessionId
//      13     8    Sequence     uint64
//      21    16    Nonce
//      37     4    PayloadLen   uint32 = Body 字节数
//      41     N    Body
//      41+N  16    MacTag
//
//      包头 41 字节，总开销 41 + 16 = 57 字节。
//
//  要点：
//    * 数据包的 MAC 覆盖 [Version .. Body]，即 encode() 的全部输出；
//      Magic 与 MacTag 本身不参与（MacTag 是结果，Magic 只用于快速过滤）；
//    * PayloadLen 参与 MAC，因此攻击者无法截断或拼接 Body；
//    * Direction 参与 MAC，因此无法把对端发来的包原样反射回去。
// ============================================================================

#ifndef SECURETRANSFER_PROTOCOL_PACKET_H
#define SECURETRANSFER_PROTOCOL_PACKET_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "common/types.h"
#include "protocol/message_type.h"

struct Packet {
    static constexpr std::size_t kMagicSize = 2;
    static constexpr std::size_t kHeaderSize = 41;
    static constexpr std::size_t kMacSize = 16;
    static constexpr std::size_t kOverhead = kHeaderSize + kMacSize;  // 57

    /// Body 的最长长度，使整个 Packet 不超过 Frame::kMaxPayloadSize (1 MiB)。
    static constexpr std::size_t kMaxBodySize = 1024u * 1024u - kOverhead;

    /// 为避免与 Frame::kMaxPayloadSize 不一致，这里做一次编译期检查。
    static_assert(kMaxBodySize + kOverhead == 1024u * 1024u,
                  "Packet 开销与 Frame 上限不一致");

    static constexpr Byte kMagic0 = 0x53;  // 'S'
    static constexpr Byte kMagic1 = 0x54;  // 'T'
    static constexpr Byte kVersion = 0x01;

    Byte version = kVersion;
    MessageType type = MessageType::kError;
    Direction direction = Direction::kClientToServer;
    SessionId sessionId{};
    std::uint64_t sequence = 0;
    Nonce nonce{};
    Bytes body;
    MacTag mac{};

    /// 编码为 [Version .. Body]，这正是数据包 MAC 的输入。
    Bytes encode() const;

    /// 编码为完整线上字节 [Magic .. MacTag]。
    Bytes encodeWithMac() const;

    /// 线上总字节数。
    std::size_t wireSize() const;

    /// 字段自检（Body 长度不超过上限）。
    bool isValid() const;

    /// 解析完整线上字节；失败时返回 false 并给出原因（可选）。
    static bool decode(const Bytes& wire, Packet& out, std::string* error = nullptr);

    /// 便捷函数：按当前字段计算并填入 MacTag。
    void seal(const MacTag& tag);
};

#endif  // SECURETRANSFER_PROTOCOL_PACKET_H
