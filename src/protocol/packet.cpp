// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: src/protocol/packet.cpp
// ============================================================================

#include "protocol/packet.h"

#include <cstring>

namespace {

void writeU32Big(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<Byte>((value >> 24) & 0xFF));
    out.push_back(static_cast<Byte>((value >> 16) & 0xFF));
    out.push_back(static_cast<Byte>((value >> 8) & 0xFF));
    out.push_back(static_cast<Byte>(value & 0xFF));
}

void writeU64Big(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<Byte>((value >> shift) & 0xFF));
    }
}

std::uint32_t readU32Big(const Byte* in) {
    return (static_cast<std::uint32_t>(in[0]) << 24) |
           (static_cast<std::uint32_t>(in[1]) << 16) |
           (static_cast<std::uint32_t>(in[2]) << 8) |
           static_cast<std::uint32_t>(in[3]);
}

std::uint64_t readU64Big(const Byte* in) {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | static_cast<std::uint64_t>(in[i]);
    }
    return value;
}

bool fail(std::string* error, const char* message) {
    if (error != nullptr) {
        *error = message;
    }
    return false;
}

}  // namespace

Bytes Packet::encode() const {
    Bytes out;
    out.reserve(kHeaderSize - kMagicSize + body.size());
    out.push_back(version);
    out.push_back(static_cast<Byte>(type));
    out.push_back(static_cast<Byte>(direction));
    out.insert(out.end(), sessionId.begin(), sessionId.end());
    writeU64Big(out, sequence);
    out.insert(out.end(), nonce.begin(), nonce.end());
    writeU32Big(out, static_cast<std::uint32_t>(body.size()));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

Bytes Packet::encodeWithMac() const {
    Bytes out;
    out.reserve(wireSize());
    out.push_back(kMagic0);
    out.push_back(kMagic1);
    const Bytes rest = encode();
    out.insert(out.end(), rest.begin(), rest.end());
    out.insert(out.end(), mac.begin(), mac.end());
    return out;
}

std::size_t Packet::wireSize() const {
    return kOverhead + body.size();
}

bool Packet::isValid() const {
    return body.size() <= kMaxBodySize;
}

void Packet::seal(const MacTag& tag) {
    mac = tag;
}

bool Packet::decode(const Bytes& wire, Packet& out, std::string* error) {
    if (wire.size() < kOverhead) {
        return fail(error, "数据包长度小于最小包头+MAC 长度");
    }
    if (wire[0] != kMagic0 || wire[1] != kMagic1) {
        return fail(error, "Magic 不匹配：不是本协议的数据包");
    }
    if (wire[2] != kVersion) {
        return fail(error, "协议版本不支持");
    }

    const std::uint32_t payloadLength = readU32Big(wire.data() + 37);
    if (payloadLength > kMaxBodySize) {
        return fail(error, "PayloadLen 超过允许的最大 Body 长度");
    }
    if (wire.size() != kHeaderSize + static_cast<std::size_t>(payloadLength) + kMacSize) {
        return fail(error, "PayloadLen 与数据包实际长度不一致");
    }

    Packet parsed;
    parsed.version = wire[2];
    parsed.type = static_cast<MessageType>(wire[3]);
    parsed.direction = static_cast<Direction>(wire[4]);
    std::memcpy(parsed.sessionId.data(), wire.data() + 5, parsed.sessionId.size());
    parsed.sequence = readU64Big(wire.data() + 13);
    std::memcpy(parsed.nonce.data(), wire.data() + 21, parsed.nonce.size());
    parsed.body.assign(wire.begin() + kHeaderSize,
                       wire.begin() + kHeaderSize + payloadLength);
    std::memcpy(parsed.mac.data(), wire.data() + kHeaderSize + payloadLength,
                parsed.mac.size());

    out = parsed;
    return true;
}
