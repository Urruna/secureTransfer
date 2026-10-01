// ============================================================================
//  SecureTransfer - 第一阶段：基础 TCP 通信
//  file: src/network/frame.cpp
//  说明：Frame 的序列化 / 反序列化实现。字节序固定为大端（网络字节序）。
// ============================================================================

#include "network/frame.h"

#include <cstring>

#include "common/log.h"

namespace {

/// 模块名（日志用）。
const char* const kLogModule = "Frame";

}  // namespace

Frame::Frame() : length(0), payload() {}

Frame::Frame(const std::vector<uint8_t>& data)
    : length(static_cast<uint32_t>(data.size())), payload(data) {}

Frame::Frame(uint32_t len, const std::vector<uint8_t>& data)
    : length(len), payload(data) {}

Frame Frame::fromString(const std::string& text) {
    Frame frame;
    frame.setPayload(text);
    return frame;
}

Frame Frame::fromBytes(const std::vector<uint8_t>& data) {
    return Frame(data);
}

void Frame::setPayload(const std::vector<uint8_t>& data) {
    payload = data;
    length = static_cast<uint32_t>(payload.size());
}

void Frame::setPayload(const std::string& text) {
    payload.assign(reinterpret_cast<const uint8_t*>(text.data()),
                   reinterpret_cast<const uint8_t*>(text.data()) + text.size());
    length = static_cast<uint32_t>(payload.size());
}

std::string Frame::toString() const {
    return std::string(payload.begin(), payload.end());
}

bool Frame::isEmpty() const {
    return payload.empty();
}

bool Frame::isValid() const {
    return static_cast<std::size_t>(length) == payload.size() &&
           isPayloadLengthValid(length);
}

std::size_t Frame::wireSize() const {
    return kLengthFieldSize + payload.size();
}

void Frame::encodeLength(uint32_t value, uint8_t* out4Bytes) {
    out4Bytes[0] = static_cast<uint8_t>((value >> 24) & 0xFFu);
    out4Bytes[1] = static_cast<uint8_t>((value >> 16) & 0xFFu);
    out4Bytes[2] = static_cast<uint8_t>((value >> 8) & 0xFFu);
    out4Bytes[3] = static_cast<uint8_t>(value & 0xFFu);
}

uint32_t Frame::decodeLength(const uint8_t* in4Bytes) {
    return (static_cast<uint32_t>(in4Bytes[0]) << 24) |
           (static_cast<uint32_t>(in4Bytes[1]) << 16) |
           (static_cast<uint32_t>(in4Bytes[2]) << 8) |
           static_cast<uint32_t>(in4Bytes[3]);
}

bool Frame::isPayloadLengthValid(uint32_t value) {
    return static_cast<std::size_t>(value) <= kMaxPayloadSize;
}

const char* Frame::statusToString(Status status) {
    switch (status) {
        case Status::OK:
            return "OK";
        case Status::INCOMPLETE:
            return "INCOMPLETE";
        case Status::LENGTH_TOO_LARGE:
            return "LENGTH_TOO_LARGE";
    }
    return "UNKNOWN";
}

std::vector<uint8_t> Frame::serialize() const {
    if (!isValid()) {
        ST_LOG_ERROR_STREAM(kLogModule,
                            "serialize() 失败：Frame 非法 (length=" << length
                            << ", payload.size()=" << payload.size()
                            << ", kMaxPayloadSize=" << kMaxPayloadSize << ")");
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> buffer(wireSize(), 0);
    encodeLength(length, buffer.data());
    if (!payload.empty()) {
        std::memcpy(buffer.data() + kLengthFieldSize, payload.data(), payload.size());
    }
    return buffer;
}

Frame::Status Frame::deserialize(const std::vector<uint8_t>& buffer,
                                 Frame& frame,
                                 std::size_t* consumed) {
    // 1) 先读取固定长度的 length 字段。
    if (buffer.size() < kLengthFieldSize) {
        return Status::INCOMPLETE;
    }

    const uint32_t declaredLength = decodeLength(buffer.data());

    // 2) 长度必须在允许范围内：避免恶意长度导致大块内存分配。
    if (!isPayloadLengthValid(declaredLength)) {
        ST_LOG_ERROR_STREAM(kLogModule,
                            "deserialize() 失败：length=" << declaredLength
                            << " 超过最大允许值 " << kMaxPayloadSize);
        return Status::LENGTH_TOO_LARGE;
    }

    // 3) payload 必须完整到达。
    const std::size_t totalSize =
        static_cast<std::size_t>(kLengthFieldSize) + static_cast<std::size_t>(declaredLength);
    if (buffer.size() < totalSize) {
        return Status::INCOMPLETE;
    }

    frame.length = declaredLength;
    frame.payload.assign(buffer.begin() + static_cast<std::ptrdiff_t>(kLengthFieldSize),
                         buffer.begin() + static_cast<std::ptrdiff_t>(totalSize));
    if (consumed != nullptr) {
        *consumed = totalSize;
    }
    return Status::OK;
}
