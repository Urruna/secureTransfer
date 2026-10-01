// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/common/byte_buffer.h
//
//  说明：字节读写与 TLV 编解码（header-only）。
//        协议里的多字节整数一律使用网络字节序（大端）。
//        TLV = 2 字节大端长度 + 内容，用于握手消息与转录串，
//        避免"不同字段拼接后字节相同"的歧义。
// ============================================================================

#ifndef SECURETRANSFER_COMMON_BYTE_BUFFER_H
#define SECURETRANSFER_COMMON_BYTE_BUFFER_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "common/types.h"

class ByteWriter {
public:
    void u8(Byte value) {
        buffer_.push_back(value);
    }

    void u16(std::uint16_t value) {
        buffer_.push_back(static_cast<Byte>((value >> 8) & 0xFF));
        buffer_.push_back(static_cast<Byte>(value & 0xFF));
    }

    void u32(std::uint32_t value) {
        for (int shift = 24; shift >= 0; shift -= 8) {
            buffer_.push_back(static_cast<Byte>((value >> shift) & 0xFF));
        }
    }

    void u64(std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            buffer_.push_back(static_cast<Byte>((value >> shift) & 0xFF));
        }
    }

    void raw(const Byte* data, std::size_t length) {
        buffer_.insert(buffer_.end(), data, data + length);
    }

    void raw(const Bytes& data) {
        buffer_.insert(buffer_.end(), data.begin(), data.end());
    }

    void tlv(const Bytes& data) {
        u16(static_cast<std::uint16_t>(data.size()));
        raw(data);
    }

    void tlv(const std::string& text) {
        tlv(stringToBytes(text));
    }

    const Bytes& bytes() const {
        return buffer_;
    }

    Bytes take() {
        return std::move(buffer_);
    }

    std::size_t size() const {
        return buffer_.size();
    }

private:
    Bytes buffer_;
};

/// 只读解析器。任何一步失败都会把内部状态标记为失败，
/// 之后所有读取都直接返回 false，调用点只需在最后统一检查。
class ByteReader {
public:
    explicit ByteReader(const Bytes& data) : data_(data) {}

    bool u8(Byte& value) {
        if (!ensure(1)) {
            return false;
        }
        value = data_[offset_++];
        return true;
    }

    bool u16(std::uint16_t& value) {
        if (!ensure(2)) {
            return false;
        }
        value = static_cast<std::uint16_t>((data_[offset_] << 8) | data_[offset_ + 1]);
        offset_ += 2;
        return true;
    }

    bool u32(std::uint32_t& value) {
        if (!ensure(4)) {
            return false;
        }
        value = 0;
        for (int i = 0; i < 4; ++i) {
            value = (value << 8) | static_cast<std::uint32_t>(data_[offset_ + i]);
        }
        offset_ += 4;
        return true;
    }

    bool u64(std::uint64_t& value) {
        if (!ensure(8)) {
            return false;
        }
        value = 0;
        for (int i = 0; i < 8; ++i) {
            value = (value << 8) | static_cast<std::uint64_t>(data_[offset_ + i]);
        }
        offset_ += 8;
        return true;
    }

    bool raw(std::size_t length, Bytes& out) {
        if (!ensure(length)) {
            return false;
        }
        out.assign(data_.begin() + static_cast<std::ptrdiff_t>(offset_),
                   data_.begin() + static_cast<std::ptrdiff_t>(offset_ + length));
        offset_ += length;
        return true;
    }

    bool tlv(Bytes& out) {
        std::uint16_t length = 0;
        if (!u16(length)) {
            return false;
        }
        return raw(length, out);
    }

    bool tlv(std::string& out) {
        Bytes rawBytes;
        if (!tlv(rawBytes)) {
            return false;
        }
        out = bytesToString(rawBytes);
        return true;
    }

    std::size_t remaining() const {
        return data_.size() - offset_;
    }

    std::size_t position() const {
        return offset_;
    }

    bool empty() const {
        return remaining() == 0;
    }

private:
    bool ensure(std::size_t length) const {
        return offset_ + length <= data_.size();
    }

    const Bytes& data_;
    std::size_t offset_ = 0;
};

#endif  // SECURETRANSFER_COMMON_BYTE_BUFFER_H
