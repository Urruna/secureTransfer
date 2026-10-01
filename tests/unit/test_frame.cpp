// ============================================================================
//  SecureTransfer 测试
//  file: tests/unit/test_frame.cpp
//  说明：Frame 的序列化 / 反序列化测试，包括正常数据与各种非法输入。
// ============================================================================

#include "test_util.h"

#include <cstdint>
#include <string>
#include <vector>

#include "network/frame.h"

namespace {

using Bytes = std::vector<uint8_t>;

Bytes makeBytes(std::size_t size, uint8_t seed) {
    Bytes data(size);
    for (std::size_t index = 0; index < size; ++index) {
        data[index] = static_cast<uint8_t>((index * 31u + seed) & 0xFFu);
    }
    return data;
}

}  // namespace

ST_TEST_CASE("Frame: 普通文本序列化后可以完整还原") {
    const Frame frame = Frame::fromString("Hello Bob");

    ST_CHECK_EQ(frame.length, static_cast<uint32_t>(9));
    ST_CHECK(frame.isValid());
    ST_CHECK(!frame.isEmpty());
    ST_CHECK_EQ(frame.wireSize(), static_cast<std::size_t>(4 + 9));

    const Bytes wire = frame.serialize();
    ST_CHECK_EQ(wire.size(), frame.wireSize());
    ST_CHECK_EQ(wire[0], static_cast<uint8_t>(0x00));
    ST_CHECK_EQ(wire[1], static_cast<uint8_t>(0x00));
    ST_CHECK_EQ(wire[2], static_cast<uint8_t>(0x00));
    ST_CHECK_EQ(wire[3], static_cast<uint8_t>(0x09));
    ST_CHECK_EQ(wire[4], static_cast<uint8_t>('H'));

    Frame parsed;
    std::size_t consumed = 0;
    ST_CHECK(Frame::deserialize(wire, parsed, &consumed) == Frame::Status::OK);
    ST_CHECK_EQ(consumed, wire.size());
    ST_CHECK_EQ(parsed.length, frame.length);
    ST_CHECK_EQ(parsed.toString(), std::string("Hello Bob"));
    ST_CHECK(parsed.isValid());
}

ST_TEST_CASE("Frame: length 字段使用大端序") {
    // payload 长度 258 = 0x00000102
    const Frame frame = Frame::fromBytes(makeBytes(258, 1));
    const Bytes wire = frame.serialize();

    ST_CHECK_EQ(wire[0], static_cast<uint8_t>(0x00));
    ST_CHECK_EQ(wire[1], static_cast<uint8_t>(0x00));
    ST_CHECK_EQ(wire[2], static_cast<uint8_t>(0x01));
    ST_CHECK_EQ(wire[3], static_cast<uint8_t>(0x02));
    ST_CHECK_EQ(Frame::decodeLength(wire.data()), static_cast<uint32_t>(258));
}

ST_TEST_CASE("Frame: 空 payload 也可以正常收发") {
    const Frame frame;  // length = 0, payload 为空
    ST_CHECK(frame.isValid());
    ST_CHECK(frame.isEmpty());
    ST_CHECK_EQ(frame.length, static_cast<uint32_t>(0));
    ST_CHECK_EQ(frame.wireSize(), Frame::kLengthFieldSize);

    const Bytes wire = frame.serialize();
    ST_CHECK_EQ(wire.size(), Frame::kLengthFieldSize);

    Frame parsed;
    ST_CHECK(Frame::deserialize(wire, parsed) == Frame::Status::OK);
    ST_CHECK(parsed.isEmpty());
    ST_CHECK(parsed.isValid());
    ST_CHECK_EQ(parsed.toString(), std::string());
}

ST_TEST_CASE("Frame: 最大允许的 payload（1 MB）可以正常处理") {
    const Bytes data = makeBytes(Frame::kMaxPayloadSize, 7);
    const Frame frame = Frame::fromBytes(data);

    ST_CHECK(frame.isValid());
    ST_CHECK_EQ(frame.length, static_cast<uint32_t>(Frame::kMaxPayloadSize));

    const Bytes wire = frame.serialize();
    ST_CHECK_EQ(wire.size(), Frame::kMaxPayloadSize + Frame::kLengthFieldSize);

    Frame parsed;
    ST_CHECK(Frame::deserialize(wire, parsed) == Frame::Status::OK);
    ST_CHECK_EQ(parsed.payload.size(), Frame::kMaxPayloadSize);
    ST_CHECK(parsed.payload == data);
}

ST_TEST_CASE("Frame: 超过 1 MB 的 payload 被认为是非法的") {
    const Bytes data = makeBytes(Frame::kMaxPayloadSize + 1, 3);
    const Frame frame = Frame::fromBytes(data);

    ST_CHECK(!frame.isValid());
    ST_CHECK(!Frame::isPayloadLengthValid(static_cast<uint32_t>(data.size())));
    // 非法 Frame 不应被序列化出去
    ST_CHECK(frame.serialize().empty());
}

ST_TEST_CASE("Frame: length 与 payload 不一致时视为非法") {
    const Frame frame(5, makeBytes(3, 9));  // 声称 5 字节，实际 3 字节

    ST_CHECK(!frame.isValid());
    ST_CHECK(frame.serialize().empty());
}

ST_TEST_CASE("Frame: 反序列化时数据不完整返回 INCOMPLETE") {
    // 1) 连 length 字段都不够
    const Bytes empty;
    Frame parsed;
    ST_CHECK(Frame::deserialize(empty, parsed) == Frame::Status::INCOMPLETE);

    const Bytes threeBytes{0x00, 0x00, 0x00};
    ST_CHECK(Frame::deserialize(threeBytes, parsed) == Frame::Status::INCOMPLETE);

    // 2) length 说 100 字节，但只给了 10 字节
    Bytes partial = {0x00, 0x00, 0x00, 0x64};
    const Bytes body = makeBytes(10, 5);
    partial.insert(partial.end(), body.begin(), body.end());
    ST_CHECK(Frame::deserialize(partial, parsed) == Frame::Status::INCOMPLETE);
}

ST_TEST_CASE("Frame: 反序列化时长度超过 1 MB 返回 LENGTH_TOO_LARGE") {
    const Bytes malicious = {0x7F, 0xFF, 0xFF, 0xFF};  // 约 2 GB
    Frame parsed;

    ST_CHECK(Frame::deserialize(malicious, parsed) == Frame::Status::LENGTH_TOO_LARGE);

    // 边界：正好 1 MB 仍然合法
    Bytes boundary = {0x00, 0x10, 0x00, 0x00};  // 1 MB = 1048576 = 0x00100000
    ST_CHECK(Frame::decodeLength(boundary.data()) == static_cast<uint32_t>(Frame::kMaxPayloadSize));
    ST_CHECK(Frame::isPayloadLengthValid(Frame::decodeLength(boundary.data())));

    // 边界 + 1 非法
    const Bytes tooLarge = {0x00, 0x10, 0x00, 0x01};
    ST_CHECK(!Frame::isPayloadLengthValid(Frame::decodeLength(tooLarge.data())));
}

ST_TEST_CASE("Frame: 一个缓冲区里可以连续解析出多个 Frame") {
    const Frame first = Frame::fromString("first");
    const Frame second = Frame::fromString("second message");

    Bytes stream = first.serialize();
    const Bytes secondWire = second.serialize();
    stream.insert(stream.end(), secondWire.begin(), secondWire.end());

    Frame parsedFirst;
    std::size_t consumed = 0;
    ST_CHECK(Frame::deserialize(stream, parsedFirst, &consumed) == Frame::Status::OK);
    ST_CHECK_EQ(parsedFirst.toString(), std::string("first"));
    ST_CHECK_EQ(consumed, first.wireSize());

    const Bytes rest(stream.begin() + static_cast<std::ptrdiff_t>(consumed), stream.end());
    Frame parsedSecond;
    ST_CHECK(Frame::deserialize(rest, parsedSecond, &consumed) == Frame::Status::OK);
    ST_CHECK_EQ(parsedSecond.toString(), std::string("second message"));
    ST_CHECK_EQ(consumed, second.wireSize());
}

ST_TEST_CASE("Frame: 含 0x00 的二进制数据不会被截断") {
    const Bytes binary = {0x00, 0x01, 0x00, 0xFF, 0x00};
    const Frame frame = Frame::fromBytes(binary);
    const Bytes wire = frame.serialize();

    Frame parsed;
    ST_CHECK(Frame::deserialize(wire, parsed) == Frame::Status::OK);
    ST_CHECK(parsed.payload == binary);
    ST_CHECK_EQ(parsed.payload.size(), static_cast<std::size_t>(5));
}

ST_TEST_CASE("Frame: UTF-8 中文内容可以正确还原") {
    const std::string text = "你好，Bob，这是一次安全通信测试。";
    const Frame frame = Frame::fromString(text);
    const Bytes wire = frame.serialize();

    Frame parsed;
    ST_CHECK(Frame::deserialize(wire, parsed) == Frame::Status::OK);
    ST_CHECK_EQ(parsed.toString(), text);
    ST_CHECK_EQ(parsed.payload.size(), text.size());
}

ST_TEST_CASE("Frame: encodeLength / decodeLength 边界值") {
    uint8_t buffer[Frame::kLengthFieldSize] = {0};
    const uint32_t values[] = {0u, 1u, 255u, 256u, 65535u, 0x01020304u, 0xFFFFFFFFu};

    for (std::size_t index = 0; index < sizeof(values) / sizeof(values[0]); ++index) {
        Frame::encodeLength(values[index], buffer);
        ST_CHECK_EQ(Frame::decodeLength(buffer), values[index]);
    }

    // 0xFFFFFFFF 明显超过 1 MB，应当被判为非法长度
    Frame::encodeLength(0xFFFFFFFFu, buffer);
    ST_CHECK(!Frame::isPayloadLengthValid(Frame::decodeLength(buffer)));
}

int main() {
    return ::testutil::runAll("frame");
}
