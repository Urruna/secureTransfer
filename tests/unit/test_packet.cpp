// ============================================================================
//  SecureTransfer 测试
//  file: tests/unit/test_packet.cpp
//
//  说明：统一数据包格式（Packet）的编解码、边界与非法输入测试。
// ============================================================================

#include "test_util.h"

#include <string>

#include "common/hex.h"
#include "protocol/packet.h"

namespace {

Packet makePacket(const Bytes& body) {
    Packet packet;
    packet.type = MessageType::kData;
    packet.direction = Direction::kClientToServer;
    packet.sessionId = SessionId{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    packet.sequence = 0x0102030405060708ULL;
    packet.nonce = Nonce{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                         0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
    packet.body = body;
    packet.mac = MacTag{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
                        0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF};
    return packet;
}

}  // namespace

// 1. 普通 Body 的编解码往返
ST_TEST_CASE("packet: 编解码往返") {
    const Bytes body = {'H', 'e', 'l', 'l', 'o'};
    const Packet original = makePacket(body);
    const Bytes wire = original.encodeWithMac();
    ST_CHECK_EQ(wire.size(), Packet::kOverhead + body.size());

    Packet decoded;
    std::string error;
    ST_CHECK(Packet::decode(wire, decoded, &error));
    ST_CHECK(decoded.type == MessageType::kData);
    ST_CHECK(decoded.direction == Direction::kClientToServer);
    ST_CHECK(decoded.sessionId == original.sessionId);
    ST_CHECK_EQ(decoded.sequence, original.sequence);
    ST_CHECK(decoded.nonce == original.nonce);
    ST_CHECK(decoded.body == body);
    ST_CHECK(decoded.mac == original.mac);
}

// 2. 空 Body 合法
ST_TEST_CASE("packet: 空 Body 合法") {
    const Packet original = makePacket(Bytes{});
    const Bytes wire = original.encodeWithMac();
    ST_CHECK_EQ(wire.size(), Packet::kOverhead);

    Packet decoded;
    ST_CHECK(Packet::decode(wire, decoded));
    ST_CHECK(decoded.body.empty());
}

// 3. 最大 Body 边界
ST_TEST_CASE("packet: 最大 Body 边界") {
    Bytes body(Packet::kMaxBodySize, 0x5A);
    const Packet original = makePacket(body);
    ST_CHECK(original.isValid());
    const Bytes wire = original.encodeWithMac();
    ST_CHECK_EQ(wire.size(), 1024u * 1024u);

    Packet decoded;
    ST_CHECK(Packet::decode(wire, decoded));
    ST_CHECK_EQ(decoded.body.size(), body.size());
    ST_CHECK(decoded.body == body);
}

// 4. 超过最大 Body 直接判为非法
ST_TEST_CASE("packet: Body 超过上限判非法") {
    const Packet tooLarge = makePacket(Bytes(Packet::kMaxBodySize + 1, 0x01));
    ST_CHECK(!tooLarge.isValid());
}

// 5. 字节序：Magic / Version / Direction / Sequence 都在约定位置，且为大端
ST_TEST_CASE("packet: 字段位置与大端序") {
    const Packet packet = makePacket(Bytes{0x01});
    const Bytes wire = packet.encodeWithMac();
    ST_CHECK_EQ(static_cast<int>(wire[0]), 0x53);  // 'S'
    ST_CHECK_EQ(static_cast<int>(wire[1]), 0x54);  // 'T'
    ST_CHECK_EQ(static_cast<int>(wire[2]), 0x01);  // Version
    ST_CHECK_EQ(static_cast<int>(wire[3]), 0x08);  // Type = DATA
    ST_CHECK_EQ(static_cast<int>(wire[4]), 0x01);  // Direction = C2S
    // SessionId 位于偏移 5，8 字节
    ST_CHECK_EQ(static_cast<int>(wire[5]), 0x11);
    ST_CHECK_EQ(static_cast<int>(wire[12]), 0x88);
    // Sequence 位于偏移 13，大端
    ST_CHECK_EQ(static_cast<int>(wire[13]), 0x01);
    ST_CHECK_EQ(static_cast<int>(wire[14]), 0x02);
    ST_CHECK_EQ(static_cast<int>(wire[19]), 0x07);
    ST_CHECK_EQ(static_cast<int>(wire[20]), 0x08);
    // Nonce 位于偏移 21，16 字节
    ST_CHECK_EQ(static_cast<int>(wire[21]), 0xA0);
    ST_CHECK_EQ(static_cast<int>(wire[36]), 0xAF);
    // PayloadLen 位于偏移 37，大端 = 1
    ST_CHECK_EQ(static_cast<int>(wire[37]), 0x00);
    ST_CHECK_EQ(static_cast<int>(wire[40]), 0x01);
    // Body 从偏移 41 开始，MAC 在最后 16 字节
    ST_CHECK_EQ(static_cast<int>(wire[41]), 0x01);
    ST_CHECK_EQ(static_cast<int>(wire[42]), 0xB0);
}

// 6. MAC 输入 = [Version .. Body]，不含 Magic 与 MacTag 本身
ST_TEST_CASE("packet: MAC 输入范围") {
    const Bytes body = {'a', 'b', 'c', 'd'};
    const Packet packet = makePacket(body);
    const Bytes macInput = packet.encode();
    ST_CHECK_EQ(macInput.size(), Packet::kHeaderSize - Packet::kMagicSize + body.size());
    ST_CHECK_EQ(static_cast<int>(macInput[0]), 0x01);  // Version 起
    const Bytes wire = packet.encodeWithMac();
    ST_CHECK(macInput == Bytes(wire.begin() + 2, wire.begin() + 2 + macInput.size()));
}

// 7. 非法输入：太短 / Magic 错 / 版本错 / PayloadLen 不匹配 / 多余尾巴
ST_TEST_CASE("packet: 非法输入全部被拒绝") {
    const Bytes wire = makePacket(Bytes{0x01, 0x02, 0x03}).encodeWithMac();
    Packet decoded;
    std::string error;

    // 太短
    ST_CHECK(!Packet::decode(Bytes(wire.begin(), wire.begin() + 10), decoded, &error));

    // Magic 被改
    Bytes badMagic = wire;
    badMagic[0] = 0x00;
    ST_CHECK(!Packet::decode(badMagic, decoded, &error));

    // 版本被改
    Bytes badVersion = wire;
    badVersion[2] = 0x09;
    ST_CHECK(!Packet::decode(badVersion, decoded, &error));

    // PayloadLen 与实际长度不一致（截断 1 字节）
    Bytes truncated(wire.begin(), wire.end() - 1);
    ST_CHECK(!Packet::decode(truncated, decoded, &error));

    // 多余尾巴字节
    Bytes extended = wire;
    extended.push_back(0x00);
    ST_CHECK(!Packet::decode(extended, decoded, &error));
}

// 8. 超长 PayloadLen 不会导致内存分配（直接拒绝）
ST_TEST_CASE("packet: 超长 PayloadLen 直接拒绝") {
    Bytes wire = makePacket(Bytes{0x01}).encodeWithMac();
    // 把 PayloadLen 改成 0x7FFFFFFF
    wire[37] = 0x7F;
    wire[38] = 0xFF;
    wire[39] = 0xFF;
    wire[40] = 0xFF;
    Packet decoded;
    std::string error;
    ST_CHECK(!Packet::decode(wire, decoded, &error));
    ST_CHECK(!error.empty());
}

int main() {
    return ::testutil::runAll("packet");
}
