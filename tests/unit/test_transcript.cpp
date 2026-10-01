// ============================================================================
//  SecureTransfer 测试
//  file: tests/unit/test_transcript.cpp
//
//  说明：握手转录串（transcript）的性质测试。
//        这些性质是"认证不可伪造、不可反射、无歧义"的基础：
//          * 确定性：同一输入得到同一结果；
//          * 域分离：不同用途（认证 / 密钥请求 / 确认）互不相同；
//          * 方向分离：C2S 与 S2C 的 tag 不同（防反射）；
//          * 无歧义：TLV 长度前缀使 ("ab","c") 与 ("a","bc") 不同。
// ============================================================================

#include "test_util.h"

#include <string>

#include "common/hex.h"
#include "crypto/mock_crypto_provider.h"
#include "protocol/transcript.h"

namespace {

const SessionId kSessionId = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
const Nonce kNonceA = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};
const Nonce kNonceB = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                       0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};

Key128 testKey() {
    Key128 key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<Byte>(i);
    }
    return key;
}

}  // namespace

// 1. 确定性
ST_TEST_CASE("transcript: 相同输入得到相同结果") {
    const Bytes first =
        transcript::authTranscript(kSessionId, "alice", "bob", kNonceA, kNonceB);
    const Bytes second =
        transcript::authTranscript(kSessionId, "alice", "bob", kNonceA, kNonceB);
    ST_CHECK(first == second);
}

// 2. 长度符合 TLV 约定
ST_TEST_CASE("transcript: 长度符合 TLV 约定") {
    const Bytes data = transcript::authTranscript(kSessionId, "alice", "bob", kNonceA, kNonceB);
    // L("ST-AUTH-v1")=2+10, L(SessionId)=2+8, L("alice")=2+5, L("bob")=2+3,
    // L(NonceA)=2+16, L(NonceB)=2+16
    const std::size_t expected = (2 + 10) + (2 + 8) + (2 + 5) + (2 + 3) + (2 + 16) + (2 + 16);
    ST_CHECK_EQ(data.size(), expected);
}

// 3. 方向标签分离：防止把对方的 MAC 反射回来冒充自己
ST_TEST_CASE("transcript: C2S 与 S2C 不同（防反射）") {
    const Bytes s2c = transcript::helloAckMacInput(kSessionId, "alice", "bob", kNonceA, kNonceB);
    const Bytes c2s = transcript::authMacInput(kSessionId, "alice", "bob", kNonceA, kNonceB);
    ST_CHECK(s2c != c2s);

    MockCryptoProvider crypto;
    const MacTag tagS2C = crypto.cmac(testKey(), s2c);
    const MacTag tagC2S = crypto.cmac(testKey(), c2s);
    ST_CHECK(tagS2C != tagC2S);
}

// 4. 身份顺序敏感
ST_TEST_CASE("transcript: 身份顺序敏感") {
    const Bytes normal = transcript::authTranscript(kSessionId, "alice", "bob", kNonceA, kNonceB);
    const Bytes swapped = transcript::authTranscript(kSessionId, "bob", "alice", kNonceA, kNonceB);
    ST_CHECK(normal != swapped);
}

// 5. TLV 消除字段拼接歧义
ST_TEST_CASE("transcript: TLV 消除拼接歧义") {
    const Bytes first = transcript::authTranscript(kSessionId, "ab", "c", kNonceA, kNonceB);
    const Bytes second = transcript::authTranscript(kSessionId, "a", "bc", kNonceA, kNonceB);
    ST_CHECK(first != second);
}

// 6. Nonce 参与转录串：Nonce 不同 => 转录串不同（新鲜性）
ST_TEST_CASE("transcript: Nonce 参与且影响结果") {
    Nonce other = kNonceB;
    other[0] = static_cast<Byte>(other[0] ^ 0xFF);
    const Bytes a = transcript::authTranscript(kSessionId, "alice", "bob", kNonceA, kNonceB);
    const Bytes b = transcript::authTranscript(kSessionId, "alice", "bob", kNonceA, other);
    ST_CHECK(a != b);
}

// 7. 各用途的 MAC 输入互不相同（域分离）
ST_TEST_CASE("transcript: 各用途的 MAC 输入互不相同") {
    const Bytes auth = transcript::authMacInput(kSessionId, "alice", "bob", kNonceA, kNonceB);
    const Bytes request = transcript::keyRequestMacInput(kSessionId, kNonceA, kNonceB);
    const Bytes confirm = transcript::keyConfirmMacInput(kSessionId, kNonceA, kNonceB);
    const Bytes confirmAck = transcript::keyConfirmAckMacInput(kSessionId, kNonceA, kNonceB);
    const Bytes enc = transcript::encKeyDerivationInput();
    const Bytes mac = transcript::macKeyDerivationInput();

    ST_CHECK(auth != request);
    ST_CHECK(request != confirm);
    ST_CHECK(confirm != confirmAck);
    ST_CHECK(enc != mac);
}

// 8. 密钥包裹的 MAC 输入覆盖 Nonce 与包裹内容
ST_TEST_CASE("transcript: 密钥包裹 MAC 输入覆盖 Nonce 与内容") {
    Nonce wrapNonce = kNonceA;
    const Bytes wrapped(16, 0x42);
    const Bytes base =
        transcript::keyExchangeMacInput(kSessionId, kNonceA, kNonceB, wrapNonce, wrapped);

    Bytes otherWrapped = wrapped;
    otherWrapped[0] = static_cast<Byte>(otherWrapped[0] ^ 0x01);
    const Bytes changedKey =
        transcript::keyExchangeMacInput(kSessionId, kNonceA, kNonceB, wrapNonce, otherWrapped);

    wrapNonce[0] = static_cast<Byte>(wrapNonce[0] ^ 0x01);
    const Bytes changedNonce =
        transcript::keyExchangeMacInput(kSessionId, kNonceA, kNonceB, wrapNonce, wrapped);

    ST_CHECK(base != changedKey);
    ST_CHECK(base != changedNonce);
}

int main() {
    return ::testutil::runAll("transcript");
}
