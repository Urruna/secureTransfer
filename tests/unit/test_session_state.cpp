// ============================================================================
//  SecureTransfer 测试
//  file: tests/unit/test_session_state.cpp
//
//  说明：会话状态机的边界行为（不涉及真实网络连接的部分）。
// ============================================================================

#include "secure_test_util.h"
#include "test_util.h"

#include <string>

#include "crypto/aes_crypto_provider.h"
#include "crypto/mock_crypto_provider.h"
#include "security/keystore.h"
#include "security/session.h"

namespace {

SessionConfig baseConfig() {
    SessionConfig config;
    config.localId = "alice";
    config.peerId = "bob";
    config.port = 9000;
    config.masterKey = testutil::testMasterKey(0x11);
    config.hasMasterKey = true;
    config.logHandshake = false;
    return config;
}

}  // namespace

ST_TEST_CASE("session: 未建立连接时不能收发业务数据") {
    MockCryptoProvider crypto;
    SecureSession session(crypto, baseConfig());

    ST_CHECK(session.state() == SessionState::kDisconnected);
    ST_CHECK(!session.isEstablished());

    ST_CHECK(!session.sendMessage(MessageType::kData, stringToBytes("hi")));
    ST_CHECK(!session.lastError().empty());

    MessageType receivedType = MessageType::kError;
    Bytes received;
    ST_CHECK(!session.receiveMessage(receivedType, received));

    ST_CHECK_EQ(session.stats().rejectedState, 2u);
}

ST_TEST_CASE("session: 未加载 K_master 时拒绝建立会话") {
    MockCryptoProvider crypto;
    SessionConfig config = baseConfig();
    config.hasMasterKey = false;
    SecureSession session(crypto, config);
    ST_CHECK(!session.connectToServer());
    ST_CHECK(session.state() == SessionState::kDisconnected);
}

ST_TEST_CASE("session: localId / peerId 为空时拒绝建立会话") {
    MockCryptoProvider crypto;
    SessionConfig config = baseConfig();
    config.localId.clear();
    SecureSession session(crypto, config);
    ST_CHECK(!session.connectToServer());
}

ST_TEST_CASE("session: 连接不存在的服务端时报错而不是崩溃") {
    AesCryptoProvider crypto(nullptr);
    SessionConfig config = baseConfig();
    config.host = "127.0.0.1";
    config.port = 1;  // 几乎不可能有人监听
    SecureSession session(crypto, config);
    ST_CHECK(!session.connectToServer());
    ST_CHECK(session.state() == SessionState::kFailed);
    ST_CHECK(!session.lastError().empty());
}

ST_TEST_CASE("session: 状态与统计的可读输出") {
    ST_CHECK_EQ(std::string(sessionStateToString(SessionState::kEstablished)), "ESTABLISHED");
    ST_CHECK_EQ(std::string(sessionStateToString(SessionState::kFailed)), "FAILED");

    ProtocolStats stats;
    stats.sentPackets = 3;
    stats.rejectedMac = 1;
    const std::string summary = stats.summary();
    ST_CHECK(summary.find("sent=3") != std::string::npos);
    ST_CHECK(summary.find("handshake(ok/fail)") != std::string::npos);
}

ST_TEST_CASE("session: 关闭可以重复调用") {
    MockCryptoProvider crypto;
    SecureSession session(crypto, baseConfig());
    session.close();
    session.close();
    ST_CHECK(session.state() == SessionState::kDisconnected);
}

ST_TEST_CASE("keystore: 解析十六进制密钥与身份") {
    KeyStoreConfig config;
    std::string error;
    const std::string text =
        "# 测试配置\n"
        "[identity]\n"
        "alice_id = alice\n"
        "bob_id   = bob\n"
        "[keys]\n"
        "master_key = 0f1e2d3c4b5a69788796a5b4c3d2e1f0\n";
    ST_CHECK(KeyStore::parse(text, config, error));
    ST_CHECK(config.hasMasterKey);
    ST_CHECK_EQ(config.aliceId, std::string("alice"));
    ST_CHECK_EQ(config.bobId, std::string("bob"));
    ST_CHECK_EQ(static_cast<int>(config.masterKey[0]), 0x0f);
    ST_CHECK_EQ(static_cast<int>(config.masterKey[15]), 0xf0);
}

ST_TEST_CASE("keystore: 非法密钥被拒绝") {
    Key128 key{};
    std::string error;
    // 长度不足
    ST_CHECK(!KeyStore::parseKey("00112233", key, error));
    ST_CHECK(!error.empty());
    // 非十六进制字符
    ST_CHECK(!KeyStore::parseKey("zz1122334455667788990011223344ff", key, error));
    // 正确长度
    ST_CHECK(KeyStore::parseKey("00112233445566778899aabbccddeeff", key, error));
}

ST_TEST_CASE("keystore: 缺少 master_key 时报错") {
    KeyStoreConfig config;
    std::string error;
    ST_CHECK(!KeyStore::parse("alice_id = alice\n", config, error));
    ST_CHECK(!error.empty());
}

int main() {
    return ::testutil::runAll("session_state");
}
