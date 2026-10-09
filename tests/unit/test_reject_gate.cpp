// ============================================================================
//  SecureTransfer 测试
//  file: tests/unit/test_reject_gate.cpp
//
//  说明：验证 SecureSession 新增的 RejectGate（"倒在哪一关"）。
//        Eve 攻击面板要靠它精确显示拦截点，所以这里把三种攻击的关卡钉死：
//          篡改密文（sequence+1）→ ⑦ CMAC
//          原样重放            → ⑥ 防重放
//          改 SessionId        → ③ SessionId 不匹配
//        另外验证"连续两次不同拒绝时，读到的是当前关卡而不是陈旧值"。
// ============================================================================

#include "secure_test_util.h"
#include "test_util.h"

#include <future>
#include <thread>
#include <vector>

#include "crypto/aes_crypto_provider.h"
#include "protocol/packet.h"
#include "security/session.h"

namespace {

struct GateResult {
    bool handshakeOk = false;
    std::vector<RejectGate> gates;   ///< 每次接收失败时记录的关卡
    std::vector<std::string> errors;
    ProtocolStats stats;
    std::string error;
};

/// 服务端：先接受会话，然后一直收，直到累计 `expectedFailures` 次失败为止。
/// 记录每次失败时的 lastRejectGate()（这正是 UI 面板要用的信息）。
void runServer(SessionConfig config, int expectedFailures, GateResult* result) {
    AesCryptoProvider crypto(nullptr);
    SecureSession session(crypto, config);
    if (!session.acceptOneClient()) {
        result->error = session.lastError();
        return;
    }
    result->handshakeOk = true;

    int failures = 0;
    while (failures < expectedFailures) {
        MessageType type = MessageType::kError;
        Bytes body;
        if (session.receiveMessage(type, body)) {
            (void)session.sendMessage(MessageType::kData, stringToBytes("OK"));
            continue;
        }
        result->gates.push_back(session.lastRejectGate());
        result->errors.push_back(session.lastError());
        ++failures;
    }

    result->stats = session.stats();
    session.close();
}

/// 客户端：连接 + 发一条正常消息并等回执（建立防重放水位）。
Bytes sendOneNormalMessage(SecureSession& client) {
    ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("transfer 100 USD")));
    MessageType replyType = MessageType::kError;
    Bytes reply;
    ST_CHECK(client.receiveMessage(replyType, reply));
    return client.lastSentWireForTesting();   // 返回刚才那条合法数据包的线上字节
}

}  // namespace

ST_TEST_CASE("reject_gate: 篡改密文倒在第⑦关（CMAC）") {
    const Key128 key = testutil::testMasterKey(0x51);

    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    SessionConfig serverConfig = testutil::makeServerConfig(0, key);
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    GateResult server;
    testutil::ThreadGuard serverThread(std::thread(runServer, serverConfig, 1, &server));
    const std::uint16_t port = portFuture.get();

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(port, key));
    ST_CHECK(client.connectToServer());
    const Bytes legal = sendOneNormalMessage(client);

    // 篡改：改 1 个密文字节 + 序号 +1（序号必须变，否则先被防重放拦下，测不到 MAC 关）
    Packet packet;
    ST_CHECK(Packet::decode(legal, packet));
    ST_CHECK(!packet.body.empty());
    packet.body[0] = static_cast<Byte>(packet.body[0] ^ 0xFF);
    packet.sequence += 1;
    ST_CHECK(client.sendRawWireForTesting(packet.encodeWithMac()));

    client.close();
    serverThread.join();

    ST_CHECK(server.handshakeOk);
    ST_CHECK_EQ(server.gates.size(), 1u);
    ST_CHECK(server.gates[0] == RejectGate::kMac);
    ST_CHECK_EQ(server.stats.rejectedMac, 1u);
    ST_CHECK_EQ(server.stats.rejectedReplay, 0u);
}

ST_TEST_CASE("reject_gate: 原样重放倒在第⑥关（防重放）") {
    const Key128 key = testutil::testMasterKey(0x52);

    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    SessionConfig serverConfig = testutil::makeServerConfig(0, key);
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    GateResult server;
    testutil::ThreadGuard serverThread(std::thread(runServer, serverConfig, 1, &server));
    const std::uint16_t port = portFuture.get();

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(port, key));
    ST_CHECK(client.connectToServer());
    const Bytes legal = sendOneNormalMessage(client);

    // 原样重放：同一段线上字节再发一次（序号没有前进）
    ST_CHECK(client.sendRawWireForTesting(legal));

    client.close();
    serverThread.join();

    ST_CHECK(server.handshakeOk);
    ST_CHECK_EQ(server.gates.size(), 1u);
    ST_CHECK(server.gates[0] == RejectGate::kReplay);
    ST_CHECK_EQ(server.stats.rejectedReplay, 1u);
    ST_CHECK_EQ(server.stats.rejectedMac, 0u);
}

ST_TEST_CASE("reject_gate: 改 SessionId 倒在第③关") {
    const Key128 key = testutil::testMasterKey(0x53);

    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    SessionConfig serverConfig = testutil::makeServerConfig(0, key);
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    GateResult server;
    testutil::ThreadGuard serverThread(std::thread(runServer, serverConfig, 1, &server));
    const std::uint16_t port = portFuture.get();

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(port, key));
    ST_CHECK(client.connectToServer());
    const Bytes legal = sendOneNormalMessage(client);

    // 改 SessionId（第③关在防重放之前检查，所以不用动序号）
    Packet packet;
    ST_CHECK(Packet::decode(legal, packet));
    packet.sessionId[0] = static_cast<Byte>(packet.sessionId[0] ^ 0xFF);
    ST_CHECK(client.sendRawWireForTesting(packet.encodeWithMac()));

    client.close();
    serverThread.join();

    ST_CHECK(server.handshakeOk);
    ST_CHECK_EQ(server.gates.size(), 1u);
    ST_CHECK(server.gates[0] == RejectGate::kSessionId);
    ST_CHECK(server.errors[0].find("SessionId") != std::string::npos);
}

ST_TEST_CASE("reject_gate: 连续两次不同拒绝读到的是当前关卡（不是陈旧值）") {
    const Key128 key = testutil::testMasterKey(0x54);

    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    SessionConfig serverConfig = testutil::makeServerConfig(0, key);
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    GateResult server;
    testutil::ThreadGuard serverThread(std::thread(runServer, serverConfig, 2, &server));
    const std::uint16_t port = portFuture.get();

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(port, key));
    ST_CHECK(client.connectToServer());
    const Bytes legal = sendOneNormalMessage(client);

    // ① 先重放（第⑥关）
    ST_CHECK(client.sendRawWireForTesting(legal));

    // ② 再篡改（第⑦关）：序号 +1 以跳过防重放
    Packet packet;
    ST_CHECK(Packet::decode(legal, packet));
    packet.body[0] = static_cast<Byte>(packet.body[0] ^ 0xFF);
    packet.sequence += 1;
    ST_CHECK(client.sendRawWireForTesting(packet.encodeWithMac()));

    client.close();
    serverThread.join();

    ST_CHECK(server.handshakeOk);
    ST_CHECK_EQ(server.gates.size(), 2u);
    ST_CHECK(server.gates[0] == RejectGate::kReplay);   // 第一次：重放
    ST_CHECK(server.gates[1] == RejectGate::kMac);      // 第二次：篡改（不能是陈旧的重放）
}

int main() {
    return ::testutil::runAll("reject_gate");
}
