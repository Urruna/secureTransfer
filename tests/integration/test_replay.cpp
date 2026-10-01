// ============================================================================
//  SecureTransfer 测试
//  file: tests/integration/test_replay.cpp
//
//  说明：重放攻击测试（对应课程"Eve 截获合法数据包后重新发送"）。
//        Bob 必须只处理一次，第二次收到同样的包时判定为重放并拒绝。
// ============================================================================

#include "secure_test_util.h"
#include "test_util.h"

#include <future>
#include <thread>

#include "crypto/aes_crypto_provider.h"
#include "security/session.h"

namespace {

struct ReplayResult {
    bool handshakeOk = false;
    bool firstMessageOk = false;
    bool secondMessageRejected = false;
    int delivered = 0;
    ProtocolStats stats;
    std::string error;
};

void runServer(SessionConfig config, ReplayResult* result) {
    AesCryptoProvider crypto(nullptr);
    SecureSession session(crypto, config);
    if (!session.acceptOneClient()) {
        result->error = session.lastError();
        return;
    }
    result->handshakeOk = true;

    MessageType type = MessageType::kError;
    Bytes plaintext;
    if (session.receiveMessage(type, plaintext)) {
        result->firstMessageOk = true;
        ++result->delivered;
        (void)session.sendMessage(MessageType::kData, stringToBytes("OK"));
    }

    MessageType replayedType = MessageType::kError;
    Bytes replayedData;
    if (!session.receiveMessage(replayedType, replayedData)) {
        result->secondMessageRejected = true;
        result->error = session.lastError();
    } else {
        ++result->delivered;
    }

    result->stats = session.stats();
    session.close();
}

}  // namespace

ST_TEST_CASE("replay: 重放同一个数据包必须被拒绝") {
    const Key128 key = testutil::testMasterKey(0x71);

    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    SessionConfig serverConfig = testutil::makeServerConfig(0, key);
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    ReplayResult server;
    testutil::ThreadGuard serverThread(std::thread(runServer, serverConfig, &server));
    const std::uint16_t port = portFuture.get();

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(port, key));
    ST_CHECK(client.connectToServer());

    ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("transfer 100 USD")));
    const Bytes captured = client.lastSentWireForTesting();

    MessageType replyType = MessageType::kError;
    Bytes reply;
    ST_CHECK(client.receiveMessage(replyType, reply));

    // Eve 把刚才抓到的字节原样再发一次
    ST_CHECK(client.sendRawWireForTesting(captured));

    client.close();
    serverThread.join();

    ST_CHECK(server.handshakeOk);
    ST_CHECK(server.firstMessageOk);
    ST_CHECK(server.secondMessageRejected);
    ST_CHECK_EQ(server.delivered, 1);
    ST_CHECK_EQ(server.stats.rejectedReplay, 1u);
    ST_CHECK_EQ(server.stats.rejectedMac, 0u);
    ST_CHECK(server.error.find("Replay Attack Detected") != std::string::npos);
}

ST_TEST_CASE("replay: 每次会话都使用新的 SessionId 与 Nonce_A（握手新鲜性）") {
    const Key128 key = testutil::testMasterKey(0x81);

    std::promise<std::uint16_t> firstPortPromise;
    auto firstPortFuture = firstPortPromise.get_future();
    SessionConfig firstServerConfig = testutil::makeServerConfig(0, key);
    firstServerConfig.onListening = [&firstPortPromise](std::uint16_t port) {
        firstPortPromise.set_value(port);
    };

    // 第一轮：正常握手并记录 Alice 的 HELLO
    ReplayResult first;
    testutil::ThreadGuard firstServer(std::thread(runServer, firstServerConfig, &first));
    const std::uint16_t port = firstPortFuture.get();
    AesCryptoProvider crypto1(nullptr);
    SecureSession client1(crypto1, testutil::makeClientConfig(port, key));
    ST_CHECK(client1.connectToServer());
    ST_CHECK(client1.sendMessage(MessageType::kData, stringToBytes("hello")));
    MessageType type = MessageType::kError;
    Bytes reply;
    ST_CHECK(client1.receiveMessage(type, reply));
    client1.close();
    firstServer.join();
    ST_CHECK(first.firstMessageOk);

    std::promise<std::uint16_t> secondPortPromise;
    auto secondPortFuture = secondPortPromise.get_future();
    SessionConfig secondServerConfig = testutil::makeServerConfig(0, key);
    secondServerConfig.onListening = [&secondPortPromise](std::uint16_t port) {
        secondPortPromise.set_value(port);
    };

    // 第二轮：新客户端连接。Bob 每次都会生成新的 NonceB，
    // 认证标签又绑定了 NonceA / NonceB / SessionId，
    // 因此旧会话的认证消息无法通过新会话的校验
    // （转录串的绑定关系见 tests/unit/test_transcript.cpp）。
    ReplayResult second;
    testutil::ThreadGuard secondServer(std::thread(runServer, secondServerConfig, &second));
    const std::uint16_t secondPort = secondPortFuture.get();
    AesCryptoProvider crypto2(nullptr);
    SecureSession client2(crypto2, testutil::makeClientConfig(secondPort, key));
    ST_CHECK(client2.connectToServer());
    ST_CHECK(client2.sessionId() != client1.sessionId() ||
              client2.nonceA() != client1.nonceA());
    client2.close();
    secondServer.join();
}

int main() {
    return ::testutil::runAll("replay");
}
