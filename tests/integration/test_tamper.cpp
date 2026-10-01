// ============================================================================
//  SecureTransfer 测试
//  file: tests/integration/test_tamper.cpp
//
//  说明：篡改攻击测试（对应课程"Eve 篡改通信内容"）。
//        Alice 在合法数据包上改动密文字节后再发送，Bob 必须：
//          1. 拒绝该数据包（不交给上层）；
//          2. 在统计里记录 rejectedMac；
//          3. 继续正常工作，不崩溃。
// ============================================================================

#include "secure_test_util.h"
#include "test_util.h"

#include <future>
#include <thread>

#include "crypto/aes_crypto_provider.h"
#include "security/session.h"

namespace {

struct TamperResult {
    bool handshakeOk = false;
    bool firstMessageOk = false;
    bool secondMessageRejected = false;
    int delivered = 0;
    ProtocolStats stats;
    std::string error;
};

void runServer(SessionConfig config, TamperResult* result) {
    AesCryptoProvider crypto(nullptr);
    SecureSession session(crypto, config);
    if (!session.acceptOneClient()) {
        result->error = session.lastError();
        return;
    }
    result->handshakeOk = true;

    // 第 1 条：正常消息
    MessageType type = MessageType::kError;
    Bytes plaintext;
    if (session.receiveMessage(type, plaintext)) {
        result->firstMessageOk = true;
        ++result->delivered;
        (void)session.sendMessage(MessageType::kData, stringToBytes("OK"));
    }

    // 第 2 条：被篡改的消息，必须被拒绝
    MessageType tamperedType = MessageType::kError;
    Bytes tamperedData;
    if (!session.receiveMessage(tamperedType, tamperedData)) {
        result->secondMessageRejected = true;
        result->error = session.lastError();
    } else {
        ++result->delivered;
    }

    result->stats = session.stats();
    session.close();
}

}  // namespace

ST_TEST_CASE("tamper: 修改密文字节后必须被拒绝") {
    const Key128 key = testutil::testMasterKey(0x41);

    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    SessionConfig serverConfig = testutil::makeServerConfig(0, key);
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    TamperResult server;
    testutil::ThreadGuard serverThread(std::thread(runServer, serverConfig, &server));
    const std::uint16_t port = portFuture.get();

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(port, key));
    ST_CHECK(client.connectToServer());

    // 第 1 条正常消息
    ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("transfer 100 USD")));
    MessageType replyType = MessageType::kError;
    Bytes reply;
    ST_CHECK(client.receiveMessage(replyType, reply));

    // 构造被篡改的数据包：在合法包的基础上改 1 个密文字节，并把序号 +1
    // （序号必须变化，否则会先被防重放逻辑拦住，测不到完整性校验）
    Packet packet;
    ST_CHECK(Packet::decode(client.lastSentWireForTesting(), packet));
    ST_CHECK(!packet.body.empty());
    packet.body[0] = static_cast<Byte>(packet.body[0] ^ 0xFF);
    packet.sequence += 1;
    ST_CHECK(client.sendRawWireForTesting(packet.encodeWithMac()));

    client.close();
    serverThread.join();

    ST_CHECK(server.handshakeOk);
    ST_CHECK(server.firstMessageOk);
    ST_CHECK(server.secondMessageRejected);
    ST_CHECK_EQ(server.delivered, 1);
    ST_CHECK_EQ(server.stats.rejectedMac, 1u);
    ST_CHECK_EQ(server.stats.rejectedReplay, 0u);
    ST_CHECK(server.error.find("CMAC verification failed") != std::string::npos);
}

int main() {
    return ::testutil::runAll("tamper");
}
