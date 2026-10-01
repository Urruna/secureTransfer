// ============================================================================
//  SecureTransfer 测试
//  file: tests/integration/test_secure_roundtrip.cpp
//
//  说明：第二部分的主集成测试。真实 TCP + 完整握手 + 4 条课程要求的
//        测试消息，验证"解密结果与原始明文逐字节一致、完整性校验通过"。
// ============================================================================

#include "secure_test_util.h"
#include "test_util.h"

#include <future>
#include <thread>
#include <vector>

#include "crypto/aes_crypto_provider.h"
#include "security/session.h"

namespace {

Bytes makeBinaryMessage() {
    Bytes data = stringToBytes("你好，Bob，这是一次安全通信测试。");
    for (int i = 0; i < 37; ++i) {
        data.push_back(static_cast<Byte>(i * 7 + 3));
    }
    return data;
}

std::vector<Bytes> testMessages() {
    std::vector<Bytes> messages;
    messages.push_back(stringToBytes("Hello Bob!"));
    messages.push_back(stringToBytes("A secure message between Alice and Bob."));
    messages.push_back(stringToBytes(
        "Transfer #1024: Alice->Bob, amount=500.00 USD; status=OK! (check: 9f8e7d6c)"));
    messages.push_back(makeBinaryMessage());
    return messages;
}

struct ServerResult {
    bool handshakeOk = false;
    bool finished = false;
    std::vector<Bytes> received;
    ProtocolStats stats;
    std::string error;
};

void runServer(SessionConfig config, ServerResult* result) {
    AesCryptoProvider crypto(nullptr);
    SecureSession session(crypto, config);

    if (!session.acceptOneClient()) {
        result->error = session.lastError();
        return;
    }
    result->handshakeOk = true;

    // 循环上限只是防御性保护（避免测试写错时无限等待），
    // 正常退出路径是收到 kClose。
    for (int i = 0; i < 64; ++i) {
        MessageType type = MessageType::kError;
        Bytes plaintext;
        if (!session.receiveMessage(type, plaintext)) {
            result->error = session.lastError();
            break;
        }
        if (type == MessageType::kClose) {
            result->finished = true;
            // 回复 CLOSE 的确认（同样是加密数据包）
            (void)session.sendMessage(MessageType::kData, stringToBytes("BYE"));
            break;
        }
        result->received.push_back(plaintext);
        const std::string ack = "ACK " + std::to_string(result->received.size());
        if (!session.sendMessage(MessageType::kData, stringToBytes(ack))) {
            result->error = session.lastError();
            break;
        }
    }

    result->stats = session.stats();
    session.close();
}

}  // namespace

ST_TEST_CASE("secure_roundtrip: 完整握手 + 4 条消息双向传输") {
    const Key128 key = testutil::testMasterKey(0x21);

    // 服务端监听 0 端口，通过回调把真实端口告诉测试代码，
    // 保证客户端一定在服务端 listen() 之后再连接。
    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    SessionConfig serverConfig = testutil::makeServerConfig(0, key);
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    ServerResult server;
    testutil::ThreadGuard serverThread(std::thread(runServer, serverConfig, &server));
    const std::uint16_t port = portFuture.get();

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(port, key));
    ST_CHECK(client.connectToServer());
    ST_CHECK(client.isEstablished());
    ST_CHECK(client.state() == SessionState::kEstablished);

    const std::vector<Bytes> messages = testMessages();
    for (std::size_t i = 0; i < messages.size(); ++i) {
        ST_CHECK(client.sendMessage(MessageType::kData, messages[i]));

        // 发送侧的可观测信息应当完整（用于报告中的"明文→密文→CMAC"记录）
        const PacketTrace& trace = client.lastSentTrace();
        ST_CHECK(trace.valid);
        ST_CHECK_EQ(trace.ciphertext.size(), messages[i].size());
        ST_CHECK(trace.ciphertext != messages[i]);  // 确实被加密了
        ST_CHECK(trace.sequence == i + 1);

        MessageType replyType = MessageType::kError;
        Bytes reply;
        ST_CHECK(client.receiveMessage(replyType, reply));
        ST_CHECK(replyType == MessageType::kData);
        ST_CHECK_EQ(bytesToString(reply), std::string("ACK ") + std::to_string(i + 1));
    }

    ST_CHECK(client.sendMessage(MessageType::kClose, Bytes{}));
    MessageType closingReply = MessageType::kError;
    Bytes closingData;
    ST_CHECK(client.receiveMessage(closingReply, closingData));
    ST_CHECK_EQ(bytesToString(closingData), std::string("BYE"));

    const ProtocolStats clientStats = client.stats();
    client.close();
    serverThread.join();

    ST_CHECK(server.handshakeOk);
    ST_CHECK(server.finished);
    ST_CHECK(server.error.empty());
    ST_CHECK_EQ(server.received.size(), messages.size());
    for (std::size_t i = 0; i < messages.size(); ++i) {
        ST_CHECK(server.received[i] == messages[i]);
    }

    ST_CHECK_EQ(clientStats.rejectedMac, 0u);
    ST_CHECK_EQ(clientStats.rejectedReplay, 0u);
    ST_CHECK_EQ(clientStats.handshakesOk, 1u);
    ST_CHECK_EQ(server.stats.rejectedMac, 0u);
    ST_CHECK_EQ(server.stats.rejectedReplay, 0u);
    ST_CHECK_EQ(server.stats.handshakesOk, 1u);
}

ST_TEST_CASE("secure_roundtrip: 同一会话内 Nonce 不重复") {
    const Key128 key = testutil::testMasterKey(0x33);

    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    SessionConfig serverConfig = testutil::makeServerConfig(0, key);
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    ServerResult server;
    testutil::ThreadGuard serverThread(std::thread(runServer, serverConfig, &server));
    const std::uint16_t port = portFuture.get();

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(port, key));
    ST_CHECK(client.connectToServer());

    // 发送 20 条相同的明文，Nonce 与密文都必须各不相同
    std::vector<Nonce> nonces;
    std::vector<Bytes> ciphertexts;
    for (int i = 0; i < 20; ++i) {
        ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("SAME")));
        nonces.push_back(client.lastSentTrace().nonce);
        ciphertexts.push_back(client.lastSentTrace().ciphertext);
        MessageType type = MessageType::kError;
        Bytes reply;
        ST_CHECK(client.receiveMessage(type, reply));
    }
    for (std::size_t i = 0; i < nonces.size(); ++i) {
        for (std::size_t j = i + 1; j < nonces.size(); ++j) {
            ST_CHECK(nonces[i] != nonces[j]);
            ST_CHECK(ciphertexts[i] != ciphertexts[j]);
        }
    }

    ST_CHECK(client.sendMessage(MessageType::kClose, Bytes{}));
    MessageType type = MessageType::kError;
    Bytes reply;
    ST_CHECK(client.receiveMessage(type, reply));
    client.close();
    serverThread.join();
    ST_CHECK(server.error.empty());
}

int main() {
    return ::testutil::runAll("secure_roundtrip");
}
