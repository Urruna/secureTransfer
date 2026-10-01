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
#include <chrono>

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

ST_TEST_CASE("secure_roundtrip: tryReceiveMessage 区分「没有数据」「收到消息」「会话结束」") {
    const Key128 key = testutil::testMasterKey(0x5A);

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

    MessageType type = MessageType::kError;
    Bytes body;

    // ① 对端没有数据：返回 kNothing，等待时间到就返回，而不是把"超时"当成错误。
    const auto idleStart = std::chrono::steady_clock::now();
    ST_CHECK(client.tryReceiveMessage(type, body, 60) ==
             SecureSession::ReceiveStatus::kNothing);
    const auto idleMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - idleStart)
                            .count();
    ST_CHECK(idleMs >= 40);        // 确实等待过（不是忙等空转）
    ST_CHECK(client.lastError().empty());   // "没有数据"不是错误，不写 lastError
    ST_CHECK(client.isEstablished());       // 会话仍然可用

    // ② 对端发来数据：select() 一到数据就返回，远早于给定的等待上限。
    ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("ping")));
    const auto replyStart = std::chrono::steady_clock::now();
    ST_CHECK(client.tryReceiveMessage(type, body, 3000) ==
             SecureSession::ReceiveStatus::kMessage);
    const auto replyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - replyStart)
                             .count();
    ST_CHECK(replyMs < 1000);  // 数据一到就醒（不是等满 3000 ms 的超时轮询）
    ST_CHECK(type == MessageType::kData);
    ST_CHECK_EQ(bytesToString(body), std::string("ACK 1"));

    // ③ 对端关闭连接：返回 kClosed（会话结束），而不是 continue 死循环。
    ST_CHECK(client.sendMessage(MessageType::kClose, Bytes{}));
    ST_CHECK(client.tryReceiveMessage(type, body, 3000) ==
             SecureSession::ReceiveStatus::kMessage);
    ST_CHECK_EQ(bytesToString(body), std::string("BYE"));

    bool closed = false;
    for (int i = 0; i < 100 && !closed; ++i) {
        const SecureSession::ReceiveStatus status = client.tryReceiveMessage(type, body, 100);
        if (status == SecureSession::ReceiveStatus::kClosed) {
            closed = true;
        } else {
            ST_CHECK(status == SecureSession::ReceiveStatus::kNothing);
        }
    }
    ST_CHECK(closed);
    ST_CHECK(!client.lastError().empty());  // 会话结束一定有原因

    client.close();
    serverThread.join();
    ST_CHECK(server.finished);
    ST_CHECK(server.error.empty());
}

int main() {
    return ::testutil::runAll("secure_roundtrip");
}
