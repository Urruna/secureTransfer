// ============================================================================
//  SecureTransfer 测试
//  file: tests/integration/test_forge.cpp
//
//  说明：身份伪造测试（对应课程"Eve 假冒 Alice"）。
//        Eve 不知道 K_master，因此既无法通过 Bob 的认证，
//        也无法验证 Bob 的 HELLO_ACK。双方都必须失败。
// ============================================================================

#include "secure_test_util.h"
#include "test_util.h"

#include <future>
#include <thread>

#include "crypto/aes_crypto_provider.h"
#include "security/session.h"

namespace {

struct ForgeResult {
    bool handshakeOk = false;
    ProtocolStats stats;
    std::string error;
};

void runServer(SessionConfig config, ForgeResult* result) {
    AesCryptoProvider crypto(nullptr);
    SecureSession session(crypto, config);
    if (!session.acceptOneClient()) {
        result->error = session.lastError();
    } else {
        result->handshakeOk = true;
    }
    result->stats = session.stats();
    session.close();
}

}  // namespace

ST_TEST_CASE("forge: 使用错误 K_master 的客户端无法通过认证") {
    const Key128 serverKey = testutil::testMasterKey(0x51);
    const Key128 attackerKey = testutil::testMasterKey(0x99);  // Eve 不知道真密钥

    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    SessionConfig serverConfig = testutil::makeServerConfig(0, serverKey);
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    ForgeResult server;
    testutil::ThreadGuard serverThread(std::thread(runServer, serverConfig, &server));
    const std::uint16_t port = portFuture.get();

    AesCryptoProvider crypto(nullptr);
    SecureSession attacker(crypto, testutil::makeClientConfig(port, attackerKey));
    const bool attackerHandshake = attacker.connectToServer();
    const std::string attackerError = attacker.lastError();
    attacker.close();

    serverThread.join();

    ST_CHECK(!attackerHandshake);
    ST_CHECK(attackerError.find("Authentication Failed") != std::string::npos);

    ST_CHECK(!server.handshakeOk);
    ST_CHECK(server.stats.handshakesFailed >= 1u);
}

ST_TEST_CASE("forge: 服务端使用不同 K_master 时客户端也应拒绝") {
    const Key128 clientKey = testutil::testMasterKey(0x61);
    const Key128 wrongServerKey = testutil::testMasterKey(0x62);

    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    SessionConfig serverConfig = testutil::makeServerConfig(0, wrongServerKey);
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    ForgeResult server;
    testutil::ThreadGuard serverThread(std::thread(runServer, serverConfig, &server));
    const std::uint16_t port = portFuture.get();

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(port, clientKey));
    const bool ok = client.connectToServer();
    const std::string error = client.lastError();
    client.close();

    serverThread.join();

    ST_CHECK(!ok);
    ST_CHECK(error.find("Authentication Failed") != std::string::npos ||
             error.find("不符") != std::string::npos);
}

int main() {
    return ::testutil::runAll("forge");
}
