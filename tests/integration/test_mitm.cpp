// ============================================================================
//  SecureTransfer 测试
//  file: tests/integration/test_mitm.cpp
//
//  说明：链路中间人（MITM）攻击测试（对应课程"Eve 攻击测试"）：
//  这里不再由通信端点"自己改自己的发送路径"，而是让一个**独立的转发者**
//  坐在 Alice 与 Bob 中间：
//
//        Alice ──▶ [ MitmRelay ] ──▶ Bob
//
//  五条用例：
//    1. 纯中继      → 会话照常建立、双向消息正常（中间人在链路上也读不懂）；
//    2. 中继篡改    → Bob 必须拒绝（⑦ CMAC）；
//    3. 中继丢弃    → 密码学防不住，Bob 只能超时（报告的 limitation）；
//    4. 中继重放    → Bob 必须拒绝（⑥ 防重放）；
//    5. 目标选择    → "下一条 DATA"与"最近一条 DATA"两种选包方式都能命中业务包
//                     （不再是写死的"第几个包"）。
// ============================================================================

#include "secure_test_util.h"
#include "test_util.h"

#include <future>
#include <memory>
#include <string>
#include <thread>

#include <atomic>
#include <chrono>

#include "attack/mitm_relay.h"
#include "crypto/aes_crypto_provider.h"
#include "security/session.h"

namespace {

/// 轮询等待条件成立（最多 timeoutMs）。中继的统计是在"包真的发出去之后"才 ++ 的，
/// 而它与服务端线程是并发的；直接读统计会偶发读到旧值（实测在整套 ctest 里翻过车）。
template <typename Predicate>
bool waitFor(Predicate predicate, int timeoutMs = 3000) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return predicate();
}

/// 服务端跑一次会话：收 expected 条消息，每收一条回一条 ACK。
struct ServerResult {
    bool handshakeOk = false;
    /// 用原子量：测试线程要轮询"服务端收到第几条了"，普通 int 在这里是数据竞争。
    std::atomic<int> received{0};
    std::string lastError;
    ProtocolStats stats;
};

void runServer(SessionConfig config, int expected, ServerResult* result) {
    AesCryptoProvider crypto(nullptr);
    SecureSession session(crypto, config);
    if (!session.acceptOneClient()) {
        result->lastError = session.lastError();
        return;
    }
    result->handshakeOk = true;

    for (int i = 0; i < expected; ++i) {
        MessageType type = MessageType::kError;
        Bytes plaintext;
        if (!session.receiveMessage(type, plaintext)) {
            result->lastError = session.lastError();
            break;
        }
        ++result->received;
        (void)session.sendMessage(MessageType::kData, stringToBytes("ACK"));
    }
    result->stats = session.stats();
    session.close();
}

/// 起一个服务端线程 + 一个中间人中继，返回中继监听端口。
struct MitmFixture {
    ServerResult server;
    std::unique_ptr<testutil::ThreadGuard> serverThread;
    std::unique_ptr<attack::MitmRelay> relay;
    std::uint16_t relayPort = 0;

    /// 中继输出的原始行（回调可能来自转发线程，所以要加锁）
    std::mutex linesMutex;
    std::vector<std::string> lines;

    void addLine(const std::string& line) {
        std::lock_guard<std::mutex> lock(linesMutex);
        lines.push_back(line);
    }
    bool hasLine(const std::string& needle) {
        std::lock_guard<std::mutex> lock(linesMutex);
        for (const std::string& line : lines) {
            if (line.find(needle) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
};

/// @param expected        服务端期望成功收到几条消息
/// @param tamperIndex     中继要篡改的 C2S 包序号（0 = 不篡改）
/// @param dropIndex       中继要丢弃的 C2S 包序号（0 = 不丢弃）
/// @param replayIndex     在第几个 C2S 包之后重放上一个包（0 = 不重放）
bool startMitmScenario(std::uint16_t seed, int expected, std::uint64_t tamperIndex,
                       std::uint64_t dropIndex, std::uint64_t replayIndex,
                       MitmFixture* fixture, std::uint16_t* serverPortOut,
                       attack::MitmPacketType tamperType = attack::MitmPacketType::kAny) {
    const Key128 key = testutil::testMasterKey(static_cast<Byte>(seed));

    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    SessionConfig serverConfig = testutil::makeServerConfig(0, key);
    // 丢弃用例要靠"等超时"收场，这里把 IO 超时压短，测试才跑得快
    serverConfig.ioTimeoutMs = 1200;
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    fixture->serverThread = std::make_unique<testutil::ThreadGuard>(
        std::thread(runServer, serverConfig, expected, &fixture->server));
    const std::uint16_t serverPort = portFuture.get();
    *serverPortOut = serverPort;

    attack::MitmConfig relayConfig;
    relayConfig.listenPort = 0;  // 由系统分配，避免测试之间抢端口
    relayConfig.targetHost = "127.0.0.1";
    relayConfig.targetPort = serverPort;
    relayConfig.quiet = true;    // 测试输出里不要每个包都打一行
    fixture->relay = std::make_unique<attack::MitmRelay>(
        relayConfig, [fixture](const std::string& line) { fixture->addLine(line); });

    std::string error;
    if (!fixture->relay->start(&error)) {
        return false;
    }
    fixture->relayPort = fixture->relay->listenPort();
    if (tamperIndex != 0) {
        attack::MitmTarget target;
        target.index = tamperIndex;
        target.type = tamperType;
        fixture->relay->queueAttack(attack::MitmAttack::kTamper, target, attack::MitmDirection::kC2S);
    }
    if (dropIndex != 0) {
        fixture->relay->queueAttack(attack::MitmAttack::kDrop, attack::MitmTarget{dropIndex},
                                    attack::MitmDirection::kC2S);
    }
    if (replayIndex != 0) {
        fixture->relay->queueReplay(attack::MitmTarget{replayIndex}, attack::MitmDirection::kC2S);
    }
    return true;
}

}  // namespace

// 握手阶段 C2S 有 4 个包（HELLO / AUTH / KEY_REQUEST / KEY_CONFIRM），
// 所以"第 5 个 C2S 包"正好是握手后的第一条业务数据。
constexpr std::uint64_t kFirstDataPacket = 5;

ST_TEST_CASE("mitm: 纯中继下会话照常建立（中间人在链路上也读不懂）") {
    MitmFixture fixture;
    std::uint16_t serverPort = 0;
    ST_CHECK(startMitmScenario(0x51, 1, 0, 0, 0, &fixture, &serverPort));

    // Alice 连的是"中间人"的端口，而不是 Bob 的端口
    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(fixture.relayPort, testutil::testMasterKey(0x51)));
    ST_CHECK(client.connectToServer());
    ST_CHECK(fixture.relay->waitForConnection(2000));

    ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("hello-through-mitm")));
    MessageType replyType = MessageType::kError;
    Bytes reply;
    ST_CHECK(client.receiveMessage(replyType, reply));
    ST_CHECK_EQ(testutil::asText(reply), std::string("ACK"));

    client.close();
    fixture.serverThread->join();
    const attack::MitmStats stats = fixture.relay->stats();

    ST_CHECK(fixture.server.handshakeOk);
    ST_CHECK_EQ(fixture.server.received.load(), 1);
    ST_CHECK_EQ(stats.tampered, 0u);
    ST_CHECK_EQ(stats.dropped, 0u);
    // 两个方向都真的被中继搬运过：C2S 握手 4 个 + 业务 1 个；S2C 握手 3 个 + ACK 1 个
    ST_CHECK(stats.c2sPackets >= 5u);
    ST_CHECK(stats.s2cPackets >= 4u);
    // 只要求"握手 7 个 + 业务 1 个"这 8 个 —— 服务端那条 ACK 是否来得及被转发取决于
    // 谁先关连接（Windows 与 Linux 的时序不同，实测 Linux 上会少一个），不能作为硬条件。
    ST_CHECK(stats.forwarded >= 8u);
}

ST_TEST_CASE("mitm: 中继篡改数据包必须被 ⑦ CMAC 关拒绝") {
    MitmFixture fixture;
    std::uint16_t serverPort = 0;
    ST_CHECK(startMitmScenario(0x62, 1, kFirstDataPacket, 0, 0, &fixture, &serverPort));

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(fixture.relayPort, testutil::testMasterKey(0x62)));
    ST_CHECK(client.connectToServer());
    ST_CHECK(fixture.relay->waitForConnection(2000));
    (void)client.sendMessage(MessageType::kData, stringToBytes("tamper-me"));

    client.close();
    fixture.serverThread->join();
    ST_CHECK(waitFor([&fixture]() { return fixture.relay->stats().tampered >= 1; }));
    const attack::MitmStats stats = fixture.relay->stats();

    ST_CHECK(fixture.server.handshakeOk);
    ST_CHECK_EQ(fixture.server.received.load(), 0);
    ST_CHECK(fixture.server.lastError.find("CMAC") != std::string::npos);
    ST_CHECK_EQ(fixture.server.stats.rejectedMac, 1u);
    ST_CHECK_EQ(stats.tampered, 1u);
}

ST_TEST_CASE("mitm: 中继丢弃数据包时密码学防不住（只能超时）") {
    MitmFixture fixture;
    std::uint16_t serverPort = 0;
    ST_CHECK(startMitmScenario(0x73, 1, 0, kFirstDataPacket, 0, &fixture, &serverPort));

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(fixture.relayPort, testutil::testMasterKey(0x73)));
    ST_CHECK(client.connectToServer());
    ST_CHECK(fixture.relay->waitForConnection(2000));
    (void)client.sendMessage(MessageType::kData, stringToBytes("drop-me"));

    client.close();
    fixture.serverThread->join();
    ST_CHECK(waitFor([&fixture]() { return fixture.relay->stats().dropped >= 1; }));
    const attack::MitmStats stats = fixture.relay->stats();

    ST_CHECK(fixture.server.handshakeOk);
    ST_CHECK_EQ(fixture.server.received.load(), 0);
    ST_CHECK_EQ(stats.dropped, 1u);
    // 可用性攻击：没有"拒绝计数"，只有超时
    ST_CHECK_EQ(fixture.server.stats.rejectedMac, 0u);
    ST_CHECK(fixture.server.lastError.find("CMAC") == std::string::npos);
}

ST_TEST_CASE("mitm: 中继重放数据包必须被 ⑥ 防重放关拒绝") {
    MitmFixture fixture;
    std::uint16_t serverPort = 0;
    // 在第 6 个 C2S 包（第 2 条业务数据）之后，把第 5 个包（第 1 条业务数据）原样重发
    ST_CHECK(startMitmScenario(0x84, 3, 0, 0, kFirstDataPacket + 1, &fixture, &serverPort));

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(fixture.relayPort, testutil::testMasterKey(0x84)));
    ST_CHECK(client.connectToServer());
    ST_CHECK(fixture.relay->waitForConnection(2000));
    ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("first")));
    ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("second")));

    client.close();
    fixture.serverThread->join();
    ST_CHECK(waitFor([&fixture]() { return fixture.relay->stats().replayed >= 1; }));
    const attack::MitmStats stats = fixture.relay->stats();

    ST_CHECK(fixture.server.handshakeOk);
    ST_CHECK_EQ(fixture.server.received.load(), 2);  // 前两条正常收下，重放的那条被拒
    ST_CHECK(fixture.server.lastError.find("Replay") != std::string::npos);
    ST_CHECK_EQ(fixture.server.stats.rejectedReplay, 1u);
    ST_CHECK_EQ(stats.replayed, 1u);
}

ST_TEST_CASE("mitm: 按类型选目标——「下一条 DATA」与「最近一条 DATA」") {
    // 期望服务端只收下 1 条：第 1 条正常，随后被"最近一条"注入的篡改包必须被拒
    MitmFixture fixture;
    std::uint16_t serverPort = 0;
    ST_CHECK(startMitmScenario(0x95, 2, 0, 0, 0, &fixture, &serverPort));

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto,
                         testutil::makeClientConfig(fixture.relayPort, testutil::testMasterKey(0x95)));
    ST_CHECK(client.connectToServer());
    ST_CHECK(fixture.relay->waitForConnection(2000));
    ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("first-message")));

    // 等到"服务端确实收到了第一条"——注意 c2sPackets 是"中继收到"的计数，
    // 它在前、缓存写入在后，用它会抢跑（实测就踩到了）。
    ST_CHECK(waitFor([&fixture]() { return fixture.server.received.load() >= 1; }));

    // 「最近一条 DATA」：不等新包，立刻把刚才那条改一个字节再发一遍（捕获-篡改-重发）
    attack::MitmTarget lastData;
    lastData.type = attack::MitmPacketType::kData;
    lastData.lastOfType = true;
    fixture.relay->queueAttack(attack::MitmAttack::kTamper, lastData,
                               attack::MitmDirection::kC2S);
    ST_CHECK(waitFor([&fixture]() { return fixture.relay->stats().tampered >= 1; }));

    client.close();
    fixture.serverThread->join();

    ST_CHECK(fixture.server.handshakeOk);
    ST_CHECK_EQ(fixture.server.received.load(), 1);  // 只有第一条被正常收下
    ST_CHECK(fixture.server.lastError.find("CMAC") != std::string::npos);
    ST_CHECK_EQ(fixture.server.stats.rejectedMac, 1u);
    // "按类型"意味着握手包不会被误伤：换句话说不必再数"第几个包"
    ST_CHECK_EQ(fixture.relay->stats().c2sPackets, 5u);
}

ST_TEST_CASE("mitm: 序号可以按类型计数（第 1 条短消息 ≠ 第 1 个包）") {
    // 关键点：不写 --type 时"第 1 个包"是 HELLO；写了 --type DATA 之后，
    // "第 1 条"才是第一条业务数据 —— 用户不用再自己扣除 4 个握手包。
    MitmFixture fixture;
    std::uint16_t serverPort = 0;
    ST_CHECK(startMitmScenario(0xA6, 1, 1, 0, 0, &fixture, &serverPort,
                               attack::MitmPacketType::kData));

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto,
                         testutil::makeClientConfig(fixture.relayPort, testutil::testMasterKey(0xA6)));
    ST_CHECK(client.connectToServer());
    ST_CHECK(fixture.relay->waitForConnection(2000));
    ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("first-short-message")));

    client.close();
    fixture.serverThread->join();
    ST_CHECK(waitFor([&fixture]() { return fixture.relay->stats().tampered >= 1; }));

    // 握手完好（没被误伤），只有第一条短消息被改
    ST_CHECK(fixture.server.handshakeOk);
    ST_CHECK_EQ(fixture.server.received.load(), 0);
    ST_CHECK_EQ(fixture.server.stats.rejectedMac, 1u);
    ST_CHECK_EQ(fixture.relay->stats().tampered, 1u);
}

ST_TEST_CASE("mitm: 序号已经过去时必须立刻报错，不能静静挂着") {
    // 这正是"选了第 N 个包、点了篡改、什么都没发生、会话照常"的成因：
    // 早期版本会把这个攻击永久挂在队列里（那个序号永远不会再出现）。
    MitmFixture fixture;
    std::uint16_t serverPort = 0;
    ST_CHECK(startMitmScenario(0xB7, 1, 0, 0, 0, &fixture, &serverPort));

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto,
                         testutil::makeClientConfig(fixture.relayPort, testutil::testMasterKey(0xB7)));
    ST_CHECK(client.connectToServer());
    ST_CHECK(fixture.relay->waitForConnection(2000));
    ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("hello")));
    ST_CHECK(waitFor([&fixture]() { return fixture.server.received.load() >= 1; }));

    // 握手 4 个包早就过去了，这里故意填 2（= AUTH）——必须当场拒绝并说明原因
    attack::MitmTarget stale;
    stale.index = 2;
    fixture.relay->queueAttack(attack::MitmAttack::kTamper, stale, attack::MitmDirection::kC2S);
    ST_CHECK(waitFor([&fixture]() {
        return fixture.hasLine("ERR target=index:2") && fixture.hasLine("已经过去了");
    }));
    // 没有真的注入：统计里不该多出篡改次数
    ST_CHECK_EQ(fixture.relay->stats().tampered, 0u);

    client.close();
    fixture.serverThread->join();
    ST_CHECK_EQ(fixture.server.stats.rejectedMac, 0u);
}

int main() {
    return ::testutil::runAll("mitm");
}
