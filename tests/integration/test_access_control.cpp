// ============================================================================
//  SecureTransfer 测试 - 访问控制端到端测试
//  file: tests/integration/test_access_control.cpp
//
//  验证"服务端权威判定"：
//    * 管理员（alice）发送文件 → 允许，落盘成功；
//    * 访客（mallory）发送文件 → 拒绝：不落盘、回明确拒绝消息、
//      **会话保持可用**（之后还能正常发短消息，与"篡改/重放导致断连"不同）；
//    * 审计记录里同时出现 ALLOW 与 DENY。
//
//  两个客户端各用一个服务端线程（不同端口），避免重连竞态。
// ============================================================================

#include "secure_test_util.h"
#include "test_util.h"

#include <cstdlib>
#include <fstream>
#include <future>
#include <string>
#include <thread>
#include <vector>

#include "application/file_transfer.h"
#include "crypto/aes_crypto_provider.h"
#include "security/access_control.h"
#include "security/session.h"

namespace {

const std::string kWorkDir = testutil::workDir("st_access_test");

const char* const kPolicyText =
    "[default]\n"
    "role = guest\n"
    "[identity]\n"
    "alice = admin\n"
    "mallory = guest\n"
    "[role:admin]\n"
    "permissions = send_message, send_file, send_image, view_log, manage_users\n"
    "[role:guest]\n"
    "permissions = send_message\n";

void ensureDir(const std::string& dir) {
    (void)ensureDirectory(dir);
}

Bytes makeData(std::size_t size, std::uint32_t seed) {
    Bytes data(size);
    std::uint32_t state = seed ? seed : 1;
    for (std::size_t i = 0; i < size; ++i) {
        state = state * 1103515245u + 12345u;
        data[i] = static_cast<Byte>((state >> 16) & 0xFF);
    }
    return data;
}

std::string writeFile(const std::string& path, const Bytes& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    out.close();
    return path;
}

Bytes readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return Bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

bool fileExists(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return in.good();
}

struct ServerResult {
    bool handshakeOk = false;
    bool finished = false;
    std::size_t allowed = 0;
    std::size_t denied = 0;
    std::vector<transfer::ReceiveResult> transfers;
    std::vector<std::string> decisions;
    std::string error;
};

/// 服务端：完整握手 + 访问控制判定 + 正常的应用层处理。
void runServer(SessionConfig config, std::string outDir, ServerResult* result) {
    AesCryptoProvider crypto(nullptr);
    SecureSession session(crypto, config);
    if (!session.acceptOneClient()) {
        result->error = session.lastError();
        return;
    }
    result->handshakeOk = true;

    acl::AccessController access;
    std::string error;
    if (!access.loadText(kPolicyText, error)) {
        result->error = "策略加载失败: " + error;
        return;
    }

    // 身份来自**认证过的对端标识**（握手时双方交换并校验过），不是客户端自称
    const std::string peer = config.peerId;
    transfer::TransferReceiver receiver(outDir);
    bool droppingTransfer = false;

    for (int i = 0; i < 64; ++i) {
        MessageType type = MessageType::kError;
        Bytes body;
        if (!session.receiveMessage(type, body)) {
            result->error = session.lastError();
            break;
        }
        if (type == MessageType::kClose) {
            result->finished = true;
            (void)session.sendMessage(MessageType::kData, stringToBytes("BYE"));
            break;
        }

        acl::Operation operation = acl::Operation::kSendMessage;
        const bool protectedOperation = acl::operationFromMessageType(type, operation);

        // 传输进行中：被拒绝的传输只剩数据块与结束包，直接丢弃（不落盘）
        if (droppingTransfer && (type == MessageType::kFileChunk || type == MessageType::kFileEnd)) {
            if (type == MessageType::kFileEnd) {
                droppingTransfer = false;
            }
            continue;
        }
        if (type == MessageType::kFileStart || type == MessageType::kImage) {
            droppingTransfer = false;
        }

        if (protectedOperation && !access.isAllowed(peer, operation)) {
            access.record(peer, operation, false, "被服务端拒绝");
            result->denied = access.deniedCount();
            if (type == MessageType::kFileStart || type == MessageType::kImage) {
                droppingTransfer = true;
            }
            (void)session.sendMessage(
                MessageType::kData,
                stringToBytes(std::string("ACCESS DENIED: ") + acl::operationToString(operation) +
                              " 角色 " + access.roleOf(peer) + " 无此权限"));
            continue;
        }
        if (protectedOperation) {
            access.record(peer, operation, true, "");
            result->allowed = access.allowedCount();
        }

        std::string transferError;
        if (receiver.handle(type, body, &transferError)) {
            if (receiver.inProgress()) {
                continue;
            }
            const transfer::ReceiveResult& done = receiver.lastResult();
            result->transfers.push_back(done);
            const std::string ack =
                done.ok ? "FILE OK " + done.fileName : "FILE FAILED " + done.error;
            (void)session.sendMessage(MessageType::kData, stringToBytes(ack));
            continue;
        }

        (void)session.sendMessage(MessageType::kData, stringToBytes("ACK"));
    }

    result->decisions = access.recentDecisions();
    result->allowed = access.allowedCount();
    result->denied = access.deniedCount();
    session.close();
}

}  // namespace

ST_TEST_CASE("access_control: 管理员可发文件，访客被拒绝且会话继续") {
    ensureDir(kWorkDir);
    ensureDir(kWorkDir + "/admin_out");
    ensureDir(kWorkDir + "/guest_out");

    const Bytes payload = makeData(100u * 1024u, 0xACE);
    const std::string sourcePath = writeFile(kWorkDir + "/access_src.bin", payload);
    const std::string adminSavedPath = kWorkDir + "/admin_out/access_src.bin";
    const std::string guestSavedPath = kWorkDir + "/guest_out/access_src.bin";
    (void)std::remove(adminSavedPath.c_str());
    (void)std::remove(guestSavedPath.c_str());

    const Key128 key = testutil::testMasterKey(0x5A);

    // ---------------- 管理员客户端（期望：允许，文件落盘）----------------
    std::promise<std::uint16_t> adminPortPromise;
    auto adminPortFuture = adminPortPromise.get_future();
    SessionConfig adminServerConfig = testutil::makeServerConfig(0, key);
    adminServerConfig.onListening = [&adminPortPromise](std::uint16_t port) {
        adminPortPromise.set_value(port);
    };

    ServerResult adminServer;
    testutil::ThreadGuard adminServerThread(
        std::thread(runServer, adminServerConfig, kWorkDir + "/admin_out", &adminServer));
    const std::uint16_t adminPort = adminPortFuture.get();

    AesCryptoProvider adminCrypto(nullptr);
    SessionConfig adminClientConfig = testutil::makeClientConfig(adminPort, key);
    adminClientConfig.localId = "alice";  // 管理员身份
    SecureSession adminClient(adminCrypto, adminClientConfig);
    ST_CHECK(adminClient.connectToServer());

    const transfer::SendResult adminSent =
        transfer::FileSender::send(adminClient, sourcePath, transfer::Kind::kFile);
    ST_CHECK(adminSent.ok);
    MessageType replyType = MessageType::kError;
    Bytes reply;
    ST_CHECK(adminClient.receiveMessage(replyType, reply));
    ST_CHECK_EQ(bytesToString(reply).rfind("FILE OK", 0), 0u);
    ST_CHECK(adminClient.sendMessage(MessageType::kClose, Bytes{}));
    ST_CHECK(adminClient.receiveMessage(replyType, reply));
    adminClient.close();
    adminServerThread.join();

    ST_CHECK(adminServer.handshakeOk);
    ST_CHECK(adminServer.error.empty());
    ST_CHECK_EQ(adminServer.transfers.size(), 1u);
    ST_CHECK(adminServer.transfers[0].ok);
    ST_CHECK(fileExists(adminSavedPath));
    ST_CHECK(readFile(adminSavedPath) == payload);  // 管理员：文件正常落盘且字节一致
    ST_CHECK_EQ(adminServer.denied, 0u);

    // ---------------- 访客客户端（期望：拒绝，不落盘，会话继续）----------------
    std::promise<std::uint16_t> guestPortPromise;
    auto guestPortFuture = guestPortPromise.get_future();
    SessionConfig guestServerConfig = testutil::makeServerConfig(0, key);
    guestServerConfig.peerId = "mallory";  // 这次服务端接受的身份是访客
    guestServerConfig.onListening = [&guestPortPromise](std::uint16_t port) {
        guestPortPromise.set_value(port);
    };

    ServerResult guestServer;
    testutil::ThreadGuard guestServerThread(
        std::thread(runServer, guestServerConfig, kWorkDir + "/guest_out", &guestServer));
    const std::uint16_t guestPort = guestPortFuture.get();

    AesCryptoProvider guestCrypto(nullptr);
    SessionConfig guestClientConfig = testutil::makeClientConfig(guestPort, key);
    guestClientConfig.localId = "mallory";  // 访客身份
    SecureSession guestClient(guestCrypto, guestClientConfig);
    ST_CHECK(guestClient.connectToServer());

    // 1) 发文件：服务端必须拒绝
    const transfer::SendResult guestSent =
        transfer::FileSender::send(guestClient, sourcePath, transfer::Kind::kFile);
    ST_CHECK(guestSent.ok);  // 客户端本地发送成功（服务端才有权裁定）
    ST_CHECK(guestClient.receiveMessage(replyType, reply));
    ST_CHECK_EQ(bytesToString(reply).rfind("ACCESS DENIED", 0), 0u);

    // 2) 文件绝不能落盘
    ST_CHECK(!fileExists(guestSavedPath));

    // 3) 会话必须仍然可用：访客还能正常发短消息（对照：篡改/重放会断连）
    ST_CHECK(guestClient.sendMessage(MessageType::kData, stringToBytes("hello")));
    ST_CHECK(guestClient.receiveMessage(replyType, reply));
    ST_CHECK_EQ(bytesToString(reply), std::string("ACK"));

    ST_CHECK(guestClient.sendMessage(MessageType::kClose, Bytes{}));
    ST_CHECK(guestClient.receiveMessage(replyType, reply));
    guestClient.close();
    guestServerThread.join();

    ST_CHECK(guestServer.handshakeOk);
    ST_CHECK(guestServer.error.empty());
    ST_CHECK_EQ(guestServer.transfers.size(), 0u);  // 没有成功接收任何文件
    ST_CHECK_EQ(guestServer.denied, 1u);            // 文件请求被拒绝一次

    // 4) 审计记录：允许与拒绝都要留痕
    bool sawAllow = false;
    bool sawDeny = false;
    for (const std::string& line : guestServer.decisions) {
        if (line.find("ALLOW") != std::string::npos && line.find("mallory(guest)") != std::string::npos) {
            sawAllow = true;
        }
        if (line.find("DENY") != std::string::npos && line.find("send_file") != std::string::npos) {
            sawDeny = true;
        }
    }
    ST_CHECK(sawDeny);
    ST_CHECK(sawAllow);

    bool adminSawAllow = false;
    for (const std::string& line : adminServer.decisions) {
        if (line.find("ALLOW") != std::string::npos && line.find("alice(admin)") != std::string::npos &&
            line.find("send_file") != std::string::npos) {
            adminSawAllow = true;
        }
    }
    ST_CHECK(adminSawAllow);
}

int main() {
    return ::testutil::runAll("access_control");
}
