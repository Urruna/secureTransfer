// ============================================================================
//  SecureTransfer 测试 - 文件 / 图像安全传输端到端测试
//  file: tests/integration/test_file_transfer.cpp
//
//  真实 TCP + 完整握手 + 加密通道，覆盖三条路径：
//    1. 普通文件 -> 分块传输（FILE_START / FILE_CHUNK / FILE_END）
//    2. 小图像   -> 单包传输（IMAGE，元数据 + 数据同一包）
//    3. 大图像   -> 超单包上限，自动分块（起始包仍是 IMAGE，kind = 图像）
//  并验证接收端落盘文件的字节与 CRC32 都与源文件一致。
// ============================================================================

#include "secure_test_util.h"
#include "test_util.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <future>
#include <string>
#include <thread>
#include <vector>

#include "application/crc32.h"
#include "application/file_transfer.h"
#include "crypto/aes_crypto_provider.h"
#include "security/session.h"

namespace {

const std::string kWorkDir = testutil::workDir("st_file_transfer_test");

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

struct ServerResult {
    bool handshakeOk = false;
    bool finished = false;
    std::size_t textMessages = 0;
    std::vector<transfer::ReceiveResult> transfers;
    ProtocolStats stats;
    std::string error;
};

void runServer(SessionConfig config, std::string outDir, ServerResult* result) {
    AesCryptoProvider crypto(nullptr);
    SecureSession session(crypto, config);
    if (!session.acceptOneClient()) {
        result->error = session.lastError();
        return;
    }
    result->handshakeOk = true;

    transfer::TransferReceiver receiver(outDir);
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

        std::string transferError;
        if (receiver.handle(type, body, &transferError)) {
            if (receiver.inProgress()) {
                continue;
            }
            const transfer::ReceiveResult& done = receiver.lastResult();
            result->transfers.push_back(done);
            const std::string ack =
                done.ok ? "FILE OK " + done.fileName : "FILE FAILED " + done.error;
            if (!session.sendMessage(MessageType::kData, stringToBytes(ack))) {
                result->error = session.lastError();
                break;
            }
            continue;
        }

        ++result->textMessages;
        if (!session.sendMessage(MessageType::kData, stringToBytes("ACK"))) {
            result->error = session.lastError();
            break;
        }
    }

    result->stats = session.stats();
    session.close();
}

/// 客户端侧：发送一个文件 / 图像，并等待服务端确认。
void sendOne(SecureSession& session, const std::string& path, transfer::Kind kind,
             bool expectSingleShot, transfer::SendResult* out) {
    const transfer::SendResult sent = transfer::FileSender::send(session, path, kind);
    *out = sent;
    ST_CHECK(sent.ok);
    ST_CHECK_EQ(sent.singleShot, expectSingleShot);

    MessageType type = MessageType::kError;
    Bytes reply;
    ST_CHECK(session.receiveMessage(type, reply));
    ST_CHECK_EQ(bytesToString(reply).rfind("FILE OK", 0), 0u);
}

}  // namespace

ST_TEST_CASE("file_transfer: 文本 + 文件 + 小图像 + 大图像端到端") {
    ensureDir(kWorkDir);
    ensureDir(kWorkDir + "/out");

    // 准备实验数据：300 KB 文件 / 40 KB 小图像 / 2 MB 大图像
    const Bytes fileData = makeData(300u * 1024u + 13u, 0xC0FFEE);
    const Bytes smallImage = makeData(40u * 1024u, 0xBEEF);
    const Bytes bigImage = makeData(2u * 1024u * 1024u + 5u, 0xFEED);
    const std::string filePath = writeFile(kWorkDir + "/src_file.bin", fileData);
    const std::string smallPath = writeFile(kWorkDir + "/src_small.png", smallImage);
    const std::string bigPath = writeFile(kWorkDir + "/src_big.png", bigImage);

    std::promise<std::uint16_t> portPromise;
    auto portFuture = portPromise.get_future();
    const Key128 key = testutil::testMasterKey(0xAB);
    SessionConfig serverConfig = testutil::makeServerConfig(0, key);
    serverConfig.onListening = [&portPromise](std::uint16_t port) {
        portPromise.set_value(port);
    };

    ServerResult server;
    testutil::ThreadGuard serverThread(
        std::thread(runServer, serverConfig, kWorkDir + "/out", &server));
    const std::uint16_t port = portFuture.get();

    AesCryptoProvider crypto(nullptr);
    SecureSession client(crypto, testutil::makeClientConfig(port, key));
    ST_CHECK(client.connectToServer());

    // 1. 普通文本消息
    ST_CHECK(client.sendMessage(MessageType::kData, stringToBytes("hello")));
    MessageType type = MessageType::kError;
    Bytes reply;
    ST_CHECK(client.receiveMessage(type, reply));
    ST_CHECK_EQ(bytesToString(reply), std::string("ACK"));

    // 2. 普通文件 -> 分块传输
    transfer::SendResult fileSent;
    sendOne(client, filePath, transfer::Kind::kFile, false, &fileSent);
    ST_CHECK_EQ(fileSent.bytes, fileData.size());
    ST_CHECK_EQ(fileSent.crc32, Crc32::compute(fileData));
    ST_CHECK_EQ(fileSent.chunks,
                (fileData.size() + transfer::kChunkSize - 1) / transfer::kChunkSize);

    // 3. 小图像 -> 单包（IMAGE）
    transfer::SendResult smallSent;
    sendOne(client, smallPath, transfer::Kind::kImage, true, &smallSent);
    ST_CHECK_EQ(smallSent.chunks, 0u);

    // 4. 大图像 -> 超过单包上限，自动分块（起始包仍是 IMAGE）
    transfer::SendResult bigSent;
    sendOne(client, bigPath, transfer::Kind::kImage, false, &bigSent);
    ST_CHECK(bigSent.chunks > 0);

    // 5. 结束会话
    ST_CHECK(client.sendMessage(MessageType::kClose, Bytes{}));
    ST_CHECK(client.receiveMessage(type, reply));
    ST_CHECK_EQ(bytesToString(reply), std::string("BYE"));
    client.close();
    serverThread.join();

    // ---- 服务端侧断言 ----
    ST_CHECK(server.handshakeOk);
    ST_CHECK(server.finished);
    ST_CHECK(server.error.empty());
    ST_CHECK_EQ(server.textMessages, 1u);
    ST_CHECK_EQ(server.transfers.size(), 3u);

    const transfer::ReceiveResult& fileGot = server.transfers[0];
    ST_CHECK(fileGot.ok);
    ST_CHECK_EQ(fileGot.fileName, std::string("src_file.bin"));
    ST_CHECK_EQ(fileGot.bytes, fileData.size());
    ST_CHECK_EQ(fileGot.crc32, Crc32::compute(fileData));
    ST_CHECK(readFile(fileGot.savedPath) == fileData);

    const transfer::ReceiveResult& smallGot = server.transfers[1];
    ST_CHECK(smallGot.ok);
    ST_CHECK(smallGot.singleShot);
    ST_CHECK(readFile(smallGot.savedPath) == smallImage);

    const transfer::ReceiveResult& bigGot = server.transfers[2];
    ST_CHECK(bigGot.ok);
    ST_CHECK(!bigGot.singleShot);
    ST_CHECK_EQ(bigGot.bytes, bigImage.size());
    ST_CHECK(readFile(bigGot.savedPath) == bigImage);

    ST_CHECK_EQ(server.stats.rejectedMac, 0u);
    ST_CHECK_EQ(server.stats.rejectedReplay, 0u);
}

int main() {
    return ::testutil::runAll("file_transfer");
}
