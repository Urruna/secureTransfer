// ============================================================================
//  SecureTransfer 测试
//  file: tests/unit/test_network.cpp
//
//  说明：Network 类的错误处理与边界情况测试。这些用例使用真实的 TCP
//        loopback 连接，而不是模拟通信。
// ============================================================================

#include "raw_client.h"
#include "test_util.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "network/network.h"

ST_TEST_CASE("Network: 未建立连接时 sendFrame/receiveFrame/accept 都会失败") {
    Network network;
    const Frame frame = Frame::fromString("data");

    ST_CHECK(!network.sendFrame(frame));
    ST_CHECK(network.lastResult() == Network::Result::NOT_CONNECTED);
    ST_CHECK(!network.lastError().empty());

    Frame incoming;
    ST_CHECK(!network.receiveFrame(incoming));
    ST_CHECK(network.lastResult() == Network::Result::NOT_CONNECTED);

    ST_CHECK(!network.accept());
    ST_CHECK(network.lastResult() == Network::Result::NOT_CONNECTED);

    ST_CHECK(!network.isConnected());
    ST_CHECK(!network.isListening());
}

ST_TEST_CASE("Network: connect 到没有监听的端口会失败而不是崩溃") {
    Network network;

    ST_CHECK(!network.connect("127.0.0.1", 1));
    ST_CHECK(network.lastResult() == Network::Result::SOCKET_FAILURE);
    ST_CHECK(!network.lastError().empty());
    ST_CHECK(!network.isConnected());
}

ST_TEST_CASE("Network: 非法参数会被拒绝") {
    Network network;

    ST_CHECK(!network.connect("", 9000));
    ST_CHECK(network.lastResult() == Network::Result::INVALID_ARGUMENT);

    ST_CHECK(!network.connect("127.0.0.1", 0));
    ST_CHECK(network.lastResult() == Network::Result::INVALID_ARGUMENT);
}

ST_TEST_CASE("Network: listen(0) 由系统分配端口，并能完成一次真实往返") {
    Network server;
    ST_CHECK(server.listen(0));
    ST_CHECK(server.isListening());
    ST_CHECK(!server.isConnected());

    const uint16_t port = server.boundPort();
    ST_CHECK(port != 0);

    Network client;
    ST_CHECK(client.connect("127.0.0.1", port));
    ST_CHECK(client.isConnected());
    ST_CHECK(server.accept());
    ST_CHECK(server.isConnected());

    ST_CHECK(client.sendFrame(Frame::fromString("ping")));

    Frame request;
    ST_CHECK(server.receiveFrame(request));
    ST_CHECK_EQ(request.toString(), std::string("ping"));

    ST_CHECK(server.sendFrame(Frame::fromString("pong")));

    Frame reply;
    ST_CHECK(client.receiveFrame(reply));
    ST_CHECK_EQ(reply.toString(), std::string("pong"));

    server.close();
    client.close();
    ST_CHECK(!server.isConnected());
    ST_CHECK(!server.isListening());

    // close() 可以重复调用
    server.close();
    client.close();
}

ST_TEST_CASE("Network: 非法的 length 前缀会被拒绝，且不会尝试分配大量内存") {
    Network server;
    ST_CHECK(server.listen(0));
    const uint16_t port = server.boundPort();

    testutil::RawClient malicious;
    ST_CHECK(malicious.connectTo(port));
    ST_CHECK(server.accept());
    ST_CHECK(server.setReceiveTimeoutMs(5000));

    // length = 0x7FFFFFFF（约 2 GB）：实现必须先检查长度再分配内存
    const std::vector<uint8_t> header = {0x7F, 0xFF, 0xFF, 0xFF};
    ST_CHECK(malicious.sendBytes(header));

    Frame frame;
    ST_CHECK(!server.receiveFrame(frame));
    ST_CHECK(server.lastResult() == Network::Result::INVALID_FRAME);
    ST_CHECK(!server.lastError().empty());
}

ST_TEST_CASE("Network: 对端在 payload 中途断开时返回 PEER_CLOSED") {
    Network server;
    ST_CHECK(server.listen(0));
    const uint16_t port = server.boundPort();

    testutil::RawClient malicious;
    ST_CHECK(malicious.connectTo(port));
    ST_CHECK(server.accept());
    ST_CHECK(server.setReceiveTimeoutMs(5000));

    // 声称 payload 有 100 字节，实际只发送 10 字节就断开连接
    std::vector<uint8_t> partial = {0x00, 0x00, 0x00, 0x64};
    for (int index = 0; index < 10; ++index) {
        partial.push_back(0x41);
    }
    ST_CHECK(malicious.sendBytes(partial));
    malicious.closeNow();

    Frame frame;
    ST_CHECK(!server.receiveFrame(frame));
    ST_CHECK(server.lastResult() == Network::Result::PEER_CLOSED);
}

ST_TEST_CASE("Network: 对端立即关闭连接时 receiveFrame 返回 PEER_CLOSED") {
    Network server;
    ST_CHECK(server.listen(0));
    const uint16_t port = server.boundPort();

    testutil::RawClient client;
    ST_CHECK(client.connectTo(port));
    ST_CHECK(server.accept());
    ST_CHECK(server.setReceiveTimeoutMs(5000));
    client.closeNow();

    Frame frame;
    ST_CHECK(!server.receiveFrame(frame));
    ST_CHECK(server.lastResult() == Network::Result::PEER_CLOSED);
}

ST_TEST_CASE("Network: 接收超时设置生效（不会永久阻塞）") {
    Network server;
    ST_CHECK(server.listen(0));
    const uint16_t port = server.boundPort();

    Network client;
    ST_CHECK(client.connect("127.0.0.1", port));
    ST_CHECK(server.accept());
    ST_CHECK(server.setReceiveTimeoutMs(300));

    const auto start = std::chrono::steady_clock::now();
    Frame frame;
    ST_CHECK(!server.receiveFrame(frame));
    const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - start)
                               .count();

    ST_CHECK(server.lastResult() == Network::Result::TIMEOUT);
    ST_CHECK(elapsedMs < 5000);
}

ST_TEST_CASE("Network: 超大或非法的 Frame 会被拒绝，且不影响后续通信") {
    Network server;
    ST_CHECK(server.listen(0));
    const uint16_t port = server.boundPort();

    Network client;
    ST_CHECK(client.connect("127.0.0.1", port));
    ST_CHECK(server.accept());

    // 1) payload 超过 1 MB
    Frame tooBig;
    tooBig.payload.assign(Frame::kMaxPayloadSize + 1, 0x41);
    tooBig.length = static_cast<uint32_t>(tooBig.payload.size());
    ST_CHECK(!client.sendFrame(tooBig));
    ST_CHECK(client.lastResult() == Network::Result::INVALID_FRAME);

    // 2) length 与 payload 不一致
    const Frame mismatched(10, std::vector<uint8_t>(3, 0x42));
    ST_CHECK(!client.sendFrame(mismatched));
    ST_CHECK(client.lastResult() == Network::Result::INVALID_FRAME);

    // 3) 上面两次失败都不应该把 TCP 字节流搞乱
    ST_CHECK(client.sendFrame(Frame::fromString("still alive")));

    Frame received;
    ST_CHECK(server.receiveFrame(received));
    ST_CHECK_EQ(received.toString(), std::string("still alive"));
}

ST_TEST_CASE("Network: Linux 上同一端口重复 listen 会失败") {
#if defined(_WIN32)
    // 平台差异：Windows 的 SO_REUSEADDR 语义与 POSIX 不同——它允许第二个 socket
    // 绑定到已经被监听的端口，因此这里无法断言“重复 listen 必定失败”。
    // 项目当前在 Windows 上沿用 SO_REUSEADDR（保证服务端重启后能立刻重新绑定端口），
    // 该差异记录在 Part2_transfer.md 的“平台差异”一节。
    Network first;
    ST_CHECK(first.listen(0));
    ST_CHECK(first.isListening());
#else
    Network first;
    ST_CHECK(first.listen(0));
    const uint16_t port = first.boundPort();

    Network second;
    ST_CHECK(!second.listen(port));
    ST_CHECK(second.lastResult() == Network::Result::SOCKET_FAILURE);
#endif
}

ST_TEST_CASE("Network: waitReadable 用于非阻塞探测（无数据=超时，有数据=立即可读）") {
    Network server;
    ST_CHECK(server.listen(0));
    const uint16_t port = server.boundPort();

    Network client;
    ST_CHECK(client.connect("127.0.0.1", port));
    ST_CHECK(server.accept());

    // ① 还没有数据：返回 TIMEOUT，且不被当作错误（lastResult 保持 OK、没有错误文本）
    ST_CHECK(server.waitReadable(50) == Network::WaitResult::kTimeout);
    ST_CHECK(server.lastResult() == Network::Result::OK);
    ST_CHECK(server.lastError().empty());

    // ② 对端发来数据：探测立即返回可读，随后可以正常读出完整 Frame
    ST_CHECK(client.sendFrame(Frame::fromString("ping")));
    ST_CHECK(server.waitReadable(2000) == Network::WaitResult::kReadable);
    Frame frame;
    ST_CHECK(server.receiveFrame(frame));
    ST_CHECK_EQ(frame.toString(), std::string("ping"));

    // ③ 读完之后又变回"没有数据"
    ST_CHECK(server.waitReadable(50) == Network::WaitResult::kTimeout);

    // ④ 对端关闭连接：探测仍然报"可读"（EOF），此时 receiveFrame 会得到 PEER_CLOSED
    client.close();
    ST_CHECK(server.waitReadable(2000) == Network::WaitResult::kReadable);
    Frame closedFrame;
    ST_CHECK(!server.receiveFrame(closedFrame));
    ST_CHECK(server.lastResult() == Network::Result::PEER_CLOSED);

    // ⑤ 没有连接时探测要明确报错，而不是假装"暂时没数据"
    Network fresh;
    ST_CHECK(fresh.waitReadable(0) == Network::WaitResult::kError);
    ST_CHECK(!fresh.lastError().empty());
}

int main() {
    return ::testutil::runAll("network");
}
