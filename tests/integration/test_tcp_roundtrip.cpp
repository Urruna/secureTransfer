// ============================================================================
//  SecureTransfer 测试
//  file: tests/integration/test_tcp_roundtrip.cpp
//
//  说明：Alice <-> Bob 的完整 TCP 往返测试，覆盖：
//          - 多条消息顺序收发
//          - 连续发送大量小 Frame（验证粘包处理）
//          - 1 MB 大 Frame（验证拆包处理）
//          - 对端关闭连接
//          - 单连接服务端顺序服务多个客户端
//        服务端运行在独立线程中，客户端在主线程中，是真实的 TCP loopback 通信。
// ============================================================================

#include "test_util.h"

#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "network/network.h"

namespace {

constexpr int kTestTimeoutMs = 10000;

using Bytes = std::vector<uint8_t>;

/// 生成一段可校验的测试数据。
Bytes makePattern(std::size_t size, uint8_t seed) {
    Bytes data(size);
    for (std::size_t index = 0; index < size; ++index) {
        data[index] = static_cast<uint8_t>((index * 31u + seed) & 0xFFu);
    }
    return data;
}

/// 在子线程中运行的简单服务端。监听在主线程完成，端口通过 port 传递。
struct TestServer {
    Network network;
    uint16_t port = 0;
    std::string failure;
    std::thread worker;

    bool start() {
        return network.listen(0);
    }

    void run(std::function<void(Network&, std::string&)> handler) {
        port = network.boundPort();
        worker = std::thread([this, handler]() {
            if (!network.accept()) {
                failure = "server accept() 失败: " + network.lastError();
                return;
            }
            handler(network, failure);
        });
    }

    void join() {
        if (worker.joinable()) {
            worker.join();
        }
    }
};

}  // namespace

ST_TEST_CASE("Alice/Bob: 三条消息顺序往返") {
    TestServer server;
    ST_CHECK(server.start());

    const std::vector<std::string> requests = {
        "Hello Bob", "Secure Transfer", "Test Message 3"};
    const std::vector<std::string> expectedReplies = {
        "echo:Hello Bob", "echo:Secure Transfer", "echo:Test Message 3"};

    server.run([&requests, &expectedReplies](Network& network, std::string& failure) {
        for (std::size_t index = 0; index < requests.size(); ++index) {
            Frame incoming;
            if (!network.receiveFrame(incoming)) {
                failure = "server receiveFrame() 第 " + std::to_string(index + 1) +
                          " 条失败: " + network.lastError();
                return;
            }
            if (incoming.toString() != requests[index]) {
                failure = "server 收到的第 " + std::to_string(index + 1) +
                          " 条消息内容不符: " + incoming.toString();
                return;
            }
            if (!network.sendFrame(Frame::fromString(expectedReplies[index]))) {
                failure = "server sendFrame() 第 " + std::to_string(index + 1) +
                          " 条失败: " + network.lastError();
                return;
            }
        }
        network.close();
    });

    Network client;
    ST_CHECK(client.connect("127.0.0.1", server.port));
    ST_CHECK(client.setReceiveTimeoutMs(kTestTimeoutMs));

    for (std::size_t index = 0; index < requests.size(); ++index) {
        ST_CHECK(client.sendFrame(Frame::fromString(requests[index])));

        Frame reply;
        ST_CHECK(client.receiveFrame(reply));
        ST_CHECK_EQ(reply.toString(), expectedReplies[index]);
    }
    client.close();
    server.join();

    ST_CHECK_EQ(server.failure, std::string());
}

ST_TEST_CASE("Alice/Bob: 连续 200 个小 Frame（粘包处理）") {
    constexpr int kFrameCount = 200;

    TestServer server;
    ST_CHECK(server.start());

    server.run([kFrameCount](Network& network, std::string& failure) {
        for (int index = 0; index < kFrameCount; ++index) {
            const Frame frame = Frame::fromString("frame-" + std::to_string(index));
            if (!network.sendFrame(frame)) {
                failure = "server sendFrame() 第 " + std::to_string(index) +
                          " 个失败: " + network.lastError();
                return;
            }
        }
        network.close();
    });

    Network client;
    ST_CHECK(client.connect("127.0.0.1", server.port));
    ST_CHECK(client.setReceiveTimeoutMs(kTestTimeoutMs));

    for (int index = 0; index < kFrameCount; ++index) {
        Frame frame;
        ST_CHECK(client.receiveFrame(frame));
        ST_CHECK_EQ(frame.toString(), std::string("frame-" + std::to_string(index)));
    }
    client.close();
    server.join();

    ST_CHECK_EQ(server.failure, std::string());
}

ST_TEST_CASE("Alice/Bob: 1 MB 大 Frame 完整传输（拆包处理）") {
    const Bytes bigPayload = makePattern(Frame::kMaxPayloadSize, 11);

    TestServer server;
    ST_CHECK(server.start());

    server.run([&bigPayload](Network& network, std::string& failure) {
        if (!network.setReceiveTimeoutMs(kTestTimeoutMs)) {
            failure = "server setReceiveTimeoutMs() 失败: " + network.lastError();
            return;
        }

        Frame incoming;
        if (!network.receiveFrame(incoming)) {
            failure = "server receiveFrame() 失败: " + network.lastError();
            return;
        }
        if (incoming.payload.size() != Frame::kMaxPayloadSize) {
            failure = "server 收到的 payload 长度不符: " +
                      std::to_string(incoming.payload.size());
            return;
        }
        if (incoming.payload != bigPayload) {
            failure = "server 收到的 payload 内容与发送方不一致";
            return;
        }

        // 回复一个短的确认消息
        std::string reply = "received " + std::to_string(incoming.payload.size()) + " bytes";
        if (!network.sendFrame(Frame::fromString(reply))) {
            failure = "server sendFrame() 失败: " + network.lastError();
            return;
        }
        network.close();
    });

    Network client;
    ST_CHECK(client.connect("127.0.0.1", server.port));
    ST_CHECK(client.setReceiveTimeoutMs(kTestTimeoutMs));

    const Frame bigFrame = Frame::fromBytes(bigPayload);
    ST_CHECK(bigFrame.isValid());
    ST_CHECK(client.sendFrame(bigFrame));

    Frame reply;
    ST_CHECK(client.receiveFrame(reply));
    ST_CHECK_EQ(reply.toString(),
                std::string("received " + std::to_string(Frame::kMaxPayloadSize) + " bytes"));

    client.close();
    server.join();
    ST_CHECK_EQ(server.failure, std::string());
}

ST_TEST_CASE("Alice/Bob: 对端关闭连接后 receiveFrame 返回 PEER_CLOSED") {
    TestServer server;
    ST_CHECK(server.start());

    // 服务端接受连接后立即关闭，不再发送任何数据。
    server.run([](Network& network, std::string&) {
        network.close();
    });

    Network client;
    ST_CHECK(client.connect("127.0.0.1", server.port));
    ST_CHECK(client.setReceiveTimeoutMs(kTestTimeoutMs));

    Frame frame;
    ST_CHECK(!client.receiveFrame(frame));
    ST_CHECK(client.lastResult() == Network::Result::PEER_CLOSED);

    client.close();
    server.join();
}

ST_TEST_CASE("Alice/Bob: 服务端按顺序服务两个客户端") {
    TestServer server;
    ST_CHECK(server.start());

    server.run([](Network& network, std::string& failure) {
        const std::string replies[] = {"reply-1", "reply-2"};

        for (int round = 0; round < 2; ++round) {
            // 第二轮调用 accept() 时会先关闭上一轮已结束的连接。
            if (round > 0 && !network.accept()) {
                failure = "server 第 2 次 accept() 失败: " + network.lastError();
                return;
            }

            Frame incoming;
            if (!network.receiveFrame(incoming)) {
                failure = "server 第 " + std::to_string(round + 1) +
                          " 轮 receiveFrame() 失败: " + network.lastError();
                return;
            }
            if (!network.sendFrame(Frame::fromString(replies[round]))) {
                failure = "server 第 " + std::to_string(round + 1) +
                          " 轮 sendFrame() 失败: " + network.lastError();
                return;
            }
        }
        network.close();
    });

    for (int round = 0; round < 2; ++round) {
        Network client;
        ST_CHECK(client.connect("127.0.0.1", server.port));
        ST_CHECK(client.setReceiveTimeoutMs(kTestTimeoutMs));
        ST_CHECK(client.sendFrame(Frame::fromString("message-" + std::to_string(round + 1))));

        Frame reply;
        ST_CHECK(client.receiveFrame(reply));
        ST_CHECK_EQ(reply.toString(), std::string("reply-" + std::to_string(round + 1)));
        client.close();
    }

    server.join();
    ST_CHECK_EQ(server.failure, std::string());
}

int main() {
    return ::testutil::runAll("integration");
}
