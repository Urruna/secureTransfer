// ============================================================================
//  SecureTransfer 测试
//  file: tests/secure_test_util.h
//
//  说明：第二部分测试的公共辅助函数（端口分配、测试用 K_master、会话配置）。
//        只用于测试，不参与正式程序构建。
// ============================================================================

#ifndef SECURETRANSFER_TESTS_SECURE_TEST_UTIL_H
#define SECURETRANSFER_TESTS_SECURE_TEST_UTIL_H

#include <cstdint>
#include <string>
#include <thread>
#include <utility>

#include "common/types.h"
#include "network/network.h"
#include "security/session.h"

namespace testutil {

/// 保证线程一定被 join，即使测试中途断言失败也不会 std::terminate。
class ThreadGuard {
public:
    explicit ThreadGuard(std::thread thread) : thread_(std::move(thread)) {}

    ~ThreadGuard() {
        join();
    }

    ThreadGuard(const ThreadGuard&) = delete;
    ThreadGuard& operator=(const ThreadGuard&) = delete;

    void join() {
        if (thread_.joinable()) {
            thread_.join();
        }
    }

private:
    std::thread thread_;
};

/// 构造测试用的 K_master（每个 seed 得到一把固定的 16 字节密钥）。
inline Key128 testMasterKey(Byte seed) {
    Key128 key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<Byte>(seed + i * 7 + 1);
    }
    return key;
}

/// 服务端配置：port 传 0 表示由系统分配端口，
/// 真实端口通过 onListening 回调拿到（避免客户端早于服务端 listen）。
inline SessionConfig makeServerConfig(std::uint16_t port, const Key128& masterKey) {
    SessionConfig config;
    config.localId = "bob";
    config.peerId = "alice";
    config.host = "127.0.0.1";
    config.port = port;
    config.masterKey = masterKey;
    config.hasMasterKey = true;
    config.handshakeTimeoutMs = 3000;
    config.ioTimeoutMs = 3000;
    config.logHandshake = false;
    return config;
}

inline SessionConfig makeClientConfig(std::uint16_t port, const Key128& masterKey) {
    SessionConfig config;
    config.localId = "alice";
    config.peerId = "bob";
    config.host = "127.0.0.1";
    config.port = port;
    config.masterKey = masterKey;
    config.hasMasterKey = true;
    config.handshakeTimeoutMs = 3000;
    config.ioTimeoutMs = 3000;
    config.logHandshake = false;
    return config;
}

/// 把 Bytes 当作文本返回，便于比较。
inline std::string asText(const Bytes& data) {
    return bytesToString(data);
}

}  // namespace testutil

#endif  // SECURETRANSFER_TESTS_SECURE_TEST_UTIL_H
