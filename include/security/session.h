// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/security/session.h
//
//  说明：第二部分对外提供的唯一门面。上半层的 UI / 短消息 / 文件 / 图像
//        只需要认识这个类，不需要了解 Frame、Packet、握手细节。
//
//  典型用法：
//
//      服务端 (Bob)                        客户端 (Alice)
//      ------------------------------      ------------------------------
//      SecureSession s(crypto, cfg);       SecureSession s(crypto, cfg);
//      s.acceptOneClient();                s.connectToServer();
//      s.receiveMessage(type, data);       s.sendMessage(kData, data);
//      s.sendMessage(kData, reply);        s.receiveMessage(type, data);
//      s.close();                          s.close();
//
//  一次会话内：身份认证（K_master）→ 会话密钥分发（K_session）→
//              数据加密（AES-CTR）→ 完整性（MAC）→ 防重放（Sequence）。
// ============================================================================

#ifndef SECURETRANSFER_SECURITY_SESSION_H
#define SECURETRANSFER_SECURITY_SESSION_H

#include <cstdint>
#include <functional>
#include <string>

#include "common/random.h"
#include "common/types.h"
#include "crypto/crypto_provider.h"
#include "network/network.h"
#include "protocol/message_type.h"
#include "protocol/packet.h"
#include "security/replay_guard.h"

/// 会话状态机。
enum class SessionState {
    kDisconnected,    ///< 尚未建立 TCP 连接
    kTcpConnected,    ///< TCP 已连接，握手尚未完成
    kAuthenticating,  ///< HELLO / AUTH 阶段
    kKeyExchange,     ///< KEY_REQUEST / KEY_EXCHANGE / KEY_CONFIRM 阶段
    kEstablished,     ///< 握手完成，可收发业务数据
    kClosing,         ///< 正在关闭
    kFailed           ///< 握手或协议出错
};

const char* sessionStateToString(SessionState state);

struct SessionConfig {
    std::string localId;                 ///< 本端身份，例如 "alice"
    std::string peerId;                  ///< 期望的对端身份，例如 "bob"
    std::string host = "127.0.0.1";      ///< 客户端使用
    std::uint16_t port = 9000;           ///< 服务端监听 / 客户端连接端口
    Key128 masterKey{};                  ///< 长期认证密钥 K_master
    bool hasMasterKey = false;
    int handshakeTimeoutMs = 5000;       ///< 握手阶段超时
    int ioTimeoutMs = 10000;             ///< 数据阶段超时
    bool logHandshake = true;            ///< 是否打印握手每一步

    /// 服务端开始监听后的回调，参数是**实际**绑定的端口。
    /// 用途：port == 0 时（由系统分配端口）把真实端口告诉我们，
    ///       测试与演示可以据此避免"客户端早于服务端 listen"的竞态。
    std::function<void(std::uint16_t)> onListening;
};

/// 会话统计，供报告的"传输状态""攻击测试"章节引用。
struct ProtocolStats {
    std::uint64_t sentPackets = 0;
    std::uint64_t receivedPackets = 0;
    std::uint64_t sentBytes = 0;
    std::uint64_t receivedBytes = 0;
    std::uint64_t rejectedFormat = 0;  ///< 格式 / 版本 / SessionId / 方向非法
    std::uint64_t rejectedReplay = 0;  ///< 重放
    std::uint64_t rejectedMac = 0;     ///< 完整性校验失败
    std::uint64_t rejectedState = 0;   ///< 状态机不允许的操作
    std::uint64_t handshakesOk = 0;
    std::uint64_t handshakesFailed = 0;

    /// 单行摘要，便于打印与写进测试报告。
    std::string summary() const;
};

/// 单个数据包的可观测信息，用于演示输出与测试报告
/// （课程要求记录：明文 → 密文 → CMAC → 接收方解密结果 → 完整性验证结果）。
struct PacketTrace {
    bool valid = false;
    MessageType type = MessageType::kError;
    std::uint64_t sequence = 0;
    Nonce nonce{};
    Bytes ciphertext;  ///< 加密后的 Body（握手包为空）
    MacTag mac{};
};

class SecureSession {
public:
    SecureSession(CryptoProvider& crypto,
                  const SessionConfig& config,
                  RandomSource& random = RandomSource::system());
    ~SecureSession();

    SecureSession(const SecureSession&) = delete;
    SecureSession& operator=(const SecureSession&) = delete;

    /// 客户端：TCP connect + 完整握手。返回 true 时 state() == kEstablished。
    bool connectToServer();

    /// 服务端：listen + accept + 完整握手。
    ///
    /// @param clientWaitMs 等待客户端接入的最长时间（毫秒）：
    ///        * `< 0`：一直等待（命令行 Bob 的默认行为，与旧版一致）；
    ///        * `>= 0`：最多等这么久。超时返回 false，但 **监听 socket 仍然有效**，
    ///          可以再次调用（超时原因见 lastAcceptTimedOut()）。
    ///          图形界面用它实现"等待客户端时也能点断开"。
    bool acceptOneClient(int clientWaitMs = -1);

    /// 最近一次 acceptOneClient(waitMs >= 0) 是否是"等待客户端超时"（可以重试），
    /// 而不是真正的失败（端口被占用 / socket 错误等）。
    bool lastAcceptTimedOut() const { return acceptTimedOut_; }

    /// 发送业务数据（短消息 / 文件分块 / 图像都用它）。
    /// 内部：Nonce → AES-CTR 加密 → MAC(头部 + 密文) → sendFrame。
    bool sendMessage(MessageType type, const Bytes& plaintext);

    /// 接收业务数据。返回 false 时 lastError() 给出原因；
    /// 若对端发送 kClose，则返回 true 且 type == kClose（plaintext 为空）。
    bool receiveMessage(MessageType& type, Bytes& plaintext);

    /// tryReceiveMessage() 的结果：把"暂时没有数据"与"会话结束/出错"区分开。
    enum class ReceiveStatus {
        kMessage,  ///< 收到一条完整消息（type / plaintext 有效）
        kNothing,  ///< 在等待时间内没有数据到达（不是错误，lastError() 保持不变）
        kClosed    ///< 会话不可继续（对端关闭 / 协议错误 / socket 错误），原因见 lastError()
    };

    /// 非阻塞（最多等待 waitMs 毫秒）地尝试接收一条业务消息。
    ///
    /// 与 receiveMessage() 的区别：
    ///   1. "暂时没有数据"不再是失败，也不会打印错误日志（返回 kNothing）；
    ///   2. 内部用 select() 等待可读，数据一到就立刻返回，
    ///      因此调用方的消息延迟不受"sleep + 超时"式轮询的间隔限制。
    ///
    /// 典型用法（图形界面工作线程）：
    ///     auto status = session.tryReceiveMessage(type, body, 100);
    ///     if (status == kNothing) { /* 处理本线程的其它任务，然后重试 */ }
    ReceiveStatus tryReceiveMessage(MessageType& type, Bytes& plaintext, int waitMs = 0);

    /// 主动结束会话：发送 kClose（尽力而为）并关闭连接。
    void close();

    // ------------------------------ 诊断接口 ------------------------------
    SessionState state() const { return state_; }
    bool isEstablished() const { return state_ == SessionState::kEstablished; }
    const SessionId& sessionId() const { return sessionId_; }
    const ProtocolStats& stats() const { return stats_; }
    const std::string& lastError() const { return lastError_; }
    std::uint16_t listeningPort() const { return network_.boundPort(); }

    /// MAC 是否具备密码学强度（CMAC 未交付时为 false）。
    bool macIsCryptographicallySecure() const { return crypto_.macIsCryptographicallySecure(); }

    /// 握手使用的两个 Nonce（仅用于演示与测试输出，不是密钥）。
    const Nonce& nonceA() const { return nonceA_; }
    const Nonce& nonceB() const { return nonceB_; }

    /// 发送 / 接收方向的当前序号。
    std::uint64_t sendSequence() const { return sendSequence_; }
    std::uint64_t receiveSequence() const { return replayGuard_.lastSequence(); }

    /// 最近一次发送 / 接收的数据包信息（用于报告与界面显示）。
    const PacketTrace& lastSentTrace() const { return lastSentTrace_; }
    const PacketTrace& lastReceivedTrace() const { return lastReceivedTrace_; }

    // ------------------- 测试 / 攻击演示专用接口 -------------------
    // 下面两个接口只用于单元测试、集成测试与第三部分的 Eve 演示：
    // 允许测试代码绕过加密与 MAC，直接收发一段原始字节，
    // 从而构造“篡改包”“重放包”。正式业务代码不应调用它们。

    /// 直接发送一段原始字节（绕过加密与完整性处理）。
    bool sendRawWireForTesting(const Bytes& wire);

    /// 最近一次真正写进 socket 的原始字节（可用于重放、篡改、抓包分析）。
    const Bytes& lastSentWireForTesting() const { return lastSentWire_; }

private:
    bool handshakeAsClient();
    bool handshakeAsServer();

    bool recvPacket(Packet& packet, const char* stage);
    bool sendHandshakePacket(MessageType type, const Nonce& nonce, const Bytes& body,
                             const MacTag& tag);
    bool sendWire(const Bytes& wire);

    bool deriveSessionKeys();
    Nonce makeNonce(const Bytes& prefix, std::uint64_t counter) const;
    Direction outgoingDirection() const;
    Direction incomingDirection() const;
    const Bytes& outgoingPrefix() const;

    bool fail(const std::string& reason);
    bool failHandshake(const std::string& reason);
    bool protocolViolation(const std::string& reason);
    void logHandshakeStep(const std::string& message) const;

    Network network_;
    CryptoProvider& crypto_;
    SessionConfig config_;
    RandomSource& random_;

    SessionState state_ = SessionState::kDisconnected;
    bool isServer_ = false;
    bool sessionIdKnown_ = false;
    SessionId sessionId_{};
    Nonce nonceA_{};
    Nonce nonceB_{};
    Key128 sessionKey_{};
    Key128 encKey_{};
    Key128 macKey_{};
    Bytes prefixC2S_;
    Bytes prefixS2C_;
    std::uint64_t sendSequence_ = 0;
    bool acceptTimedOut_ = false;
    ReplayGuard replayGuard_;
    ProtocolStats stats_;
    std::string lastError_;
    PacketTrace lastSentTrace_;
    PacketTrace lastReceivedTrace_;
    Bytes lastSentWire_;
};

#endif  // SECURETRANSFER_SECURITY_SESSION_H
