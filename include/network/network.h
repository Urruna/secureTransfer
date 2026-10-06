// ============================================================================
//  SecureTransfer - 第一阶段：基础 TCP 通信
//  file: include/network/network.h
//
//  说明：Network 是网络通信模块对外的唯一接口。
//        接口签名由项目组统一约定（connect / listen / accept /
//        sendFrame / receiveFrame / close），请不要随意修改。
//
//  设计目标：
//    1. 隐藏 POSIX Socket 细节，上层只面对 Frame；
//    2. 保证 sendFrame()/receiveFrame() 每次处理的是一个完整 Frame，
//       在内部正确处理 TCP 的粘包 / 拆包（partial send / partial recv）；
//    3. 为后续 AES / CMAC / 安全协议预留扩展空间：
//       安全层只需要重新构造 Frame 的 payload，不需要改动本类。
// ============================================================================

#ifndef SECURETRANSFER_NETWORK_NETWORK_H
#define SECURETRANSFER_NETWORK_NETWORK_H

#include <cstdint>
#include <chrono>
#include <string>

#include "network/frame.h"

/// TCP 通信封装（同时支持客户端与服务端角色）。
///
/// 典型用法：
///
///   客户端 (Alice)                    服务端 (Bob)
///   ----------------------------      ----------------------------
///   Network net;                      Network net;
///   net.connect("127.0.0.1", 9000);   net.listen(9000);
///   net.sendFrame(frame);             net.accept();
///   net.receiveFrame(frame);          net.receiveFrame(frame);
///   net.close();                      net.close();
class Network {
public:
    /// 最近一次操作的结果，便于调用者区分失败原因。
    enum class Result {
        OK,                ///< 成功
        PEER_CLOSED,       ///< 对端关闭了连接（recv() == 0 或 send() 得到 RST/EPIPE）
        TIMEOUT,           ///< 设置了收发超时并且已经超时
        INVALID_FRAME,     ///< Frame 非法（length 与 payload 不一致、超过 1 MB 等）
        NOT_CONNECTED,     ///< 尚未 connect()/accept() 就调用 sendFrame()/receiveFrame()
        INVALID_ARGUMENT,  ///< 参数非法（host 为空、port 为 0 等）
        SOCKET_FAILURE     ///< 其他 socket 系统调用错误，详情见 lastError()
    };

    Network();
    ~Network();

    // 一个 Network 对象持有一组 socket 资源，禁止拷贝与移动，避免重复析构。
    Network(const Network&) = delete;
    Network& operator=(const Network&) = delete;
    Network(Network&&) = delete;
    Network& operator=(Network&&) = delete;

    /// 作为客户端连接 host:port（例如 "127.0.0.1", 9000）。
    ///
    /// @return 成功返回 true；失败返回 false，原因见 lastResult() / lastError()
    bool connect(const std::string& host, uint16_t port);

    /// 作为服务端在 port 上监听。
    /// port == 0 表示由系统分配一个临时端口（测试时很方便，实际端口见 boundPort()）。
    bool listen(uint16_t port);

    /// 接受一个客户端连接（阻塞直到有客户端接入或出错）。
    /// 必须先用 listen() 成功监听。若已有连接，会先关闭旧连接（演示阶段只服务单个客户端）。
    bool accept();

    /// 发送一个完整 Frame。
    /// 内部会 serialize() 之后循环 writeAll()，从而正确处理 partial send。
    bool sendFrame(const Frame& frame);

    /// 接收一个完整 Frame。
    /// 内部先 readExact() 读 4 字节 length，再 readExact() 读满 payload，
    /// 从而正确处理 TCP 粘包 / 拆包。
    bool receiveFrame(Frame& frame);

    /// 关闭所有 socket。可以重复调用；不会修改 lastResult()/lastError()。
    void close();

    /// 只关闭**已建立的连接**，保留监听 socket。
    /// 用途：服务端在一次会话结束后继续等待下一个客户端（常驻服务）。
    /// 可以重复调用；不会修改 lastResult()/lastError()。
    void closeConnection();

    // ------------------------------------------------------------------
    //  扩展 / 诊断接口
    //  以下方法不属于项目组约定的核心接口，只是为 demo、测试以及后续
    //  模块提供的便利方法，可以在不破坏核心接口的前提下调整。
    // ------------------------------------------------------------------

    bool isConnected() const;    ///< connect()/accept() 是否已成功
    bool isListening() const;    ///< 是否处于监听状态
    uint16_t boundPort() const;  ///< listen() 实际绑定的端口（port == 0 时有用）

    bool setTcpNoDelay(bool on);          ///< 关闭 Nagle 算法，降低小消息延迟
    bool setReceiveTimeoutMs(int ms);     ///< 设置 recv 超时，0 表示永不超时
    bool setSendTimeoutMs(int ms);        ///< 设置 send 超时，0 表示永不超时

    // ---- 非阻塞探测（第三部分的图形界面需要）----
    // 界面工作线程不能靠"把接收超时当成没有数据"来轮询：那样既会把每次超时
    // 打成一行错误日志，又会让消息延迟受轮询间隔限制。这里提供一个
    // "等一小会儿，看有没有数据可读" 的原语：
    //   * 只要对端发来数据，select() 会立即返回 → 上层马上调用 receiveFrame()；
    //   * 期间没有数据则返回 kTimeout，这不是错误，不会写 lastError()。

    /// waitReadable() 的结果。
    enum class WaitResult {
        kReadable,  ///< 有数据可读（注意：对端关闭连接时 select() 也会报可读）
        kTimeout,   ///< 等待时间内没有数据到达
        kError      ///< socket 出错，详情见 lastError()
    };

    /// 最多等待 timeoutMs 毫秒，直到连接上有数据可读。
    /// timeoutMs == 0 表示立即返回（纯非阻塞探测）。
    /// 本方法不会打印错误日志；"暂时没有数据"时也不会修改 lastResult()/lastError()，
    /// 因此可以在循环里反复调用。
    WaitResult waitReadable(int timeoutMs);

    /// 最多等待 timeoutMs 毫秒，直到**监听 socket** 上有新连接可以 accept()。
    /// 用途：服务端不希望"卡死在 accept() 上无法取消"时，
    /// 可以先探测再调用 accept()（见 SecureSession::acceptOneClient(waitMs)）。
    /// 与 waitReadable() 一样：超时不是错误，不改 lastResult()/lastError()。
    WaitResult waitAcceptable(int timeoutMs);

    /// 为接下来的 receiveFrame() 设置"整包读取期限"（毫秒，0 = 取消）。
    ///
    /// 为什么要它：SO_RCVTIMEO 只限制"单次 recv 之间没有数据"的等待，
    /// 对端只要每次都刚好发一点字节，readExact() 就能被无限拖住。
    /// 设置期限后，readExact() 会在每次 recv 前把超时收紧到"剩余期限"，
    /// 因此"慢速发送"无法突破这个总期限（握手阶段用来防资源占用）。
    void setReadDeadlineMs(int ms);

    Result lastResult() const;            ///< 最近一次操作的结果
    const std::string& lastError() const; ///< 最近一次失败的详细描述

    /// Result 的可读描述，用于日志输出。
    static const char* resultToString(Result result);

private:
    /// 无效 socket 句柄的统一表示：
    /// POSIX 下无效的文件描述符就是 -1。
    static constexpr std::intptr_t kInvalidSocket = -1;

    bool writeAll(const uint8_t* data, std::size_t length);
    bool readExact(uint8_t* buffer, std::size_t length);
    bool applyTimeout(bool forReceive, int timeoutMs);
    /// 本轮 recv 实际应该用的超时：取"配置的超时"与"剩余读取期限"的较小值。
    /// 返回 -1 表示期限已到。
    int effectiveReceiveTimeoutMs() const;

    void resetError();
    bool fail(Result result, const std::string& message);

    std::intptr_t listenSocket_;      ///< 监听 socket（仅服务端使用）
    std::intptr_t connectionSocket_;  ///< 已建立的连接 socket
    uint16_t boundPort_;              ///< listen() 绑定的端口

    Result lastResult_;    ///< 最近一次操作的结果
    std::string lastError_; ///< 最近一次失败的原因

    int receiveTimeoutMs_ = 0;              ///< 最近一次 setReceiveTimeoutMs() 配置的值（0 = 不超时）
    bool hasReadDeadline_ = false;          ///< 是否设置了整包读取期限
    std::chrono::steady_clock::time_point readDeadline_{};
};

#endif  // SECURETRANSFER_NETWORK_NETWORK_H
