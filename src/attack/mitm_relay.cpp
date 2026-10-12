// ============================================================================
//  SecureTransfer - 第三部分：中间人中继（实现）
//  file: src/attack/mitm_relay.cpp
//
//  实现要点：
//    * 两条转发线程（C2S / S2C），各自只做"recv → 组帧 → 处理 → send"，
//      因此不需要 select()，也不会两个线程同时读写同一个 socket 状态；
//    * socket 用裸 BSD socket（Windows 上是 Winsock）而不是 Network 类：
//      攻击者侧工具不该复用受害端的会话语义，Network 也不是为"一进一出两个
//      连接"设计的（它内部有会被两个线程同时写的 lastError_ 等状态）；
//    * 帧的解析复用 `Frame`，包的解析复用 `Packet` —— 中继"看得见"的字段
//      与协议定义永远一致，不会出现两套解析。
// ============================================================================

#include "attack/mitm_relay.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

#include "common/hex.h"
#include "common/types.h"
#include "network/frame.h"
#include "protocol/message_type.h"
#include "protocol/packet.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using EveSocket = SOCKET;
static const EveSocket kEveInvalidSocket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
using EveSocket = int;
static const EveSocket kEveInvalidSocket = -1;
#endif

namespace attack {
namespace {

constexpr int kC2S = 0;
constexpr int kS2C = 1;
const char* const kDirTag[2] = {"C2S", "S2C"};

/// 类型化缓冲区的下标（kAny 不占槽位）。
int typeSlot(MitmPacketType type) {
    switch (type) {
        case MitmPacketType::kData: return 0;
        case MitmPacketType::kFileChunk: return 1;
        case MitmPacketType::kImage: return 2;
        case MitmPacketType::kAny: break;
    }
    return -1;
}

/// 协议消息类型 → 攻击目标类型（只关心这三种"业务数据"）。
MitmPacketType toMitmPacketType(MessageType type) {
    switch (type) {
        case MessageType::kData: return MitmPacketType::kData;
        case MessageType::kFileChunk: return MitmPacketType::kFileChunk;
        case MessageType::kImage: return MitmPacketType::kImage;
        default: return MitmPacketType::kAny;
    }
}

/// 单条被缓存下来的包的上限：只留"小的业务数据"（短消息、图像单包），
/// 文件块动辄 64 KiB，缓存一堆没意义。
constexpr std::size_t kMaxBufferedPayload = 256 * 1024;

/// 目标的可读描述（用于 ERR / QUEUED 提示）。
std::string describeTarget(const MitmTarget& target) {
    if (target.lastOfType) {
        return std::string("last-") + mitmPacketTypeToString(target.type);
    }
    if (target.index != 0) {
        return std::string("index:") + std::to_string(target.index) +
               (target.type == MitmPacketType::kAny
                    ? std::string("(含握手包)")
                    : std::string(" of ") + mitmPacketTypeToString(target.type));
    }
    if (target.type != MitmPacketType::kAny) {
        return std::string("next-") + mitmPacketTypeToString(target.type);
    }
    return "next";
}

/// 篡改：与项目里既有演示同一口径 —— 改 Body 第一个字节 + 序号加一。
/// 两者都参与 MAC，因此收包方一定会在 ⑦ CMAC 关（或 ⑥ 重放关）拒绝。
bool tamperPayload(Bytes& payload) {
    Packet packet;
    if (!Packet::decode(payload, packet, nullptr)) {
        return false;
    }
    if (!packet.body.empty()) {
        packet.body[0] = static_cast<Byte>(packet.body[0] ^ 0xFF);
    }
    packet.sequence += 1;
    payload = packet.encodeWithMac();
    return true;
}

/// 把符号方向转成 0/1 两个下标；kBoth 展开成两次调用。
struct DirectionPair {
    int first = kC2S;
    int count = 1;
};

DirectionPair expandDirection(MitmDirection direction) {
    DirectionPair pair;
    if (direction == MitmDirection::kS2C) {
        pair.first = kS2C;
    } else if (direction == MitmDirection::kBoth) {
        pair.first = kC2S;
        pair.count = 2;
    }
    return pair;
}

void closeSocket(EveSocket socket) {
    if (socket == kEveInvalidSocket) {
        return;
    }
#ifdef _WIN32
    ::closesocket(socket);
#else
    ::close(socket);
#endif
}

/// 先 shutdown 再 close：让阻塞在 recv() 里的线程立刻醒来。
void shutdownSocket(EveSocket socket) {
    if (socket == kEveInvalidSocket) {
        return;
    }
#ifdef _WIN32
    ::shutdown(socket, SD_BOTH);
#else
    ::shutdown(socket, SHUT_RDWR);
#endif
    closeSocket(socket);
}

EveSocket createListener(std::uint16_t port, std::uint16_t* boundPort, std::string& error) {
    // 绑定前先探测：本机 127.0.0.1:port 上是否已经有人在监听？
    //
    // 为什么必须探测：Windows（以及设置了 SO_REUSEADDR 的进程）允许
    // "0.0.0.0:port" 与 "127.0.0.1:port" 同时绑定，而发往 127.0.0.1 的连接会被
    // **更具体**的那个绑定抢走。若不做这一步，本中继会"显示 LISTEN 正常、却一个
    // 连接都收不到"——本机 9430 端口就被另一个本机服务这样占着，实测客户端连上
    // 后收到的是那个服务的 HTTP 响应，而中继日志里什么都没有。这种"看起来成功"
    // 的失败最难排查，所以宁可直接报错。
    {
        EveSocket probe = ::socket(AF_INET, SOCK_STREAM, 0);
        if (probe != kEveInvalidSocket) {
#ifdef _WIN32
            u_long nonBlocking = 1;
            ::ioctlsocket(probe, FIONBIO, &nonBlocking);
#else
            const int flags = ::fcntl(probe, F_GETFL, 0);
            ::fcntl(probe, F_SETFL, flags | O_NONBLOCK);
#endif
            sockaddr_in loopback{};
            loopback.sin_family = AF_INET;
            loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            loopback.sin_port = htons(port);
            const int connected =
                ::connect(probe, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback));
            bool inUse = connected == 0;
            if (!inUse) {
                fd_set writable;
                FD_ZERO(&writable);
                FD_SET(probe, &writable);
                timeval timeout{};
                timeout.tv_usec = 300 * 1000;  // 最多等 300ms
#ifdef _WIN32
                const int ready = ::select(0, nullptr, &writable, nullptr, &timeout);
#else
                const int ready = ::select(probe + 1, nullptr, &writable, nullptr, &timeout);
#endif
                if (ready > 0) {
                    int socketError = 0;
#ifdef _WIN32
                    int length = static_cast<int>(sizeof(socketError));
#else
                    socklen_t length = sizeof(socketError);
#endif
                    ::getsockopt(probe, SOL_SOCKET, SO_ERROR,
                                 reinterpret_cast<char*>(&socketError), &length);
                    inUse = socketError == 0;
                }
            }
            closeSocket(probe);
            if (inUse) {
                error = "端口 " + std::to_string(port) +
                        " 已被本机其它服务占用（127.0.0.1:" + std::to_string(port) +
                        " 上已有监听）——请换一个端口";
                return kEveInvalidSocket;
            }
        }
    }

    EveSocket socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (socket == kEveInvalidSocket) {
        error = "socket() 失败";
        return kEveInvalidSocket;
    }
#ifndef _WIN32
    // Linux 下保留 SO_REUSEADDR：避免刚关闭的连接处于 TIME_WAIT 时无法立刻重绑。
    // ⚠ Windows 上**不能**这么做：它的 SO_REUSEADDR 允许"通配地址 0.0.0.0:port"与
    //    别的进程"具体地址 127.0.0.1:port"同时绑定，结果是本进程绑定成功、却一个连接
    //    都收不到（Windows 优先匹配更具体的绑定）。排查过：本机 9430 被其它服务占用时
    //    就出现过"中继显示 LISTEN 正常，但客户端连上后收到的是那个服务的 HTTP 响应"。
    //    这里不设它，让端口冲突直接以 bind() 失败暴露出来。
    int reuse = 1;
    ::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
                 sizeof(reuse));
#endif
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    if (::bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        error = "bind() 失败（端口可能被占用）：" + std::to_string(port);
        closeSocket(socket);
        return kEveInvalidSocket;
    }
    if (::listen(socket, 4) != 0) {
        error = "listen() 失败";
        closeSocket(socket);
        return kEveInvalidSocket;
    }
    if (boundPort != nullptr) {
        sockaddr_in actual{};
#ifdef _WIN32
        int length = static_cast<int>(sizeof(actual));
#else
        socklen_t length = sizeof(actual);
#endif
        if (::getsockname(socket, reinterpret_cast<sockaddr*>(&actual), &length) == 0) {
            *boundPort = ntohs(actual.sin_port);
        } else {
            *boundPort = port;
        }
    }
    return socket;
}

EveSocket acceptOne(EveSocket listener, std::string& peerText) {
    sockaddr_in peer{};
#ifdef _WIN32
    int length = static_cast<int>(sizeof(peer));
#else
    socklen_t length = sizeof(peer);
#endif
    const EveSocket client = ::accept(listener, reinterpret_cast<sockaddr*>(&peer), &length);
    if (client == kEveInvalidSocket) {
        return kEveInvalidSocket;
    }
    char buffer[64] = {};
    ::inet_ntop(AF_INET, &peer.sin_addr, buffer, sizeof(buffer));
    peerText = std::string(buffer) + ":" + std::to_string(ntohs(peer.sin_port));
    return client;
}

EveSocket connectTo(const std::string& host, std::uint16_t port, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    const std::string portText = std::to_string(port);
    if (::getaddrinfo(host.c_str(), portText.c_str(), &hints, &result) != 0 || result == nullptr) {
        error = "无法解析目标地址 " + host;
        return kEveInvalidSocket;
    }
    EveSocket socket = kEveInvalidSocket;
    for (addrinfo* entry = result; entry != nullptr; entry = entry->ai_next) {
        socket = ::socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (socket == kEveInvalidSocket) {
            continue;
        }
        if (::connect(socket, entry->ai_addr, static_cast<int>(entry->ai_addrlen)) == 0) {
            break;
        }
        closeSocket(socket);
        socket = kEveInvalidSocket;
    }
    ::freeaddrinfo(result);
    if (socket == kEveInvalidSocket) {
        error = "连接 " + host + ":" + portText + " 失败（真正的服务端起来了吗？）";
    }
    return socket;
}

/// 收一点数据；>0 = 字节数，0 = 对端正常关闭，<0 = 出错。
int recvSome(EveSocket socket, std::uint8_t* buffer, std::size_t capacity) {
    for (;;) {
        const int received =
            ::recv(socket, reinterpret_cast<char*>(buffer), static_cast<int>(capacity), 0);
        if (received >= 0) {
            return received;
        }
#ifdef _WIN32
        if (::WSAGetLastError() == WSAEINTR) {
            continue;
        }
#else
        if (errno == EINTR) {
            continue;
        }
#endif
        return -1;
    }
}

/// 完整发出（处理 partial send）。
bool sendAll(EveSocket socket, const std::uint8_t* data, std::size_t length) {
#if defined(MSG_NOSIGNAL)
    // Linux：对端断开后继续 send() 会触发 SIGPIPE，默认动作是**直接杀死进程**。
    // 用它把"写失败"变成普通的返回值 -1（与 Windows 的行为一致）。
    // 同一处理见 src/network/network.cpp 的 kSendFlags。
    const int flags = MSG_NOSIGNAL;
#else
    const int flags = 0;
#endif
    std::size_t sent = 0;
    while (sent < length) {
        const int written = ::send(socket, reinterpret_cast<const char*>(data + sent),
                                   static_cast<int>(length - sent), flags);
        if (written <= 0) {
            return false;
        }
        sent += static_cast<std::size_t>(written);
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
//  实现
// ---------------------------------------------------------------------------

struct MitmRelay::Impl {
    /// 一次"待执行"的攻击。index == 0 表示"该方向的下一个包"。
    struct PendingAttackBox {
        MitmAttack kind = MitmAttack::kNone;
        MitmTarget target;
        int delayMs = 0;
    };

    MitmConfig config;
    LineCallback onLine;

    EveSocket listener = kEveInvalidSocket;
    EveSocket client = kEveInvalidSocket;    ///< 连进本中继的那一端（Alice）
    EveSocket upstream = kEveInvalidSocket;  ///< 本中继连出去的那一端（Bob）
    std::uint16_t boundPort = 0;

    std::mutex mutex;
    /// 写 socket 用：转发线程与控制线程（下发"最近一条包"的注入）可能同时写同一个
    /// socket，必须串行化（TCP socket 上并发 send 是允许的，但我们的 sendAll 是一段
    /// "循环写满"的逻辑，两条线程交错会让字节顺序不可预期）。
    std::mutex writeMutex[2];
    std::condition_variable condition;
    bool connected = false;
    bool finished = false;

    PendingAttackBox pending[2];
    struct PendingReplayBox {
        bool armed = false;
        MitmTarget target;
    };
    PendingReplayBox replay[2];
    std::uint64_t packetCount[2] = {0, 0};
    /// 每个方向、每种类型各自的计数（"第 N 条短消息"就靠它）。
    std::uint64_t typedCount[2][3] = {};
    /// 每个方向、每种类型"最近一条已转发包"的 payload（供"打最近一条"用）。
    Bytes lastTyped[2][3];
    /// 攻击者视角的观察：注入了几次、最后一次注入到连接关闭隔了多久。
    int injectedCount = 0;
    std::chrono::steady_clock::time_point lastInjectAt{};
    bool observationReported = false;
    MitmStats stats;

    std::atomic<bool> running{true};
    std::thread acceptor;
    std::thread c2s;
    std::thread s2c;

    Impl(MitmConfig inConfig, LineCallback inCallback);
    ~Impl();

    void emit(const std::string& line);
    void serverLoop();
    void forwardLoop(int dir);
    void processFrame(int dir, const std::vector<std::uint8_t>& payload);
    void printPacket(int dir, std::uint64_t index, const Bytes& payload);
    void finish();
    /// 发送一个已经组好帧的包（带写锁）。
    bool sendFramed(int dir, const Bytes& payload);
    /// 对"最近一条该类型包"立即下手（篡改 / 重放）；成功返回 true。
    bool injectLastOfType(int dir, const MitmTarget& target, MitmAttack kind, int delayMs);
    /// 连接断开时打印"攻击者能观察到什么"（只有注入过才打）。
    void reportObservation();
    /// 这个序号是不是已经过去了？（过去了就永远不会触发，必须当场说清楚）
    bool indexAlreadyPassed(int dir, const MitmTarget& target, std::string* reason);
};

MitmRelay::Impl::Impl(MitmConfig inConfig, LineCallback inCallback)
    : config(std::move(inConfig)), onLine(std::move(inCallback)) {
#ifdef _WIN32
    WSADATA data;
    ::WSAStartup(MAKEWORD(2, 2), &data);
#endif
}

MitmRelay::Impl::~Impl() {
    finish();
#ifdef _WIN32
    ::WSACleanup();
#endif
}

void MitmRelay::Impl::emit(const std::string& line) {
    if (onLine) {
        onLine(line);
        return;
    }
    std::cout << "[EVE] " << line << std::endl;  // endl 会 flush，管道对面才能实时读到
}

/// 监听 → 等客户端 → 连真正的服务端 → 起两条转发线程。
void MitmRelay::Impl::serverLoop() {
    std::string error;
    listener = createListener(config.listenPort, &boundPort, error);
    if (listener == kEveInvalidSocket) {
        emit("FATAL " + error);
        finish();
        return;
    }
    emit("LISTEN port=" + std::to_string(boundPort) + " target=" + config.targetHost + ":" +
         std::to_string(config.targetPort));

    std::string peerText;
    client = acceptOne(listener, peerText);
    closeSocket(listener);
    listener = kEveInvalidSocket;
    if (client == kEveInvalidSocket) {
        emit("FATAL accept() 失败");
        finish();
        return;
    }
    if (!running) {  // 还没等来客户端就已被要求停止
        shutdownSocket(client);
        finish();
        return;
    }

    upstream = connectTo(config.targetHost, config.targetPort, error);
    if (upstream == kEveInvalidSocket) {
        emit("FATAL " + error);
        shutdownSocket(client);
        finish();
        return;
    }
    emit("CONNECTED client=" + peerText + " upstream=" + config.targetHost + ":" +
         std::to_string(config.targetPort));
    {
        std::lock_guard<std::mutex> lock(mutex);
        connected = true;
    }
    condition.notify_all();

    c2s = std::thread(&Impl::forwardLoop, this, kC2S);
    s2c = std::thread(&Impl::forwardLoop, this, kS2C);
}

void MitmRelay::Impl::finish() {
    running = false;
    // 监听 socket 也要关：否则还没等到客户端时 acceptor 会一直卡在 accept()
    shutdownSocket(listener);
    listener = kEveInvalidSocket;
    shutdownSocket(client);
    shutdownSocket(upstream);
    client = kEveInvalidSocket;
    upstream = kEveInvalidSocket;
    if (c2s.joinable() && c2s.get_id() != std::this_thread::get_id()) {
        c2s.join();
    }
    if (s2c.joinable() && s2c.get_id() != std::this_thread::get_id()) {
        s2c.join();
    }
    if (acceptor.joinable() && acceptor.get_id() != std::this_thread::get_id()) {
        acceptor.join();
    }
    {
        std::lock_guard<std::mutex> lock(mutex);
        finished = true;
    }
    condition.notify_all();
}

/// 打印每个经过的包：这就是"Eve 能看到什么"的真实清单。
void MitmRelay::Impl::printPacket(int dir, std::uint64_t index, const Bytes& payload) {
    if (config.quiet) {
        return;
    }
    Packet packet;
    if (!Packet::decode(payload, packet, nullptr)) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            ++stats.undecodable;
        }
        emit(std::string("PACKET dir=") + kDirTag[dir] + " n=" + std::to_string(index) +
             " type=UNDECODABLE len=" + std::to_string(payload.size()));
        return;
    }
    const std::size_t preview = std::min<std::size_t>(8, packet.body.size());
    const std::string cipher =
        preview == 0 ? std::string("-") : toHex(packet.body.data(), preview);
    std::ostringstream oss;
    oss << "PACKET dir=" << kDirTag[dir] << " n=" << index
        << " type=" << messageTypeToString(packet.type) << " seq=" << packet.sequence
        << " sid=" << toHex(packet.sessionId) << " nonce=" << toHex(packet.nonce.data(), 8)
        << " len=" << packet.body.size() << " ct=" << cipher
        << " mac=" << toHex(packet.mac.data(), 8);
    emit(oss.str());
}

bool MitmRelay::Impl::sendFramed(int dir, const Bytes& payload) {
    Frame frame;
    frame.setPayload(payload);
    const std::vector<std::uint8_t> wire = frame.serialize();
    if (wire.empty()) {
        return false;
    }
    const EveSocket target = (dir == kC2S) ? upstream : client;
    const std::lock_guard<std::mutex> lock(writeMutex[dir]);
    return sendAll(target, wire.data(), wire.size());
}

/// 对"最近一条该类型的包"立即下手 —— 这就是教科书里的"捕获-篡改/重发"：
/// 不用等新包，直接拿刚才转发过的那一条再打一次。
/// kind == kNone 表示"原样重发"（重放）。
bool MitmRelay::Impl::injectLastOfType(int dir, const MitmTarget& target, MitmAttack kind,
                                       int delayMs) {
    const int slot = typeSlot(target.type);
    if (slot < 0) {
        return false;
    }
    Bytes payload;
    bool hasBuffered = false;
    {
        std::lock_guard<std::mutex> lock(mutex);
        hasBuffered = !lastTyped[dir][slot].empty();
        if (hasBuffered) {
            payload = lastTyped[dir][slot];
        }
    }
    if (!hasBuffered) {
        // 别静默失败：用户点了「最近一条」却什么都没发生，必须说清原因
        std::ostringstream oss;
        oss << "ERR target=last-" << mitmPacketTypeToString(target.type)
            << " dir=" << kDirTag[dir]
            << "：还没有已转发的该类包（先让对方发一条，再点「最近一条」）";
        emit(oss.str());
        return false;
    }
    if (kind == MitmAttack::kDelay && delayMs > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
    }
    if (kind == MitmAttack::kTamper && !tamperPayload(payload)) {
        return false;
    }
    if (!sendFramed(dir, payload)) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex);
        ++injectedCount;
        lastInjectAt = std::chrono::steady_clock::now();
        if (kind == MitmAttack::kTamper) {
            ++stats.tampered;
        } else if (kind == MitmAttack::kDelay) {
            ++stats.delayed;
        } else if (kind == MitmAttack::kNone) {
            ++stats.replayed;
        }
    }
    std::ostringstream oss;
    oss << "ATTACK kind=" << (kind == MitmAttack::kNone ? "replay" : mitmAttackToString(kind))
        << " dir=" << kDirTag[dir] << " target=last-" << mitmPacketTypeToString(target.type)
        << " result=injected（已注入到链路；对端是否接受由受害端掌握）";
    emit(oss.str());
    return true;
}

/// 连接断开时，如实说明"攻击者能确认的只有注入过"。
void MitmRelay::Impl::reportObservation() {
    int injected = 0;
    long long elapsedMs = -1;
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (observationReported) {
            return;  // 两个方向都会走到这里，只报一次
        }
        observationReported = true;
        injected = injectedCount;
        if (injected > 0 && lastInjectAt.time_since_epoch().count() != 0) {
            elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - lastInjectAt)
                            .count();
        }
    }
    if (injected == 0) {
        return;
    }
    std::ostringstream oss;
    oss << "OBSERVE attacker_view=injected_only injected=" << injected;
    if (elapsedMs >= 0) {
        oss << " closed_after_last_inject_ms=" << elapsedMs;
    }
    oss << " note=连接在注入之后被关闭（是否因为被拦下，Eve 无从得知；判定只发生在受害端）";
    emit(oss.str());
}

/// 序号是"从连接建立起算的绝对位置"（--type 则是"该类型内第几个"）。
/// 如果用户填的序号已经过去了，这个攻击**永远不会触发** —— 早期版本会静默挂着，
/// 用户看到的就是"点了没反应、会话照常"。所以这里当场判掉并给出可执行的建议。
bool MitmRelay::Impl::indexAlreadyPassed(int dir, const MitmTarget& target,
                                         std::string* reason) {
    if (target.index == 0 || !target.waitsForNextPacket()) {
        return false;
    }
    std::uint64_t seen = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        const int slot = typeSlot(target.type);
        seen = (target.type == MitmPacketType::kAny || slot < 0)
                   ? packetCount[dir]
                   : typedCount[dir][slot];
    }
    if (target.index > seen) {
        return false;
    }
    if (reason != nullptr) {
        std::ostringstream oss;
        oss << "ERR target=" << describeTarget(target) << " dir=" << kDirTag[dir]
            << "：该序号已经过去了（这个方向至今已转发 " << seen << " 个"
            << (target.type == MitmPacketType::kAny ? "包，含握手包" : "该类包")
            << "），它永远不会触发。请改用「下一个包 / 下一条短消息」"
               "或「最近一条短消息」。";
        *reason = oss.str();
    }
    return true;
}

void MitmRelay::Impl::processFrame(int dir, const std::vector<std::uint8_t>& payload) {
    std::uint64_t index = 0;
    std::uint64_t typedIndex = 0;
    // 先解析一次：既用于"按类型匹配"，也用于把"最近一条业务包"存起来
    Packet decoded;
    const bool decodable = Packet::decode(payload, decoded, nullptr);
    const MitmPacketType packetKind =
        decodable ? toMitmPacketType(decoded.type) : MitmPacketType::kAny;
    {
        std::lock_guard<std::mutex> lock(mutex);
        index = ++packetCount[dir];
        const int slot = typeSlot(packetKind);
        if (slot >= 0) {
            typedIndex = ++typedCount[dir][slot];
        }
        if (dir == kC2S) {
            ++stats.c2sPackets;
        } else {
            ++stats.s2cPackets;
        }
    }
    printPacket(dir, index, payload);

    // index 的含义：**在匹配类型之内**数第几个。
    //   * 没写 --type（kAny）→ 就是该方向第几个包（含握手，与旧行为一致）
    //   * 写了 --type DATA   → 是"第几条 DATA"，不会被握手包干扰
    const auto matches = [packetKind, index, typedIndex](const MitmTarget& target) {
        if (target.type != MitmPacketType::kAny && target.type != packetKind) {
            return false;  // 类型不匹配
        }
        if (target.index == 0) {
            return true;  // 只按类型匹配
        }
        return target.type == MitmPacketType::kAny ? target.index == index
                                                   : target.index == typedIndex;
    };

    MitmAttack kind = MitmAttack::kNone;
    int delayMs = 0;
    {
        std::lock_guard<std::mutex> lock(mutex);
        PendingAttackBox& attack = pending[dir];
        if (attack.kind != MitmAttack::kNone && matches(attack.target)) {
            kind = attack.kind;
            delayMs = attack.delayMs;
            attack = PendingAttackBox{};
        }
    }

    Bytes outgoing(payload.begin(), payload.end());
    if (kind == MitmAttack::kDelay) {
        emit(std::string("ATTACK kind=delay dir=") + kDirTag[dir] + " n=" + std::to_string(index) +
             " ms=" + std::to_string(delayMs) + " result=injected");
        std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        {
            std::lock_guard<std::mutex> lock(mutex);
            ++stats.delayed;
            ++injectedCount;
            lastInjectAt = std::chrono::steady_clock::now();
        }
    } else if (kind == MitmAttack::kDrop) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            ++stats.dropped;
            ++injectedCount;
            lastInjectAt = std::chrono::steady_clock::now();
        }
        emit(std::string("ATTACK kind=drop dir=") + kDirTag[dir] + " n=" + std::to_string(index) +
             " result=injected（该包未转发，收包方只能看到超时）");
        return;
    } else if (kind == MitmAttack::kTamper) {
        const bool ok = tamperPayload(outgoing);
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (ok) {
                ++stats.tampered;
            } else {
                ++stats.undecodable;
            }
            ++injectedCount;
            lastInjectAt = std::chrono::steady_clock::now();
        }
        emit(std::string("ATTACK kind=tamper dir=") + kDirTag[dir] + " n=" + std::to_string(index) +
             " result=" +
             (ok ? "injected（已注入到链路；对端是否接受由受害端掌握）" : "skip（该包无法解析）"));
    }

    if (!sendFramed(dir, outgoing)) {
        emit(std::string("CLOSED dir=") + kDirTag[dir] + " reason=forward_failed");
        running = false;
        return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex);
        ++stats.forwarded;
        // 记住"最近一条该类业务的原始包"（不是被篡改后的字节），供"打最近一条"用
        const int slot = typeSlot(packetKind);
        if (slot >= 0 && payload.size() <= kMaxBufferedPayload) {
            lastTyped[dir][slot] = payload;
        }
    }

    // 重放：把**刚刚转发的这个包**原样再发一次（中间人截下来再发一遍）。
    // 收包方已经收过同样的序号，因此会在 ⑥ 防重放关拒绝。
    bool doReplay = false;
    {
        std::lock_guard<std::mutex> lock(mutex);
        PendingReplayBox& pendingReplay = replay[dir];
        if (pendingReplay.armed && matches(pendingReplay.target)) {
            pendingReplay.armed = false;
            doReplay = true;
        }
    }
    if (doReplay) {
        if (!sendFramed(dir, outgoing)) {
            running = false;
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mutex);
            ++stats.replayed;
            ++injectedCount;
            lastInjectAt = std::chrono::steady_clock::now();
        }
        emit(std::string("ATTACK kind=replay dir=") + kDirTag[dir] + " n=" + std::to_string(index) +
             " result=injected（原样重发同一个包；是否被接受由受害端掌握）");
    }
}

void MitmRelay::Impl::forwardLoop(int dir) {
    const EveSocket from = (dir == kC2S) ? client : upstream;
    std::vector<std::uint8_t> buffer;
    buffer.reserve(64 * 1024);
    std::vector<std::uint8_t> chunk(64 * 1024);

    while (running) {
        const int received = recvSome(from, chunk.data(), chunk.size());
        if (received <= 0) {
            if (running) {
                emit(std::string("CLOSED dir=") + kDirTag[dir] +
                     (received == 0 ? " reason=peer_closed" : " reason=recv_error"));
                reportObservation();
            }
            running = false;
            break;
        }
        buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + received);

        for (;;) {
            Frame frame;
            std::size_t consumed = 0;
            const Frame::Status status = Frame::deserialize(buffer, frame, &consumed);
            if (status == Frame::Status::INCOMPLETE) {
                break;
            }
            if (status != Frame::Status::OK) {
                emit(std::string("CLOSED dir=") + kDirTag[dir] + " reason=invalid_frame");
                running = false;
                return;
            }
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(consumed));
            processFrame(dir, frame.payload);
            if (!running) {
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  对外接口
// ---------------------------------------------------------------------------

const char* mitmAttackToString(MitmAttack attack) {
    switch (attack) {
        case MitmAttack::kTamper: return "tamper";
        case MitmAttack::kDrop: return "drop";
        case MitmAttack::kDelay: return "delay";
        case MitmAttack::kNone: break;
    }
    return "none";
}

const char* mitmPacketTypeToString(MitmPacketType type) {
    switch (type) {
        case MitmPacketType::kData: return "DATA";
        case MitmPacketType::kFileChunk: return "FILE_CHUNK";
        case MitmPacketType::kImage: return "IMAGE";
        case MitmPacketType::kAny: break;
    }
    return "any";
}

MitmRelay::MitmRelay(MitmConfig config, LineCallback onLine)
    : impl_(std::make_unique<Impl>(std::move(config), std::move(onLine))) {}

MitmRelay::~MitmRelay() = default;

bool MitmRelay::start(std::string* error) {
    impl_->acceptor = std::thread(&Impl::serverLoop, impl_.get());
    // 等监听结果：要么拿到端口，要么拿到错误。
    std::unique_lock<std::mutex> lock(impl_->mutex);
    impl_->condition.wait_for(lock, std::chrono::seconds(5), [this]() {
        return impl_->boundPort != 0 || impl_->finished;
    });
    if (impl_->boundPort == 0) {
        if (error != nullptr) {
            *error = "中继启动失败（端口未绑定）";
        }
        return false;
    }
    return true;
}

bool MitmRelay::waitForConnection(int timeoutMs) {
    std::unique_lock<std::mutex> lock(impl_->mutex);
    impl_->condition.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                              [this]() { return impl_->connected || impl_->finished; });
    return impl_->connected && !impl_->finished;
}

std::uint16_t MitmRelay::listenPort() const {
    return impl_->boundPort;
}

bool MitmRelay::running() const {
    return impl_->running;
}

void MitmRelay::queueAttack(MitmAttack attack, MitmTarget target, MitmDirection direction,
                            int delayMs) {
    const DirectionPair pair = expandDirection(direction);
    for (int i = 0; i < pair.count; ++i) {
        const int dir = pair.first + i;
        if (!target.waitsForNextPacket()) {
            // "打最近一条"：不进队列，立即对刚才转发过的那一条下手
            (void)impl_->injectLastOfType(dir, target, attack, delayMs);
            continue;
        }
        std::string staleReason;
        if (impl_->indexAlreadyPassed(dir, target, &staleReason)) {
            impl_->emit(staleReason);
            continue;
        }
        std::lock_guard<std::mutex> lock(impl_->mutex);
        Impl::PendingAttackBox box;
        box.kind = attack;
        box.target = target;
        box.delayMs = delayMs;
        impl_->pending[dir] = box;
    }
}

void MitmRelay::queueReplay(MitmTarget target, MitmDirection direction) {
    const DirectionPair pair = expandDirection(direction);
    for (int i = 0; i < pair.count; ++i) {
        const int dir = pair.first + i;
        if (!target.waitsForNextPacket()) {
            // 原样重发"最近一条该类型包"（kind = kNone 表示不改内容）
            (void)impl_->injectLastOfType(dir, target, MitmAttack::kNone, 0);
            continue;
        }
        std::string staleReason;
        if (impl_->indexAlreadyPassed(dir, target, &staleReason)) {
            impl_->emit(staleReason);
            continue;
        }
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->replay[dir].armed = true;
        impl_->replay[dir].target = target;
    }
}

MitmStats MitmRelay::stats() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->stats;
}

void MitmRelay::stop() {
    impl_->finish();
}

}  // namespace attack
