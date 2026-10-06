// ============================================================================
//  SecureTransfer - 第一阶段：基础 TCP 通信
//  file: src/network/network.cpp
//
//  说明：Network 类的实现（Linux / POSIX Socket）。
//        本文件主要解决 TCP 的两个经典问题：
//          1. partial send：一次 send() 可能只发出部分数据 -> writeAll()
//          2. partial recv：一次 recv() 可能只收到部分数据 -> readExact()
//        因此 sendFrame()/receiveFrame() 每次处理的是“完整的一个 Frame”，
//        上层不需要关心粘包 / 拆包。
//
//  目标平台：Ubuntu 621 虚拟机（Linux），编译时只需要标准库 + POSIX Socket。
// ============================================================================

#include "network/network.h"

#include <cerrno>
#include <climits>
#include <cstring>
#include <sstream>
#include <system_error>
#include <utility>

#if defined(_WIN32)
// Windows：Winsock2（注意 winsock2.h 必须早于 windows.h）
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "common/log.h"
#include "common/text_encoding.h"

namespace {

const char* const kLogModule = "Network";

/// listen() 的 backlog。演示阶段只需要一个客户端。
constexpr int kListenBacklog = 1;

// ---------------------------------------------------------------------------
//  平台差异集中在这一段：Windows 用 Winsock2，Linux 用 POSIX socket。
//  上层（Network 的各个方法）只通过下面的小工具函数访问平台能力。
// ---------------------------------------------------------------------------
#if defined(_WIN32)
// Windows 用 SD_BOTH 表示同时关闭收发
const int kShutdownBoth = SD_BOTH;
using SocketHandle = SOCKET;
const SocketHandle kInvalidHandle = INVALID_SOCKET;

/// 进程内初始化一次 Winsock（静态对象，在 main 之前构造）。
struct WinsockGuard {
    WinsockGuard() {
        WSADATA data;
        (void)::WSAStartup(MAKEWORD(2, 2), &data);
    }
    ~WinsockGuard() { ::WSACleanup(); }
};
const WinsockGuard kWinsockGuard;
#else
/// POSIX 下 socket 就是一个文件描述符。
const int kShutdownBoth = SHUT_RDWR;
using SocketHandle = int;
const SocketHandle kInvalidHandle = -1;
#endif

SocketHandle toHandle(std::intptr_t value) {
    return static_cast<SocketHandle>(value);
}

std::intptr_t toIntptr(SocketHandle handle) {
    return static_cast<std::intptr_t>(handle);
}

#if defined(_WIN32)
/// 取最近一次 socket 错误码（Windows 用 WSAGetLastError）。
int lastSocketError() {
    return ::WSAGetLastError();
}
bool isInterrupted(int code) {
    return code == WSAEINTR;
}
bool isTimeout(int code) {
    return code == WSAEWOULDBLOCK || code == WSAETIMEDOUT;
}
bool isPeerGone(int code) {
    return code == WSAECONNRESET || code == WSAECONNABORTED || code == WSAENOTCONN ||
           code == WSAESHUTDOWN;
}
std::string describeError(int code) {
    std::ostringstream oss;
    oss << "WSA error " << code << " (";
    // 注意：std::system_category().message() 返回的是**本地代码页（GBK）**文本，
    // 而本工程内部/控制台统一用 UTF-8，直接拼进去会变成乱码。
    // 这里改用宽字符版本再转 UTF-8，中文错误信息才不会乱码。
    LPWSTR buffer = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, static_cast<DWORD>(code), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    if (length > 0 && buffer != nullptr) {
        std::wstring message(buffer, length);
        ::LocalFree(buffer);
        while (!message.empty() &&
               (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
            message.pop_back();
        }
        oss << sttext::toUtf8(message);
    } else {
        oss << "unknown error";
    }
    oss << ")";
    return oss.str();
}
void closeSocket(SocketHandle handle) {
    ::closesocket(handle);
}
#else
/// POSIX 下 socket 错误码就是 errno。
int lastSocketError() {
    return errno;
}
bool isInterrupted(int code) {
    return code == EINTR;
}
bool isTimeout(int code) {
    return code == EAGAIN || code == EWOULDBLOCK || code == ETIMEDOUT;
}
bool isPeerGone(int code) {
    return code == ECONNRESET || code == EPIPE || code == ECONNABORTED || code == ENOTCONN;
}
std::string describeError(int code) {
    std::ostringstream oss;
    oss << "errno " << code << " (" << std::strerror(code) << ")";
    return oss.str();
}
void closeSocket(SocketHandle handle) {
    ::close(handle);
}
#endif

/// send() 的附加标志：避免对端断开时进程被 SIGPIPE 直接杀死。
#if defined(MSG_NOSIGNAL)
const int kSendFlags = MSG_NOSIGNAL;
#else
const int kSendFlags = 0;
#endif

}  // namespace

Network::Network()
    : listenSocket_(kInvalidSocket),
      connectionSocket_(kInvalidSocket),
      boundPort_(0),
      lastResult_(Result::OK),
      lastError_() {}

Network::~Network() {
    close();
}

const char* Network::resultToString(Result result) {
    switch (result) {
        case Result::OK:
            return "OK";
        case Result::PEER_CLOSED:
            return "PEER_CLOSED";
        case Result::TIMEOUT:
            return "TIMEOUT";
        case Result::INVALID_FRAME:
            return "INVALID_FRAME";
        case Result::NOT_CONNECTED:
            return "NOT_CONNECTED";
        case Result::INVALID_ARGUMENT:
            return "INVALID_ARGUMENT";
        case Result::SOCKET_FAILURE:
            return "SOCKET_FAILURE";
    }
    return "UNKNOWN";
}

void Network::resetError() {
    lastResult_ = Result::OK;
    lastError_.clear();
}

bool Network::fail(Result result, const std::string& message) {
    lastResult_ = result;
    lastError_ = message;
    ST_LOG_ERROR(kLogModule, message);
    return false;
}

bool Network::isConnected() const {
    return connectionSocket_ != kInvalidSocket;
}

bool Network::isListening() const {
    return listenSocket_ != kInvalidSocket;
}

uint16_t Network::boundPort() const {
    return boundPort_;
}

Network::Result Network::lastResult() const {
    return lastResult_;
}

const std::string& Network::lastError() const {
    return lastError_;
}

bool Network::connect(const std::string& host, uint16_t port) {
    resetError();

    if (host.empty()) {
        return fail(Result::INVALID_ARGUMENT, "connect() 参数非法：host 为空");
    }
    if (port == 0) {
        return fail(Result::INVALID_ARGUMENT, "connect() 参数非法：port 不能为 0");
    }

    // 允许同一个 Network 对象复用：先清理上一次的资源。
    if (connectionSocket_ != kInvalidSocket || listenSocket_ != kInvalidSocket) {
        close();
    }

    const std::string portText = std::to_string(port);

    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // 同时支持 IPv4 / IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* results = nullptr;
    const int resolveResult = ::getaddrinfo(host.c_str(), portText.c_str(), &hints, &results);
    if (resolveResult != 0) {
        return fail(Result::SOCKET_FAILURE,
                    "Failed to resolve host " + host + ": " + ::gai_strerror(resolveResult));
    }

    std::string lastFailure = "没有可用地址";
    bool connected = false;

    for (addrinfo* entry = results; entry != nullptr; entry = entry->ai_next) {
        const SocketHandle handle = ::socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (handle == kInvalidHandle) {
            lastFailure = "socket() 失败: " + describeError(lastSocketError());
            continue;
        }

        if (::connect(handle, entry->ai_addr, static_cast<socklen_t>(entry->ai_addrlen)) == 0) {
            connectionSocket_ = toIntptr(handle);
            connected = true;
            break;
        }

        lastFailure = "connect() 失败: " + describeError(lastSocketError());
        closeSocket(handle);
    }

    ::freeaddrinfo(results);

    if (!connected) {
        return fail(Result::SOCKET_FAILURE,
                    "Failed to connect to " + host + ":" + portText + " (" + lastFailure + ")");
    }

    ST_LOG_INFO(kLogModule, "TCP connected to " + host + ":" + portText);
    return true;
}

bool Network::listen(uint16_t port) {
    resetError();

    // 允许同一个 Network 对象复用：先清理上一次的资源。
    if (listenSocket_ != kInvalidSocket || connectionSocket_ != kInvalidSocket) {
        close();
    }

    const SocketHandle handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (handle == kInvalidHandle) {
        return fail(Result::SOCKET_FAILURE,
                    "socket() 失败: " + describeError(lastSocketError()));
    }

    // 允许服务器重启后立刻重新绑定同一端口（避免 TIME_WAIT 造成的 bind 失败）。
    const int reuse = 1;
    if (::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&reuse), sizeof(reuse)) != 0) {
        ST_LOG_WARN(kLogModule,
                    "setsockopt(SO_REUSEADDR) 失败，忽略: " + describeError(lastSocketError()));
    }

    sockaddr_in address;
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);

    if (::bind(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        const std::string reason = describeError(lastSocketError());
        closeSocket(handle);
        return fail(Result::SOCKET_FAILURE,
                    "bind() 失败，端口 " + std::to_string(port) + " 可能已被占用: " + reason);
    }

    if (::listen(handle, kListenBacklog) != 0) {
        const std::string reason = describeError(lastSocketError());
        closeSocket(handle);
        return fail(Result::SOCKET_FAILURE, "listen() 失败: " + reason);
    }

    listenSocket_ = toIntptr(handle);

    // port == 0 时由系统分配端口，需要用 getsockname() 查询真实端口（便于测试）。
    boundPort_ = port;
    if (port == 0) {
        sockaddr_in local;
        std::memset(&local, 0, sizeof(local));
        socklen_t localLength = sizeof(local);
        if (::getsockname(handle, reinterpret_cast<sockaddr*>(&local), &localLength) == 0) {
            boundPort_ = ntohs(local.sin_port);
        } else {
            ST_LOG_WARN(kLogModule,
                        "getsockname() 失败，无法获知临时端口: " + describeError(lastSocketError()));
        }
    }

    ST_LOG_INFO_STREAM(kLogModule,
                       "TCP server listening on 0.0.0.0:" << boundPort_
                                                            << " (backlog=" << kListenBacklog << ")");
    return true;
}

bool Network::accept() {
    resetError();

    if (listenSocket_ == kInvalidSocket) {
        return fail(Result::NOT_CONNECTED, "accept() 之前必须先成功调用 listen()");
    }

    const SocketHandle listenHandle = toHandle(listenSocket_);
    SocketHandle clientHandle = kInvalidHandle;

    for (;;) {
        clientHandle = ::accept(listenHandle, nullptr, nullptr);
        if (clientHandle != kInvalidHandle) {
            break;
        }
        const int code = lastSocketError();
        if (isInterrupted(code)) {
            continue;  // 被信号打断，重试
        }
        return fail(Result::SOCKET_FAILURE, "accept() 失败: " + describeError(code));
    }

    // 演示阶段只服务单个客户端：如果已有连接，先关闭旧连接。
    if (connectionSocket_ != kInvalidSocket) {
        ST_LOG_WARN(kLogModule, "已有连接存在，关闭旧连接后接受新连接");
        closeSocket(toHandle(connectionSocket_));
        connectionSocket_ = kInvalidSocket;
    }

    connectionSocket_ = toIntptr(clientHandle);

    // 关闭 Nagle 算法：交互式小消息（例如 "Hello Bob"）可以更快发出。
    // 即使这一步失败也不影响连接可用性，因此只记录警告后继续。
    if (!setTcpNoDelay(true)) {
        ST_LOG_WARN(kLogModule, "setTcpNoDelay(true) 失败，忽略: " + lastError_);
        resetError();
    }

    ST_LOG_INFO(kLogModule, "accepted a client connection");
    return true;
}

bool Network::sendFrame(const Frame& frame) {
    resetError();

    if (connectionSocket_ == kInvalidSocket) {
        return fail(Result::NOT_CONNECTED,
                    "sendFrame() 失败：尚未 connect() 或 accept()，没有可用连接");
    }
    if (!frame.isValid()) {
        return fail(Result::INVALID_FRAME,
                    "sendFrame() 失败：Frame 非法 (length=" + std::to_string(frame.length) +
                        ", payload.size()=" + std::to_string(frame.payload.size()) +
                        ", 最大允许 " + std::to_string(Frame::kMaxPayloadSize) + " 字节)");
    }

    const std::vector<uint8_t> wire = frame.serialize();
    if (wire.size() != frame.wireSize()) {
        // serialize() 内部已经打印了详细错误，这里只补一个统一的失败结果。
        return fail(Result::INVALID_FRAME, "sendFrame() 失败：Frame 序列化失败");
    }

    if (!writeAll(wire.data(), wire.size())) {
        return false;  // writeAll() 内部已经设置了 lastResult_ / lastError_
    }

    ST_LOG_DEBUG_STREAM(kLogModule,
                        "sendFrame(): payload=" << frame.payload.size()
                                                << " byte(s), wire=" << wire.size() << " byte(s)");
    return true;
}

bool Network::receiveFrame(Frame& frame) {
    resetError();

    if (connectionSocket_ == kInvalidSocket) {
        return fail(Result::NOT_CONNECTED,
                    "receiveFrame() 失败：尚未 connect() 或 accept()，没有可用连接");
    }

    // 第 1 步：读满固定长度的 length 字段（可能被拆成多次 recv()）。
    uint8_t lengthField[Frame::kLengthFieldSize] = {0};
    if (!readExact(lengthField, Frame::kLengthFieldSize)) {
        return false;  // readExact() 内部已经设置了 lastResult_ / lastError_
    }

    const uint32_t declaredLength = Frame::decodeLength(lengthField);

    // 第 2 步：先检查长度是否合法，再分配内存，避免异常长度导致内存耗尽。
    if (!Frame::isPayloadLengthValid(declaredLength)) {
        return fail(Result::INVALID_FRAME,
                    "receiveFrame() 失败：非法的 Frame 长度 " + std::to_string(declaredLength) +
                        "，最大允许 " + std::to_string(Frame::kMaxPayloadSize) + " 字节");
    }

    // 第 3 步：读满 payload。
    Frame received;
    received.length = declaredLength;
    received.payload.resize(declaredLength);
    if (declaredLength > 0) {
        if (!readExact(received.payload.data(), received.payload.size())) {
            return false;
        }
    }

    frame = std::move(received);
    ST_LOG_DEBUG_STREAM(kLogModule, "receiveFrame(): payload=" << frame.payload.size() << " byte(s)");
    return true;
}

bool Network::writeAll(const uint8_t* data, std::size_t length) {
    const SocketHandle handle = toHandle(connectionSocket_);
    std::size_t totalWritten = 0;

    while (totalWritten < length) {
        const std::size_t remaining = length - totalWritten;
        const int chunk = remaining > static_cast<std::size_t>(INT_MAX)
                              ? INT_MAX
                              : static_cast<int>(remaining);

        const ssize_t written =
            ::send(handle, reinterpret_cast<const char*>(data + totalWritten), chunk, kSendFlags);

        if (written > 0) {
            totalWritten += static_cast<std::size_t>(written);
            continue;
        }
        if (written == 0) {
            return fail(Result::SOCKET_FAILURE, "send() 返回 0，连接状态异常");
        }

        const int code = lastSocketError();
        if (isInterrupted(code)) {
            continue;  // 被信号打断，重试
        }
        if (isTimeout(code)) {
            return fail(Result::TIMEOUT,
                        "send() 超时，已发送 " + std::to_string(totalWritten) + "/" +
                            std::to_string(length) + " 字节");
        }
        if (isPeerGone(code)) {
            return fail(Result::PEER_CLOSED,
                        "send() 失败：对端已关闭连接 (" + describeError(code) + ")");
        }
        return fail(Result::SOCKET_FAILURE,
                    "send() 失败，已发送 " + std::to_string(totalWritten) + "/" +
                        std::to_string(length) + " 字节: " + describeError(code));
    }

    return true;
}

bool Network::readExact(uint8_t* buffer, std::size_t length) {
    const SocketHandle handle = toHandle(connectionSocket_);
    std::size_t totalRead = 0;

    while (totalRead < length) {
        const std::size_t remaining = length - totalRead;
        const int chunk = remaining > static_cast<std::size_t>(INT_MAX)
                              ? INT_MAX
                              : static_cast<int>(remaining);

        const ssize_t received = ::recv(handle, reinterpret_cast<char*>(buffer + totalRead), chunk, 0);

        if (received > 0) {
            totalRead += static_cast<std::size_t>(received);
            continue;
        }
        if (received == 0) {
            return fail(Result::PEER_CLOSED,
                        "recv() 返回 0：对端关闭了连接 (已接收 " + std::to_string(totalRead) + "/" +
                            std::to_string(length) + " 字节)");
        }

        const int code = lastSocketError();
        if (isInterrupted(code)) {
            continue;  // 被信号打断，重试
        }
        if (isTimeout(code)) {
            return fail(Result::TIMEOUT,
                        "recv() 超时，已接收 " + std::to_string(totalRead) + "/" +
                            std::to_string(length) + " 字节");
        }
        if (isPeerGone(code)) {
            return fail(Result::PEER_CLOSED,
                        "recv() 失败：连接已被对端终止 (" + describeError(code) + ")");
        }
        return fail(Result::SOCKET_FAILURE,
                    "recv() 失败，已接收 " + std::to_string(totalRead) + "/" +
                        std::to_string(length) + " 字节: " + describeError(code));
    }

    return true;
}

bool Network::setTcpNoDelay(bool on) {
    resetError();

    if (connectionSocket_ == kInvalidSocket) {
        return fail(Result::NOT_CONNECTED, "setTcpNoDelay() 失败：当前没有已建立的连接");
    }

    const int value = on ? 1 : 0;
    if (::setsockopt(toHandle(connectionSocket_), IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&value), sizeof(value)) != 0) {
        return fail(Result::SOCKET_FAILURE,
                    "setsockopt(TCP_NODELAY) 失败: " + describeError(lastSocketError()));
    }
    return true;
}

bool Network::applyTimeout(bool forReceive, int timeoutMs) {
    resetError();

    if (timeoutMs < 0) {
        return fail(Result::INVALID_ARGUMENT, "超时时间不能为负数");
    }
    if (connectionSocket_ == kInvalidSocket) {
        return fail(Result::NOT_CONNECTED, "设置超时失败：当前没有已建立的连接");
    }

    const SocketHandle handle = toHandle(connectionSocket_);
    const int option = forReceive ? SO_RCVTIMEO : SO_SNDTIMEO;

#if defined(_WIN32)
    const DWORD value = static_cast<DWORD>(timeoutMs);   // Windows 用毫秒
#else
    timeval value;
#endif
#if !defined(_WIN32)
    value.tv_sec = timeoutMs / 1000;
    value.tv_usec = static_cast<suseconds_t>((timeoutMs % 1000) * 1000);
#endif

    if (::setsockopt(handle, SOL_SOCKET, option, reinterpret_cast<const char*>(&value),
                     sizeof(value)) != 0) {
        return fail(Result::SOCKET_FAILURE,
                    std::string("setsockopt(") + (forReceive ? "SO_RCVTIMEO" : "SO_SNDTIMEO") +
                        ") 失败: " + describeError(lastSocketError()));
    }

    ST_LOG_DEBUG_STREAM(kLogModule,
                        (forReceive ? "recv" : "send") << " timeout = " << timeoutMs << " ms");
    return true;
}

bool Network::setReceiveTimeoutMs(int timeoutMs) {
    return applyTimeout(true, timeoutMs);
}

bool Network::setSendTimeoutMs(int timeoutMs) {
    return applyTimeout(false, timeoutMs);
}

namespace {

/// 在单个 socket 上等待"可读"。kError 时的具体错误码由调用方通过 lastSocketError() 取。
Network::WaitResult waitHandleReadable(SocketHandle handle, int timeoutMs) {
    for (;;) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(handle, &readSet);

        timeval timeout;
        timeout.tv_sec = timeoutMs / 1000;
        timeout.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);

#if defined(_WIN32)
        // Windows 的 select() 忽略第一个参数
        const int ready = ::select(0, &readSet, nullptr, nullptr, &timeout);
#else
        const int ready =
            ::select(static_cast<int>(handle) + 1, &readSet, nullptr, nullptr, &timeout);
#endif
        if (ready > 0) {
            return Network::WaitResult::kReadable;
        }
        if (ready == 0) {
            // 没有数据：这不是错误，故意不设置 lastResult_ / lastError_。
            return Network::WaitResult::kTimeout;
        }

        const int code = lastSocketError();
        if (isInterrupted(code)) {
            continue;  // 被信号打断（POSIX 上 timeout 会被改写，重试即可）
        }
        return Network::WaitResult::kError;
    }
}

}  // namespace

Network::WaitResult Network::waitReadable(int timeoutMs) {
    if (timeoutMs < 0) {
        (void)fail(Result::INVALID_ARGUMENT, "waitReadable() 参数非法：超时时间不能为负数");
        return WaitResult::kError;
    }
    if (connectionSocket_ == kInvalidSocket) {
        (void)fail(Result::NOT_CONNECTED,
                   "waitReadable() 失败：尚未 connect() 或 accept()，没有可用连接");
        return WaitResult::kError;
    }

    const WaitResult result = waitHandleReadable(toHandle(connectionSocket_), timeoutMs);
    if (result == WaitResult::kError) {
        (void)fail(Result::SOCKET_FAILURE,
                   std::string("select() 失败: ") + describeError(lastSocketError()));
    }
    return result;
}

Network::WaitResult Network::waitAcceptable(int timeoutMs) {
    if (timeoutMs < 0) {
        (void)fail(Result::INVALID_ARGUMENT, "waitAcceptable() 参数非法：超时时间不能为负数");
        return WaitResult::kError;
    }
    if (listenSocket_ == kInvalidSocket) {
        (void)fail(Result::NOT_CONNECTED, "waitAcceptable() 失败：还没有成功 listen()");
        return WaitResult::kError;
    }

    const WaitResult result = waitHandleReadable(toHandle(listenSocket_), timeoutMs);
    if (result == WaitResult::kError) {
        (void)fail(Result::SOCKET_FAILURE,
                   std::string("select() 失败: ") + describeError(lastSocketError()));
    }
    return result;
}
void Network::close() {
    if (listenSocket_ != kInvalidSocket) {
        closeSocket(toHandle(listenSocket_));
        listenSocket_ = kInvalidSocket;
        ST_LOG_DEBUG(kLogModule, "listening socket closed");
    }

    if (connectionSocket_ != kInvalidSocket) {
        // 先 shutdown 再 close，让对端立即感知到连接结束。
        ::shutdown(toHandle(connectionSocket_), kShutdownBoth);
        closeSocket(toHandle(connectionSocket_));
        connectionSocket_ = kInvalidSocket;
        ST_LOG_INFO(kLogModule, "connection closed");
    }

    boundPort_ = 0;
}
