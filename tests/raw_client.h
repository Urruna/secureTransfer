// ============================================================================
//  SecureTransfer 测试
//  file: tests/raw_client.h
//
//  说明：直接操作 socket 的“裸客户端”，用来构造 Network 类本身无法生成的
//        异常字节流，例如：
//          - 非法的 length 前缀（0x7FFFFFFF）
//          - 只发送半个 Frame 就断开连接
//        这样可以验证 Network::receiveFrame() 的错误处理是否正确。
//
//        该文件只用于测试，不参与正式程序构建。
// ============================================================================

#ifndef SECURETRANSFER_TESTS_RAW_CLIENT_H
#define SECURETRANSFER_TESTS_RAW_CLIENT_H

#include <cstdint>
#include <cstring>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace testutil {

#if defined(_WIN32)
using SocketHandle = SOCKET;
inline constexpr SocketHandle kInvalidHandle = INVALID_SOCKET;
inline void closeHandle(SocketHandle handle) { ::closesocket(handle); }
#else
using SocketHandle = int;
inline constexpr SocketHandle kInvalidHandle = -1;
inline void closeHandle(SocketHandle handle) { ::close(handle); }
#endif

/// 绕过 Frame 封装、直接写 socket 的测试辅助类。
class RawClient {
public:
    RawClient() = default;

    ~RawClient() {
        closeNow();
    }

    RawClient(const RawClient&) = delete;
    RawClient& operator=(const RawClient&) = delete;

    /// 连接到 127.0.0.1:port。
    bool connectTo(uint16_t port) {
        closeNow();

        const SocketHandle handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (handle == kInvalidHandle) {
            return false;
        }

        sockaddr_in address;
        std::memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (::connect(handle, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            closeHandle(handle);
            return false;
        }

        handle_ = handle;
        return true;
    }

    /// 发送一段原始字节（不添加任何长度前缀）。
    bool sendBytes(const std::vector<uint8_t>& data) {
        if (handle_ == kInvalidHandle || data.empty()) {
            return false;
        }
        const int sent = ::send(handle_, reinterpret_cast<const char*>(data.data()),
                                    static_cast<int>(data.size()), 0);
        return sent >= 0 && static_cast<std::size_t>(sent) == data.size();
    }

    /// 关闭连接（不发送任何额外数据）。
    void closeNow() {
        if (handle_ != kInvalidHandle) {
            closeHandle(handle_);
            handle_ = kInvalidHandle;
        }
    }

private:
    SocketHandle handle_ = kInvalidHandle;
};

}  // namespace testutil

#endif  // SECURETRANSFER_TESTS_RAW_CLIENT_H
