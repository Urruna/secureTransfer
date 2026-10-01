// ============================================================================
//  SecureTransfer - 第二部分：安全通信协议与网络
//  file: include/protocol/message_type.h
//
//  说明：协议消息类型。所有"带业务数据"的类型都使用完全相同的
//        加密 + MAC + 防重放流程，只是 Type 不同，因此短消息、文件、
//        图像不需要各自实现一套安全逻辑。
// ============================================================================

#ifndef SECURETRANSFER_PROTOCOL_MESSAGE_TYPE_H
#define SECURETRANSFER_PROTOCOL_MESSAGE_TYPE_H

#include <cstdint>

enum class MessageType : std::uint8_t {
    kHello = 0x01,          // C→S  携带 Alice_ID
    kHelloAck = 0x02,       // S→C  携带 Bob_ID，MAC 使用 K_master
    kAuth = 0x03,           // C→S  认证响应，MAC 使用 K_master
    kKeyRequest = 0x04,     // C→S  请求分发会话密钥
    kKeyExchange = 0x05,    // S→C  包裹后的 K_session
    kKeyConfirm = 0x06,     // C→S  MAC 使用 K_session，证明 Alice 已持有密钥
    kKeyConfirmAck = 0x07,  // S→C  反向确认
    kData = 0x08,           // 双向  加密业务数据
    kFileStart = 0x09,      // 双向  文件传输（第三部分使用）
    kFileChunk = 0x0A,      // 双向
    kFileEnd = 0x0B,        // 双向
    kImage = 0x0C,          // 双向  图像传输（第三部分使用）
    kError = 0x0D,          // 双向  错误提示（明文，仅用于演示）
    kClose = 0x0E           // 双向  正常结束会话
};

inline const char* messageTypeToString(MessageType type) {
    switch (type) {
        case MessageType::kHello: return "HELLO";
        case MessageType::kHelloAck: return "HELLO_ACK";
        case MessageType::kAuth: return "AUTH";
        case MessageType::kKeyRequest: return "KEY_REQUEST";
        case MessageType::kKeyExchange: return "KEY_EXCHANGE";
        case MessageType::kKeyConfirm: return "KEY_CONFIRM";
        case MessageType::kKeyConfirmAck: return "KEY_CONFIRM_ACK";
        case MessageType::kData: return "DATA";
        case MessageType::kFileStart: return "FILE_START";
        case MessageType::kFileChunk: return "FILE_CHUNK";
        case MessageType::kFileEnd: return "FILE_END";
        case MessageType::kImage: return "IMAGE";
        case MessageType::kError: return "ERROR";
        case MessageType::kClose: return "CLOSE";
    }
    return "UNKNOWN";
}

/// 是否属于"必须走安全数据通道"的消息：这类消息走加密 + MAC + 防重放流程。
/// kClose 也在此列（相当于 TLS 的 close_notify，同样被加密与保护），
/// 这样"会话结束"这件事本身也无法被伪造。
inline bool isDataBearing(MessageType type) {
    switch (type) {
        case MessageType::kData:
        case MessageType::kFileStart:
        case MessageType::kFileChunk:
        case MessageType::kFileEnd:
        case MessageType::kImage:
        case MessageType::kClose:
            return true;
        default:
            return false;
    }
}

/// 是否属于握手阶段的消息。
inline bool isHandshake(MessageType type) {
    switch (type) {
        case MessageType::kHello:
        case MessageType::kHelloAck:
        case MessageType::kAuth:
        case MessageType::kKeyRequest:
        case MessageType::kKeyExchange:
        case MessageType::kKeyConfirm:
        case MessageType::kKeyConfirmAck:
            return true;
        default:
            return false;
    }
}

#endif  // SECURETRANSFER_PROTOCOL_MESSAGE_TYPE_H
