// ============================================================================
//  SecureTransfer - 第一阶段：基础 TCP 通信
//  file: include/network/frame.h
//
//  说明：Frame 是网络层传输数据的最小单元，只有 length + payload 两个字段。
//        安全协议阶段**没有改动本文件**：Packet（Type / SessionId / Sequence /
//        Nonce / Body / MAC）整体放在 Frame::payload 内部，见 docs/protocol.md。
// ============================================================================

#ifndef SECURETRANSFER_NETWORK_FRAME_H
#define SECURETRANSFER_NETWORK_FRAME_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/// 一次 TCP 通信中传输的最小数据单元。
///
/// 线上格式（大端序 / 网络字节序）：
///
///     +------------------------------+------------------------------+
///     | length (4 bytes, uint32 大端) | payload (length bytes)       |
///     +------------------------------+------------------------------+
///
/// length 表示 payload 的字节数，因此一个 Frame 在线上的总字节数为
/// kLengthFieldSize + length（见 wireSize()）。
struct Frame {
    /// length 字段的宽度（字节）。
    static constexpr std::size_t kLengthFieldSize = 4;

    /// 单个 Frame 允许的最大 payload 长度：1 MB。
    /// 接收端会先检查 length 再分配内存，避免恶意长度导致内存耗尽。
    static constexpr std::size_t kMaxPayloadSize = 1024u * 1024u;

    /// deserialize() 的返回状态，便于调用者区分“数据还没到”和“数据非法”。
    enum class Status {
        OK,               ///< 解析成功
        INCOMPLETE,       ///< 缓冲区数据不足以构成一个完整 Frame
        LENGTH_TOO_LARGE  ///< length 字段超过 kMaxPayloadSize
    };

    uint32_t length;               ///< payload 字节数，合法时等于 payload.size()
    std::vector<uint8_t> payload;  ///< 二进制数据

    /// 构造空 Frame（length = 0，payload 为空）。
    Frame();

    /// 用字节数据构造 Frame，length 自动等于 payload.size()。
    explicit Frame(const std::vector<uint8_t>& data);

    /// 用 (length, payload) 构造 Frame。两者不一致时 isValid() 返回 false，
    /// 该构造方式主要用于构造非法 Frame 以测试错误处理。
    Frame(uint32_t length, const std::vector<uint8_t>& payload);

    /// 用 UTF-8 文本构造 Frame（不包含结尾的 '\0'）。
    static Frame fromString(const std::string& text);

    /// 用字节数组构造 Frame。
    static Frame fromBytes(const std::vector<uint8_t>& data);

    /// 设置 payload，并同步更新 length。
    void setPayload(const std::vector<uint8_t>& data);
    void setPayload(const std::string& text);

    /// 把 payload 当作 UTF-8 文本返回（不做转义，二进制数据也会原样返回）。
    std::string toString() const;

    /// payload 是否为空。
    bool isEmpty() const;

    /// length 是否等于 payload.size()，且不超过 kMaxPayloadSize。
    bool isValid() const;

    /// 序列化后的总字节数：kLengthFieldSize + payload.size()。
    std::size_t wireSize() const;

    /// 序列化为字节流（大端 length + payload）。
    /// Frame 非法时返回空 vector 并输出一条 [ERROR] 日志，调用者需自行判断。
    std::vector<uint8_t> serialize() const;

    /// 从字节流反序列化出一个 Frame（允许 buffer 中还有后续数据）。
    ///
    /// @param buffer   输入缓冲区
    /// @param frame    解析结果（只有返回 OK 时才被修改为完整 Frame）
    /// @param consumed 可选输出参数：本次消耗的字节数（kLengthFieldSize + length）
    /// @return OK / INCOMPLETE / LENGTH_TOO_LARGE
    static Status deserialize(const std::vector<uint8_t>& buffer,
                              Frame& frame,
                              std::size_t* consumed = nullptr);

    /// Status 的可读描述，用于日志与测试输出。
    static const char* statusToString(Status status);

    /// 把 length 写入 4 字节大端表示（buffer 至少 4 字节）。
    static void encodeLength(uint32_t length, uint8_t* out4Bytes);

    /// 从 4 字节大端表示读出 length。
    static uint32_t decodeLength(const uint8_t* in4Bytes);

    /// length 是否在允许范围内（<= kMaxPayloadSize）。
    static bool isPayloadLengthValid(uint32_t length);
};

#endif  // SECURETRANSFER_NETWORK_FRAME_H
