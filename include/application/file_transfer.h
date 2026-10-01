// ============================================================================
//  SecureTransfer - 第三部分：应用层（文件 / 图像传输）
//  file: include/application/file_transfer.h
//
//  说明：在已有安全会话之上实现"文件 / 图像安全传输"。
//
//  设计要点
//    1. 复用安全数据通道：每一块都通过 `SecureSession::sendMessage()` 发送，
//       因此**自动获得** AES-128-CTR 加密、CMAC 完整性、Sequence 防重放、
//       方向校验与会话绑定——应用层不碰任何密码学 API；
//    2. 只有两种传输形态：
//         * 分块传输：FILE_START → FILE_CHUNK × N → FILE_END（任意大小）
//         * 单包传输：IMAGE（元数据 + 数据在一个包里，仅用于小图像）
//       大图像走分块传输，Type 仍用 IMAGE 作为起始包（kind = 图像）；
//    3. 端到端校验：发送端计算整文件 CRC32，接收端重组后再算一次并比对，
//       同时校验总字节数（能发现"少收/多收/顺序错"这类意外错误）；
//    4. 密码学安全性由每包 CMAC 保证，CRC32 只是差错检测，二者不可互相替代。
//
//  典型用法（发送端）：
//        transfer::SendResult r = transfer::FileSender::send(session, path, kind);
//
//  典型用法（接收端，放在收消息的循环里）：
//        if (receiver.handle(type, body, &error)) { /* 这条消息属于文件传输 */ }
// ============================================================================

#ifndef SECURETRANSFER_APPLICATION_FILE_TRANSFER_H
#define SECURETRANSFER_APPLICATION_FILE_TRANSFER_H

#include <cstdint>
#include <fstream>
#include <functional>
#include <string>

#include "application/crc32.h"
#include "application/transfer_meta.h"
#include "common/types.h"
#include "security/session.h"

namespace transfer {

/// 发送结果（用于日志、测试断言与实验报告）。
struct SendResult {
    bool ok = false;
    std::string fileName;
    Kind kind = Kind::kFile;
    std::uint64_t bytes = 0;
    std::uint32_t crc32 = 0;
    std::size_t chunks = 0;      ///< 分块数量（单包传输为 0）
    bool singleShot = false;     ///< 是否走了单包（IMAGE）路径
    double seconds = 0.0;        ///< 发送耗时（含加密与网络）
    double megabytesPerSecond = 0.0;
    std::string error;
};

/// 接收结果。
struct ReceiveResult {
    bool ok = false;
    std::string fileName;
    std::string savedPath;
    Kind kind = Kind::kFile;
    std::uint64_t bytes = 0;
    std::uint32_t crc32 = 0;
    std::size_t chunks = 0;
    bool singleShot = false;
    std::string error;
};

/// 发送端：把文件 / 图像切块并通过安全会话发出。
class FileSender {
public:
    /// 进度回调（已发送字节数, 总字节数）。
    using ProgressCallback = std::function<void(std::uint64_t, std::uint64_t)>;

    /// 发送一个文件 / 图像。
    /// @param forceChunked 为 true 时即使很小的图像也走分块路径（用于演示两种路径）
    static SendResult send(SecureSession& session,
                           const std::string& path,
                           Kind kind,
                           bool forceChunked = false,
                           const ProgressCallback& onProgress = nullptr);
};

/// 接收端：把收到的传输消息重组成文件，并做整文件校验。
class TransferReceiver {
public:
    explicit TransferReceiver(std::string outputDir);

    /// 处理一条业务消息。
    /// @return true 表示这条消息属于文件传输流程（已被本类消费）
    bool handle(MessageType type, const Bytes& body, std::string* error);

    bool inProgress() const { return inProgress_; }
    std::uint64_t receivedBytes() const { return receivedBytes_; }
    std::uint64_t expectedBytes() const { return meta_.totalBytes; }
    const std::string& currentFileName() const { return meta_.fileName; }

    /// 最近一次完成的传输结果（失败也记录在这里）。
    const ReceiveResult& lastResult() const { return lastResult_; }
    std::size_t completedCount() const { return completedCount_; }
    std::size_t failedCount() const { return failedCount_; }

private:
    bool beginTransfer(MessageType type, const Bytes& body, std::string* error);
    bool appendChunk(const Bytes& body, std::string* error);
    bool finishTransfer(const Bytes& body, std::string* error);
    void reset();

    std::string outputDir_;
    std::ofstream file_;
    Meta meta_{};
    bool inProgress_ = false;
    std::uint64_t receivedBytes_ = 0;
    std::size_t chunks_ = 0;
    Crc32 chunkCrc_;  ///< 逐块累积的整文件 CRC32（在 FILE_END 时与发送端比对）
    ReceiveResult lastResult_;
    std::size_t completedCount_ = 0;
    std::size_t failedCount_ = 0;
};

}  // namespace transfer

#endif  // SECURETRANSFER_APPLICATION_FILE_TRANSFER_H
